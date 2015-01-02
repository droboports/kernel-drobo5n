/*
 * Copyright (c) 1998-2014 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2014 Stony Brook University
 * Copyright (c) 2003-2014 The Research Foundation of SUNY
 * Copyright (c) 2014-2015 Ricardo Padilha for Drobo Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "notifyfs.h"
#include <linux/module.h>
#include <linux/parser.h>

enum {
	opt_event_mask,
	opt_fifo_size,
	opt_blocking_fifo,
	opt_non_blocking_fifo,
	opt_unknown
};

static const match_table_t tokens = {
	{opt_event_mask, "event_mask=%u"},
	{opt_fifo_size, "fifo_size=%u"},
	{opt_blocking_fifo, "blocking_fifo"},
	{opt_non_blocking_fifo, "non_blocking_fifo"},
	{opt_unknown, NULL}
};

typedef struct notifyfs_mount_options {
	const char *source_dir;
	u32 event_mask;
	u32 fifo_size;
	u32 fifo_block;
} notifyfs_mount_options;

/*
 * Return:
 *   0 if no options provided or successful
 *   1 if unknown option
 *   -EINVAL if unable to parse
 *   -ENOMEM if unable to allocate memory for parsing
 */
static int parse_options(char *options, struct notifyfs_mount_options *opts) {
	int err;
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;

	UDBG;
	if (!options) {
		return 0;
	}

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p) {
			continue;
		}

		token = match_token(p, tokens, args);
		switch (token) {
			case opt_event_mask:
				UDBG;
				err = match_int(&args[0], &option);
				if (err != 0) {
					return err;
				}
				UDBG;
				opts->event_mask = option;
				break;
			case opt_fifo_size:
				UDBG;
				err = match_int(&args[0], &option);
				if (err != 0) {
					return err;
				}
				UDBG;
				opts->fifo_size = option;
				break;
			case opt_blocking_fifo:
				UDBG;
				if (err != 0) {
					return err;
				}
				UDBG;
				opts->fifo_block = BLOCKING_FIFO;
				break;
			case opt_non_blocking_fifo:
				UDBG;
				if (err != 0) {
					return err;
				}
				UDBG;
				opts->fifo_block = NONBLOCKING_FIFO;
				break;
			default:
				UDBG;
				pr_debug(NOTIFYFS_NAME ": unsupported mount option: %s\n", p);
				break;
		}
	}
	UDBG;
	return 0;
}

/*
 * There is no need to lock the notifyfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int notifyfs_read_super(struct super_block *sb, void *data,
		int silent) {
	int err = 0;
	struct notifyfs_mount_options *opts = (struct notifyfs_mount_options *) data;
	struct super_block *lower_sb;
	struct path lower_path;
	struct inode *inode;
	struct notifyfs_sb_info *spd;

	if (!opts->source_dir) {
		pr_err(NOTIFYFS_NAME ": missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(opts->source_dir, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &lower_path);
	if (err) {
		pr_err(NOTIFYFS_NAME ": error accessing wrapped directory '%s'\n",
				opts->source_dir);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct notifyfs_sb_info), GFP_KERNEL);
	if (!NOTIFYFS_SB(sb)) {
		pr_crit(NOTIFYFS_NAME ": unable to allocate super block\n");
		err = -ENOMEM;
		goto out_free;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	notifyfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &notifyfs_sops;

	/* get a new inode and allocate our root dentry */
	inode = notifyfs_iget(sb, lower_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_alloc_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &notifyfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* notifier support */
	spd = NOTIFYFS_SB(sb);
	atomic64_set(&spd->event_id, 0);
	atomic_set(&spd->event_mask, opts->event_mask);
	atomic_set(&spd->fifo_block, opts->fifo_block);
	atomic_set(&spd->unmounting, 0);

	spd->proc_dir = create_proc_mount_dir(lower_path.dentry->d_inode->i_ino);
	CHECK_PTR(spd->proc_dir, out_free_private_data);
	spd->proc_source = create_src_dir_file(sb, spd->proc_dir);
	CHECK_PTR(spd->proc_source, out_free_dir);
	spd->proc_events = create_events_file(spd, spd->proc_dir);
	CHECK_PTR(spd->proc_events, out_free_source);
	spd->proc_event_mask = create_mask_file(spd, spd->proc_dir);
	CHECK_PTR(spd->proc_event_mask, out_free_events);
	spd->proc_fifo_block = create_fifo_block_file(spd, spd->proc_dir);
	CHECK_PTR(spd->proc_fifo_block, out_free_mask);
	spd->proc_fifo_size = create_fifo_size_file(spd, spd->proc_dir);
	CHECK_PTR(spd->proc_fifo_size, out_free_fifo_block);
	spd->proc_pid_blacklist = create_pid_blacklist_file(spd, spd->proc_dir);
	CHECK_PTR(spd->proc_pid_blacklist, out_free_fifo_size);

	err = kfifo_alloc(&spd->fifo, opts->fifo_size, GFP_KERNEL);
	if (err != 0) {
		goto out_free_pid_blacklist;
	}
	err = int_list_alloc(&spd->pids, 8);
	if (err != 0) {
		goto out_free_fifo;
	}
	spin_lock_init(&spd->fifo_lock);
	spin_lock_init(&spd->pids_lock);
	init_waitqueue_head(&spd->writeable);
	init_waitqueue_head(&spd->readable);
	/* end notifier support */

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	notifyfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_alloc_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);

	goto out; /* all is well */

/* notifier support */
out_free_fifo:
	kfifo_free(&spd->fifo);
out_free_pid_blacklist:
	remove_proc_entry(PROC_PID_BLACKLIST_FILE, spd->proc_dir);
out_free_fifo_size:
	remove_proc_entry(PROC_FIFO_SIZE_FILE, spd->proc_dir);
out_free_fifo_block:
	remove_proc_entry(PROC_FIFO_BLOCK_FILE, spd->proc_dir);
out_free_mask:
	remove_proc_entry(PROC_EVENT_MASK_FILE, spd->proc_dir);
out_free_events:
	remove_proc_entry(PROC_EVENTS_FILE, spd->proc_dir);
out_free_source:
	remove_proc_entry(PROC_SRC_DIR_FILE, spd->proc_dir);
out_free_dir:
	destroy_proc_mount_dir(spd->proc_dir);
out_free_private_data:
	free_dentry_private_data(sb->s_root);
/* end notifier support */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(NOTIFYFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);
out:
	return err;
}

struct dentry *notifyfs_mount(struct file_system_type *fs_type, int flags,
		const char *dev_name, void *raw_data) {
	int err;
	struct notifyfs_mount_options mount_opts;

	/* notifier support */
	mount_opts.source_dir = dev_name;
	mount_opts.event_mask = DEFAULT_EVENTS_MASK;
	mount_opts.fifo_size = DEFAULT_FIFO_SIZE;
	mount_opts.fifo_block = DEFAULT_FIFO_BLOCK;
	/* end notifier support */

	err = parse_options(raw_data, &mount_opts);
	if (err < 0) {
		return ERR_PTR(err);
	}

	return mount_nodev(fs_type, flags, &mount_opts, notifyfs_read_super);
}

static struct file_system_type notifyfs_fs_type = {
	.owner = THIS_MODULE,
	.name = NOTIFYFS_NAME,
	.mount = notifyfs_mount,
	.kill_sb = generic_shutdown_super,
	.fs_flags = FS_REVAL_DOT
};

static int __init init_notifyfs(void) {
	int err;

	pr_info("Loading " NOTIFYFS_NAME " " NOTIFYFS_VERSION "\n");

	err = notifyfs_init_inode_cache();
	if (err) {
		goto out;
	}
	err = notifyfs_init_dentry_cache();
	if (err) {
		goto out_free_inode_cache;
	}
	err = register_filesystem(&notifyfs_fs_type);
	if (err) {
		goto out_free_dentry_cache;
	}
	/* notifier support */
	err = create_proc_dir();
	if (err) {
		goto out_unregister_fs;
	}
	/* end notifier support */
	pr_info(NOTIFYFS_NAME " loaded\n");
	goto out;

out_unregister_fs:
	unregister_filesystem(&notifyfs_fs_type);
out_free_dentry_cache:
	notifyfs_destroy_dentry_cache();
out_free_inode_cache:
	notifyfs_destroy_inode_cache();
out:
	return err;
}

static void __exit exit_notifyfs(void) {
	notifyfs_destroy_inode_cache();
	notifyfs_destroy_dentry_cache();
	destroy_proc_dir();
	unregister_filesystem(&notifyfs_fs_type);
	pr_info(NOTIFYFS_NAME " unloaded\n");
}

MODULE_AUTHOR("Ricardo Padilha for Drobo Inc" " (http://www.drobo.com/)");
MODULE_DESCRIPTION(NOTIFYFS_NAME " " NOTIFYFS_VERSION " (http://www.drobo.com/)");
MODULE_LICENSE("GPL");

module_init(init_notifyfs);
module_exit(exit_notifyfs);
