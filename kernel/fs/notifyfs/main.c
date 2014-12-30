/*
 * Copyright (c) 1998-2014 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2014 Stony Brook University
 * Copyright (c) 2003-2014 The Research Foundation of SUNY
 * Copyright (c) 2014-2015 Ricardo Padilha, Drobo Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "notifyfs.h"
#include <linux/module.h>

/*
 * There is no need to lock the notifyfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int notifyfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;
	/* notifier support */
	struct notifyfs_sb_info *spd;
	/* end notifier support */

	if (!dev_name) {
		printk(KERN_ERR "NotifyFS: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"NotifyFS: error accessing wrapped directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct notifyfs_sb_info), GFP_KERNEL);
	if (!NOTIFYFS_SB(sb)) {
		printk(KERN_CRIT "NotifyFS: unable to allocate super block\n");
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
	spd->event_id = 0;
	spd->proc_entry = create_proc_file(lower_path.dentry->d_name.name, spd);
	if (spd->proc_entry == NULL) {
		err = -ENOMEM;
		goto out_free_private_data;
	}
	err = kfifo_alloc(&spd->fifo, FIFO_SIZE * MAX_EVENT_SIZE, GFP_KERNEL);
	if (err != 0) {
		goto out_free_proc;
	}
	spin_lock_init(&spd->fifo_lock);
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

	if (!silent)
		printk(KERN_INFO
		       "notifyfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

/* notifier support */
out_free_proc:
	destroy_proc_file(lower_path.dentry->d_name.name);
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
			    const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) dev_name;

	return mount_nodev(fs_type, flags, lower_path_name,
			   notifyfs_read_super);
}

static struct file_system_type notifyfs_fs_type = {
	.owner    = THIS_MODULE,
	.name     = NOTIFYFS_NAME,
	.mount    = notifyfs_mount,
	.kill_sb  = generic_shutdown_super,
	.fs_flags = FS_REVAL_DOT,
};

static int __init init_notifyfs(void)
{
	int err;

	pr_info("Loading NotifyFS " NOTIFYFS_VERSION "\n");

	/* notifier support */
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
	err = create_proc_folder();
	if (err) {
		goto out_unregister_fs;
	}
	pr_info("NotifyFS loaded\n");
	goto out;
	/* end notifier support */

out_unregister_fs:
	unregister_filesystem(&notifyfs_fs_type);
out_free_dentry_cache:
	notifyfs_destroy_dentry_cache();
out_free_inode_cache:
	notifyfs_destroy_inode_cache();
out:
	return err;
}

static void __exit exit_notifyfs(void)
{
	notifyfs_destroy_inode_cache();
	notifyfs_destroy_dentry_cache();
	destroy_proc_folder();
	unregister_filesystem(&notifyfs_fs_type);
	pr_info("NotifyFS unloaded\n");
}

MODULE_AUTHOR("Ricardo Padilha for Drobo Inc"
	      " (http://www.drobo.com/)");
MODULE_DESCRIPTION("Notifyfs " NOTIFYFS_VERSION
		   " (http://www.drobo.com/)");
MODULE_LICENSE("GPL");

module_init(init_notifyfs);
module_exit(exit_notifyfs);
