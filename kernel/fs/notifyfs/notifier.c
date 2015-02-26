/*
 * Copyright (c) 2014-2015 Ricardo Padilha for Drobo Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "notifyfs.h"

/* maximum length in decimal of a 64 bit integer */
#define STR_U64 20
/* maximum length in decimal of a 32 bit integer */
#define STR_U32 10


/* directory containing all proc files */
static struct proc_dir_entry *proc_folder;
static struct proc_dir_entry *proc_api_version;
static struct proc_dir_entry *proc_module_version;

/*
 * All operations have an oldName.
 * Only rename operations have a newName argument.
 */
void * create_notifyfs_event(const pid_t pid, const fs_operation_type op,
		const ino_t inode, const struct timespec ts, const char *old_name,
		const char *new_name, int *size) {
	const size_t headerLen = sizeof(fs_event_header);
	const size_t old_name_len = strlen(old_name) + 1; // +1 for null terminator
	const size_t new_name_len = (new_name != NULL) ? strlen(new_name) + 1 : 0;
	const size_t len = headerLen + old_name_len + new_name_len;

	void *buffer = NULL;
	fs_event_header *header = NULL;

	buffer = kzalloc(len, GFP_KERNEL);
	if (IS_ERR_OR_NULL(buffer)) {
		return !(buffer) ? ERR_PTR(-ENOMEM) : buffer;
	}

	header = (fs_event_header *) buffer;
	header->operation = op;
	header->inode = inode;
	header->mtime = ts.tv_sec;
	header->mtime_ns = ts.tv_nsec;
	header->pid = pid;
	header->path_len1 = old_name_len;
	header->path_len2 = new_name_len;

	strncpy(buffer + headerLen, old_name, old_name_len);
	strncpy(buffer + headerLen + old_name_len, new_name, new_name_len);
	*size = len;
	return buffer;
}

void destroy_notifyfs_event(void *buffer) {
	kfree(buffer);
}

/*
 * return: 1 if should send the event, 0 otherwise
 */
int should_send(struct super_block *sb, fs_event_header *header) {
	struct notifyfs_sb_info *spd = sb->s_fs_info;
//	struct fs_event_header last_event = spd->last_event;
	u32 event_mask;
	int contains_pid;

	event_mask = atomic_read(&spd->notifier_info.event_mask);
	if (event_mask & header->operation) {
		spin_lock(&spd->notifier_info.pids_lock);
		contains_pid = int_list_contains(&spd->notifier_info.pids, header->pid);
		spin_unlock(&spd->notifier_info.pids_lock);
		/* contains_pid could be greater than zero if found,
		 * or less than zero if error */
		if (!contains_pid) {
//			if (
//				last_event.operation != header->operation ||
//				last_event.inode != header->inode ||
//				last_event.time != header->time ||
//				last_event.time_ns != header->time_ns ||
//				last_event.pid != header->pid
//				) {
				return 1;
//			}
		}
	}
	return 0;
}

/* copied from fs/dcache.c */
int prepend(char **buffer, int *buflen, const char *str, int namelen) {
	*buflen -= namelen;
	if (*buflen < 0) {
		return -ENAMETOOLONG;
	}
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

/* copied from fs/dcache.c */
static int prepend_name(char **buffer, int *buflen, struct qstr *name) {
	return prepend(buffer, buflen, name->name, name->len);
}

/*
 * Based on dentry_path_raw from fs/dcache.c.
 * @sb: the super block of the notifyfs mount
 * @dentry: the underlying dentry
 *
 * Return: a pointer to the string representation
 *   of the relative path inside the notifyfs mount,
 *   -EINVAL if sb|dentry|buf are NULL
 *   -ENAMETOOLONG if buflen is too small
 */
char *dentry_to_string(struct super_block *sb, struct dentry *dentry, char *buf, int buflen) {
	int err;
	struct dentry *root;
	char *end = buf + buflen;
	char *retval;

	if (!sb || !dentry || !buf) {
		retval = ERR_PTR(-EINVAL);
		goto out;
	}
	if (buflen < 1) {
		retval = ERR_PTR(-ENAMETOOLONG);
		goto out;
	}
	err = prepend(&end, &buflen, "\0", 1);
	if (err) {
		retval = ERR_PTR(-ENAMETOOLONG);
		goto out;
	}
	/* Get '/' right */
	retval = end - 1;
	*retval = '/';

	root = NOTIFYFS_D(sb->s_root)->lower_path.dentry;
	BUG_ON(!root);

	write_seqlock(&rename_lock);

	while (dentry != root) {
		struct dentry *parent = dentry->d_parent;
		prefetch(parent);
		spin_lock(&dentry->d_lock);
		err = prepend_name(&end, &buflen, &dentry->d_name);
		spin_unlock(&dentry->d_lock);
		if (err) {
			retval = ERR_PTR(-ENAMETOOLONG);
			goto out;
		}
		err = prepend(&end, &buflen, "/", 1);
		if (err) {
			retval = ERR_PTR(-ENAMETOOLONG);
			goto out;
		}
		retval = end;
		dentry = parent;
	}
	write_sequnlock(&rename_lock);

out:
	return retval;
}

/*
 * All operations have an oldName.
 * Only rename operations have a newName argument.
 *
 * Golden rule: we only publish entire events.
 * If the fifo is blocking and there is not enough space to publish a whole event at once,
 * we wait and retry.
 * If the fifo is not blocking and there is not enough space, the event is discarded.
 *
 * return:
 *   0 if ok
 *   -EINVAL if dentry or dentry->inode is null
 *   -ENOMEM if unable to allocate memory for strings
 *   -ENAMETOOLONG from path to string conversion
 */
int send_event(struct super_block *sb, const fs_operation_type op, struct inode *inode,
		const char *old_name, const char *new_name) {
	int err = 0;
	struct notifyfs_sb_info *spd = NULL;
	int fifo_block;
	char *event = NULL;
	int eventlen = 0;
	int sent = 0;

	CHECK_NULL(sb, out);
	spd = sb->s_fs_info;
	CHECK_NULL(spd, out);
	CHECK_NULL(inode, out);

	event = create_notifyfs_event(current->tgid, op, inode->i_ino,
			inode->i_mtime, old_name, new_name, &eventlen);
	CHECK_PTR(event, out);

	if (should_send(sb, (fs_event_header *) event)) {
retry:
		fifo_block = atomic_read(&spd->notifier_info.fifo_block);

		if ((fifo_block == BLOCKING_FIFO) && (kfifo_avail(&spd->notifier_info.fifo) < eventlen)) {
			err = wait_event_interruptible(spd->notifier_info.writeable, (kfifo_avail(&spd->notifier_info.fifo) >= eventlen));
			if (err) {
				goto out_free_event;
			}
		}

		spin_lock(&spd->notifier_info.fifo_lock);
		/*
		 * Recheck free space on the fifo.
		 * Another producer might have used the space since the wait call.
		 */
		if (kfifo_avail(&spd->notifier_info.fifo) >= eventlen) {
			((fs_event_header *) event)->event_id = atomic64_inc_return(&spd->notifier_info.event_id);
			//memcpy(&spd->last_event, event, sizeof(fs_event_header));
			sent = kfifo_in(&spd->notifier_info.fifo, event, eventlen);
			BUG_ON(sent < eventlen);
		} else if (fifo_block == BLOCKING_FIFO) {
			// && (kfifo_avail(&spd->notifier_info.fifo) < eventlen)
			/*
			 * If there is not enough space, and the fifo is blocking,
			 * unlock and try again.
			 */
			spin_unlock(&spd->notifier_info.fifo_lock);
			goto retry;
		} else {
			// (fifo_block != BLOCKING_FIFO) && (kfifo_avail(&spd->notifier_info.fifo) < eventlen)
			/*
			 * We allocate an event_id so that consumers can detect that an event was discarded.
			 */
			((fs_event_header *) event)->event_id = atomic64_inc_return(&spd->notifier_info.event_id);
			sent = -1;
		}
		spin_unlock(&spd->notifier_info.fifo_lock);

#ifdef DEBUG
		if (sent >= 0) {
			printk("send_event %llu %u/%u %u\n", ((fs_event_header *) event)->event_id, sent, eventlen, kfifo_avail(&spd->notifier_info.fifo));
		} else {
			// sent < 0
			printk("send_event discarded %llu %u %u\n", ((fs_event_header *) event)->event_id, eventlen, kfifo_avail(&spd->notifier_info.fifo));
		}
#endif

		if ((fifo_block == BLOCKING_FIFO) && !kfifo_is_empty(&spd->notifier_info.fifo)) {
			wake_up_interruptible(&spd->notifier_info.readable);
		}
	}

out_free_event:
	destroy_notifyfs_event(event);
out:
	return err;
}

/*
 * Same as send_event(data, op, dentry, name, NULL);
 *
 * return:
 *   0 if ok
 *   -EINVAL if dentry or dentry->inode is null
 *   -ENOMEM if unable to allocate memory to string conversion
 *   -ENAMETOOLONG from path to string conversion
 */
int send_dentry_event(struct super_block *sb, const fs_operation_type op, struct dentry *dentry) {
	int err;
	char *buffer = NULL;
	char *name = NULL;

	CHECK_NULL(sb, out);
	CHECK_NULL(dentry, out);

	buffer = kzalloc(MAX_PATH_LENGTH, GFP_KERNEL);
	CHECK_PTR(buffer, out);

	/*
	 * Can return ERR_PTR(-ENAMETOOLONG)
	 */
	name = dentry_to_string(sb, dentry, buffer, MAX_PATH_LENGTH);
	CHECK_PTR(name, out_free_buffer);
	err = send_event(sb, op, dentry->d_inode, name, NULL);

out_free_buffer:
	kfree(buffer);
out:
	return err;
}

/*
 * Same as send_event(data, op, dentry, old_name, new_name);
 * Used only for rename/move operations.
 *
 * return:
 *   0 if ok
 *   -EINVAL if dentry or dentry->inode is null
 *   -ENOMEM if unable to allocate memory to string conversion
 *   -ENAMETOOLONG from path to string conversion
 */
int send_dentry_rename(struct super_block *sb, const fs_operation_type op, struct inode *inode,
		const char *old_name, const char *new_name) {
	int err = 0;

	CHECK_NULL(sb, out);
	CHECK_NULL(inode, out);
	CHECK_NULL(old_name, out);
	CHECK_NULL(new_name, out);
	err = send_event(sb, op, inode, old_name, new_name);

out:
	return err;
}

/*
 * Same as send_event(data, op, dentry, name, NULL);
 *
 * return:
 *   0 if ok
 *   -EINVAL if sb or sb->s_root is null
 *   -ENOMEM if unable to allocate memory to string conversion
 *   -ENAMETOOLONG from path to string conversion
 */
int send_mnt_event(struct super_block *sb, const fs_operation_type op) {
	int err;

	UDBG;
	CHECK_NULL(sb, out);
	CHECK_NULL(sb->s_root, out);

	dget(sb->s_root);
	err = send_event(sb, op, sb->s_root->d_inode, "/", NULL);
	dput(sb->s_root);

out:
	return err;
}

/*
 * Same as send_dentry_event(data, opType, fileFrom->f_path.dentry);
 *
 * return:
 *   0 if ok
 *   -EINVAL if file, file->f_path, file->f_path.dentry or file->f_path.dentry->inode are null
 *   -ENOMEM if unable to allocate memory for strings
 *   -ENAMETOOLONG from path to string conversion
 */
int send_file_event(struct super_block *sb, const fs_operation_type op, const struct file *file) {
	int err = 0;

	CHECK_NULL(sb, out);
	CHECK_NULL(file, out);
	err = send_dentry_event(sb, op, file->f_path.dentry);

out:
	return err;
}

void vfs_lock_acquire(struct super_block *sb, int *unlock, const fs_operation_type op) {
	struct notifyfs_sb_info *spd = sb->s_fs_info;
	u32 lock_mask;
	int contains_pid;
	*unlock = 0;

	lock_mask = atomic_read(&spd->notifier_info.lock_mask);
	if (lock_mask & op) {
		spin_lock(&spd->notifier_info.pids_lock);
		contains_pid = int_list_contains(&spd->notifier_info.pids, current->tgid);
		spin_unlock(&spd->notifier_info.pids_lock);

		BUG_ON(contains_pid < 0);
		/*
		 * If the current PID is on the blacklist,
		 * then no locking is necessary
		 */
		if (!contains_pid) {
			UDBG;
			down_read(&spd->notifier_info.global_lock);
			*unlock = 1;
		}
	}
}

void vfs_lock_release(struct super_block *sb, int *unlock) {
	struct notifyfs_sb_info *spd = sb->s_fs_info;
	if (*unlock) {
		UDBG;
		up_read(&spd->notifier_info.global_lock);
		*unlock = 0;
	}
}

int replicator_lock_acquire(struct notifyfs_sb_info *spd, const int trylock) {
	unsigned long flags = 0;
	int32_t activity;
	int ret = 1;

	spin_lock(&spd->notifier_info.global_write_spinlock);

	raw_spin_lock_irqsave(&spd->notifier_info.global_lock.wait_lock, flags);
	activity = spd->notifier_info.global_lock.activity;
	raw_spin_unlock_irqrestore(&spd->notifier_info.global_lock.wait_lock, flags);

	/* only acquire if not yet acquired for write */
	if (activity >= 0) {
		if (trylock) {
			UDBG;
			ret = down_write_trylock(&spd->notifier_info.global_lock);
		} else {
			UDBG;
			down_write(&spd->notifier_info.global_lock);
		}
	}

	spin_unlock(&spd->notifier_info.global_write_spinlock);

	return ret;
}

void replicator_lock_release(struct notifyfs_sb_info *spd) {
	unsigned long flags = 0;
	int32_t activity;

	spin_lock(&spd->notifier_info.global_write_spinlock);

	raw_spin_lock_irqsave(&spd->notifier_info.global_lock.wait_lock, flags);
	activity = spd->notifier_info.global_lock.activity;
	raw_spin_unlock_irqrestore(&spd->notifier_info.global_lock.wait_lock, flags);

	/* only release if acquired for write */
	if (activity < 0) {
		UDBG;
		up_write(&spd->notifier_info.global_lock);
	}

	spin_unlock(&spd->notifier_info.global_write_spinlock);
}

int replicator_lock_status(struct notifyfs_sb_info *spd) {
	unsigned long flags = 0;
	int32_t activity;

	raw_spin_lock_irqsave(&spd->notifier_info.global_lock.wait_lock, flags);
	activity = spd->notifier_info.global_lock.activity;
	raw_spin_unlock_irqrestore(&spd->notifier_info.global_lock.wait_lock, flags);

	if (activity < 0) {
		return 0x01;
	} else if (activity > 0) {
		return 0x80;
	}
	// activity == 0
	return 0;
}

/***** api version file *****/

static ssize_t proc_api_version_read(struct file *file, char *buf, size_t count, loff_t *offp) {
	int err;

	if (*offp > 0) {
		/* read complete */
		err = 0;
		goto out;
	} else {
		err = snprintf(buf, count, "%d\n", NOTIFYFS_API_VERSION);
		if (err >= count) {
			/* not enough space in the buffer */
			err = -EINVAL;
			goto out;
		}
		err++; /* include the null terminator */
		*offp = err;
	}

out:
	return err;
}

static const struct file_operations proc_api_version_fops = {
	.read = proc_api_version_read
};

struct proc_dir_entry *create_api_version_file(void *data, struct proc_dir_entry *dir) {
	return proc_create_data(PROC_API_VERSION_FILE, 0444, dir, &proc_api_version_fops, data);
}

/***** module version file *****/

static ssize_t proc_module_version_read(struct file *file, char *buf, size_t count, loff_t *offp) {
	int err;

	if (*offp > 0) {
		/* read complete */
		err = 0;
		goto out;
	} else {
		err = snprintf(buf, count, "%s\n", NOTIFYFS_VERSION);
		if (err >= count) {
			/* not enough space in the buffer */
			err = -EINVAL;
			goto out;
		}
		err++; /* include the null terminator */
		*offp = err;
	}

out:
	return err;
}

static const struct file_operations proc_module_version_fops = {
	.read = proc_module_version_read
};

struct proc_dir_entry *create_module_version_file(void *data, struct proc_dir_entry *dir) {
	return proc_create_data(PROC_MODULE_VERSION_FILE, 0444, dir, &proc_module_version_fops, data);
}

/***** main proc folder *****/

/*
 * Create the /proc folder.
 *
 * return:
 *   0 if ok
 *   -ENOMEM if unable to create folder
 */
int create_proc_dir(void) {
	int err = 0;
	proc_folder = proc_mkdir(NOTIFYFS_NAME, NULL);
	if (proc_folder == NULL) {
		pr_warn(NOTIFYFS_NAME ": Unable to create proc directory\n");
		err = -ENOMEM;
		goto out;
	}
	proc_api_version = create_api_version_file(NULL, proc_folder);
	if (proc_api_version == NULL) {
		pr_warn(NOTIFYFS_NAME ": Unable to create api version file\n");
		err = -ENOMEM;
		goto out_rmdir;
	}
	proc_module_version = create_module_version_file(NULL, proc_folder);
	if (proc_module_version == NULL) {
		pr_warn(NOTIFYFS_NAME ": Unable to create module version file\n");
		err = -ENOMEM;
		goto out_rmapi;
	}
	goto out;

out_rmapi:
	remove_proc_entry(proc_api_version->name, proc_folder);
out_rmdir:
	remove_proc_entry(NOTIFYFS_NAME, NULL);
out:
	return err;
}

void destroy_proc_dir(void) {
	/*
	 * We can only unload the module if all mounts were removed,
	 * so there should be no children left inside the folder.
	 */
	remove_proc_entry(proc_module_version->name, proc_folder);
	remove_proc_entry(proc_api_version->name, proc_folder);
	remove_proc_entry(NOTIFYFS_NAME, NULL);
}

/*
 * Create a proc folder for a new mount.
 *
 * return:
 *   0 if ok
 *   -ENOMEM if unable to create folder
 *   -EAGAIN from proc_mkdir
 */
struct proc_dir_entry *create_proc_mount_dir(ino_t inode) {
	int err = 0;
	char *name;
	struct proc_dir_entry *dir;

	name = kzalloc(STR_U64, GFP_KERNEL);
	if (IS_ERR_OR_NULL(name)) {
		pr_err(NOTIFYFS_NAME ": Unable to create mount proc directory (unable to allocate memory for name)\n");
		err = !name ? -ENOMEM : PTR_ERR(name);
		goto out;
	}

	err = sprintf(name, "%lu", inode);
	if (err <= 0) {
		pr_err(NOTIFYFS_NAME ": Unable to create mount proc directory (unable to render inode as string)\n");
		goto out_free;
	}

	dir = proc_mkdir(name, proc_folder);
	if (IS_ERR_OR_NULL(name)) {
		pr_err(NOTIFYFS_NAME ": Unable to create mount proc directory (mount directory creation failed)\n");
		err = !dir ? -ENOMEM : PTR_ERR(dir);
		goto out_free;
	}
	return dir;

out_free:
	kfree(name);
out:
	return ERR_PTR(err);
}

void destroy_proc_mount_dir(struct proc_dir_entry *dir) {
	remove_proc_entry(dir->name, proc_folder);
}

/***** events file *****/

static ssize_t proc_events_read(struct file *file, char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	int fifo_block;
	unsigned int copied;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	fifo_block = atomic_read(&spd->notifier_info.fifo_block);
	if ((fifo_block == BLOCKING_FIFO) && kfifo_is_empty(&spd->notifier_info.fifo)) {
		err = wait_event_interruptible(spd->notifier_info.readable, !kfifo_is_empty(&spd->notifier_info.fifo));
		if (err) {
			goto out;
		}
	}

	spin_lock(&spd->notifier_info.fifo_lock);
	err = kfifo_to_user(&spd->notifier_info.fifo, buf, count, &copied);
	spin_unlock(&spd->notifier_info.fifo_lock);

#ifdef DEBUG
	printk("proc_events_read %d %d\n", copied, kfifo_avail(&spd->notifier_info.fifo));
#endif

	if ((fifo_block == BLOCKING_FIFO) && !kfifo_is_full(&spd->notifier_info.fifo)) {
		wake_up_interruptible(&spd->notifier_info.writeable);
	}
	if (err) {
		goto out;
	}
	/* If no errors up to now, then return bytes copied */
	*offp += copied;
	err = copied;
out:
	return err;
}

/*
 * Returns
 *   0 on success
 *   -ERANGE on overflow
 *   -EINVAL on parsing error
 */
static ssize_t proc_events_write(struct file *file, const char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	const char *buffer = buf;
	char *token;
	long int code;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	while ((token = strsep((char **) &buffer, " ")) != NULL) {
		if (!*token) {
			continue;
		}
		err = kstrtol(token, 0, &code);
		if (err) {
			pr_warn(NOTIFYFS_NAME ": unable to parse value %s written to events on mount %s\n", buf, spd->notifier_info.proc_dir->name);
			goto out;
		}
		if (code == 0) {
			spin_lock(&spd->notifier_info.fifo_lock);
			kfifo_reset(&spd->notifier_info.fifo);
			spin_unlock(&spd->notifier_info.fifo_lock);

			if ((atomic_read(&spd->notifier_info.fifo_block) == BLOCKING_FIFO)
					&& !kfifo_is_full(&spd->notifier_info.fifo)) {
				wake_up_interruptible(&spd->notifier_info.writeable);
			}
		} else {
			err = -EINVAL;
			goto out;
		}
	}
	err = count; /* consider all data written */

out:
	return err;
}

static unsigned int proc_events_poll(struct file *file, struct poll_table_struct *pt) {
	struct notifyfs_sb_info *spd;
	unsigned int mask = 0;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		mask |= POLLERR;
		goto out;
	}
	poll_wait(file, &spd->notifier_info.writeable, pt);
	poll_wait(file, &spd->notifier_info.readable, pt);

	if (!kfifo_is_empty(&spd->notifier_info.fifo)) {
		mask |= POLLIN | POLLRDNORM;
	}
//	if (!kfifo_is_full(&spd->fifo)) {
//		mask |= POLLOUT | POLLWRNORM;
//	}
out:
	return mask;
}

static const struct file_operations proc_events_fops = {
	.read = proc_events_read,
	.write = proc_events_write,
	.poll = proc_events_poll
};

struct proc_dir_entry *create_events_file(void *data, struct proc_dir_entry *dir) {
	return proc_create_data(PROC_EVENTS_FILE, 0444, dir, &proc_events_fops, data);
}

/***** event mask file *****/

static ssize_t proc_event_mask_read(struct file *file, char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	int event_mask;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	if (*offp > 0) {
		/* read complete */
		err = 0;
		goto out;
	} else {
		event_mask = atomic_read(&spd->notifier_info.event_mask);
		err = snprintf(buf, count, "%d\n", event_mask);
		if (err >= count) {
			/* not enough space in the buffer */
			err = -EINVAL;
			goto out;
		}
		err++; /* include the null terminator */
		*offp = err;
	}

out:
	return err;
}

/*
 * Returns
 *   0 on success
 *   -ERANGE on overflow
 *   -EINVAL on parsing error
 */
static ssize_t proc_event_mask_write(struct file *file, const char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	unsigned long int event_mask;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	err = kstrtoul(buf, 0, &event_mask);
	if (err) {
		pr_warn(NOTIFYFS_NAME ": unable to set event mask %s on mount %s\n", buf, spd->notifier_info.proc_dir->name);
		goto out;
	}

	atomic_set(&spd->notifier_info.event_mask, event_mask);
	err = count; /* consider all data written */

out:
	return err;
}

static const struct file_operations proc_event_mask_fops = {
	.read = proc_event_mask_read,
	.write = proc_event_mask_write
};

struct proc_dir_entry *create_event_mask_file(void *data, struct proc_dir_entry *dir) {
	return proc_create_data(PROC_EVENT_MASK_FILE, 0664, dir, &proc_event_mask_fops, data);
}

/***** global lock file *****/

static ssize_t proc_global_lock_read(struct file *file, char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	int32_t lock_status;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	if (*offp > 0) {
		/* read complete */
		err = 0;
		goto out;
	} else {
		lock_status = replicator_lock_status(spd);
		err = snprintf(buf, count, "%d\n", lock_status);
		if (err >= count) {
			/* not enough space in the buffer */
			err = -EINVAL;
			goto out;
		}
		err++; /* include the null terminator */
		*offp = err;
	}

out:
	return err;
}

/*
 * Returns
 *   0 on success
 *   -ERANGE on overflow
 *   -EINVAL on parsing error
 *   -EAGAIN if the lock_value != 0 && lock_value != 1,
 *           and the lock cannot be acquired.
 */
static ssize_t proc_global_lock_write(struct file *file, const char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	unsigned long int lock_value;
	int acquired;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	err = kstrtoul(buf, 0, &lock_value);
	if (err) {
		pr_warn(NOTIFYFS_NAME ": unable to parse lock status %s on mount %s\n", buf, spd->notifier_info.proc_dir->name);
		goto out;
	}

	if (lock_value) {
		acquired = replicator_lock_acquire(spd, lock_value != 1);
		if (!acquired) {
			err = -EAGAIN;
		}
	} else {
		replicator_lock_release(spd);
	}
	err = count; /* consider all data written */

out:
	return err;
}

static const struct file_operations proc_global_lock_fops = {
	.read = proc_global_lock_read,
	.write = proc_global_lock_write
};

struct proc_dir_entry *create_global_lock_file(void *data, struct proc_dir_entry *dir) {
	return proc_create_data(PROC_GLOBAL_LOCK_FILE, 0664, dir, &proc_global_lock_fops, data);
}

/***** lock mask file *****/

static ssize_t proc_lock_mask_read(struct file *file, char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	int lock_mask;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	if (*offp > 0) {
		/* read complete */
		err = 0;
		goto out;
	} else {
		lock_mask = atomic_read(&spd->notifier_info.lock_mask);
		err = snprintf(buf, count, "%d\n", lock_mask);
		if (err >= count) {
			/* not enough space in the buffer */
			err = -EINVAL;
			goto out;
		}
		err++; /* include the null terminator */
		*offp = err;
	}

out:
	return err;
}

/*
 * Returns
 *   0 on success
 *   -ERANGE on overflow
 *   -EINVAL on parsing error
 */
static ssize_t proc_lock_mask_write(struct file *file, const char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	unsigned long int lock_mask;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	err = kstrtoul(buf, 0, &lock_mask);
	if (err) {
		pr_warn(NOTIFYFS_NAME ": unable to set lock mask %s on mount %s\n", buf, spd->notifier_info.proc_dir->name);
		goto out;
	}

	atomic_set(&spd->notifier_info.lock_mask, lock_mask);
	err = count; /* consider all data written */

out:
	return err;
}

static const struct file_operations proc_lock_mask_fops = {
	.read = proc_lock_mask_read,
	.write = proc_lock_mask_write
};

struct proc_dir_entry *create_lock_mask_file(void *data, struct proc_dir_entry *dir) {
	return proc_create_data(PROC_LOCK_MASK_FILE, 0664, dir, &proc_lock_mask_fops, data);
}

/***** fifo block file *****/

static ssize_t proc_fifo_block_read(struct file *file, char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	int fifo_block;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	if (*offp > 0) {
		/* read complete */
		err = 0;
		goto out;
	} else {
		fifo_block = atomic_read(&spd->notifier_info.fifo_block);
		err = snprintf(buf, count, "%d\n", fifo_block);
		if (err >= count) {
			/* not enough space in the buffer */
			err = -EINVAL;
			goto out;
		}
		err++; /* include the null terminator */
		*offp = err;
	}

out:
	return err;
}

/*
 * Returns
 *   0 on success
 *   -ERANGE on overflow
 *   -EINVAL on parsing error
 */
static ssize_t proc_fifo_block_write(struct file *file, const char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	unsigned long int fifo_block;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	err = kstrtoul(buf, 0, &fifo_block);
	if (err) {
		pr_warn(NOTIFYFS_NAME ": unable to set fifo_block %s on mount %s\n", buf, spd->notifier_info.proc_dir->name);
		goto out;
	}

	atomic_set(&spd->notifier_info.fifo_block, (fifo_block != 0) ? BLOCKING_FIFO : NONBLOCKING_FIFO);
	/*
	 * Changing to non-blocking wakes up all producers waiting.
	 */
	if (atomic_read(&spd->notifier_info.fifo_block)) {
		wake_up_interruptible_all(&spd->notifier_info.writeable);
	}
	err = count; /* consider all data written */

out:
	return err;
}

static const struct file_operations proc_fifo_block_fops = {
	.read = proc_fifo_block_read,
	.write = proc_fifo_block_write
};

struct proc_dir_entry *create_fifo_block_file(void *data, struct proc_dir_entry *dir) {
	return proc_create_data(PROC_FIFO_BLOCK_FILE, 0664, dir, &proc_fifo_block_fops, data);
}

/***** fifo size file *****/

static ssize_t proc_fifo_size_read(struct file *file, char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	if (*offp > 0) {
		/* read complete */
		err = 0;
		goto out;
	} else {
		err = snprintf(buf, count, "%d\n", kfifo_size(&spd->notifier_info.fifo));
		if (err >= count) {
			/* not enough space in the buffer */
			err = -EINVAL;
			goto out;
		}
		err++; /* include the null terminator */
		*offp = err;
	}

out:
	return err;
}

static const struct file_operations proc_fifo_size_fops = {
	.read = proc_fifo_size_read
};

struct proc_dir_entry *create_fifo_size_file(void *data, struct proc_dir_entry *dir) {
	return proc_create_data(PROC_FIFO_SIZE_FILE, 0444, dir, &proc_fifo_size_fops, data);
}

/***** pid blacklist file *****/

static ssize_t proc_pid_blacklist_read(struct file *file, char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	int pid_count = 0;
	char *b;
	int c;
	int i;
	int n = 0;
	int pid;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	if (*offp > 0) {
		/* read complete */
		err = 0;
		goto out;
	}

	spin_lock(&spd->notifier_info.pids_lock);
	err = int_list_count(&spd->notifier_info.pids, &pid_count);
	if (err) {
		goto out_unlock;
	}
	b = buf;
	c = count;
	for (i = 0; i < pid_count; i++) {
		err = int_list_get(&spd->notifier_info.pids, i, &pid);
		if (err) {
			goto out_unlock;
		}
		err = snprintf(b, c, "%d ", pid);
		if (err >= c) {
			/* not enough space in the buffer */
			err = -EINVAL;
			goto out_terminate;
		}
		b += err;
		c -= err;
		n += err;
	}

out_terminate:
	/* include the null terminator */
	*b = '\0';
	n++;
	err = n;
	*offp = n;
out_unlock:
	spin_unlock(&spd->notifier_info.pids_lock);
out:
	return err;
}

/*
 * Returns
 *   0 on success
 *   -ERANGE on overflow
 *   -EINVAL on parsing error
 */
static ssize_t proc_pid_blacklist_write(struct file *file, const char *buf, size_t count, loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	const char *buffer = buf;
	char *token;
	long int pid;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}

	while ((token = strsep((char **) &buffer, " ")) != NULL) {
		if (!*token) {
			continue;
		}
		err = kstrtol(token, 0, &pid);
		if (err) {
			pr_warn(NOTIFYFS_NAME ": unable to parse pid list %s on mount %s\n", buf, spd->notifier_info.proc_dir->name);
			goto out;
		}
		if (pid == 0) {
			spin_lock(&spd->notifier_info.pids_lock);
			err = int_list_clear(&spd->notifier_info.pids);
			spin_unlock(&spd->notifier_info.pids_lock);
			if (err) {
				goto out;
			}
		} else if (pid < 0) {
			spin_lock(&spd->notifier_info.pids_lock);
			int_list_remove(&spd->notifier_info.pids, -pid);
			spin_unlock(&spd->notifier_info.pids_lock);
			if (err) {
				goto out;
			}
		} else {
			spin_lock(&spd->notifier_info.pids_lock);
			err = int_list_add(&spd->notifier_info.pids, pid);
			if (!err) {
				err = int_list_sort(&spd->notifier_info.pids);
			}
			spin_unlock(&spd->notifier_info.pids_lock);
			if (err) {
				goto out;
			}
		}
	}
	err = count; /* consider all data written */

out:
	return err;
}

static const struct file_operations proc_pid_blacklist_fops = {
	.read = proc_pid_blacklist_read,
	.write = proc_pid_blacklist_write
};

struct proc_dir_entry *create_pid_blacklist_file(void *data, struct proc_dir_entry *dir) {
	return proc_create_data(PROC_PID_BLACKLIST_FILE, 0664, dir, &proc_pid_blacklist_fops, data);
}

/***** source directory file *****/

static ssize_t proc_src_dir_read(struct file *file, char *buf, size_t count, loff_t *offp) {
	int err = 0;
	struct super_block *sb;
	char *buffer;
	char *name;

	if (*offp > 0) {
		/* read complete */
		err = 0;
		goto out;
	}

	sb = PDE(file->f_path.dentry->d_inode)->data;
	if (IS_ERR_OR_NULL(sb)) {
		err = !(sb) ? -EINVAL : PTR_ERR(sb);
		goto out;
	}

	buffer = kzalloc(MAX_PATH_LENGTH, GFP_KERNEL);
	CHECK_PTR(buffer, out);

	name = d_path(&NOTIFYFS_D(sb->s_root)->lower_path, buffer, MAX_PATH_LENGTH);
	CHECK_PTR(buffer, out_free);

	if (strlen(name) + 1 > count) {
		err = -EINVAL;
		goto out_free;
	}

	err = strlcpy(buf, name, count);
	err++; /* include the null terminator */
	*offp = err;

out_free:
	kfree(buffer);
out:
	return err;
}

static const struct file_operations proc_src_dir_fops = {
	.read = proc_src_dir_read
};

struct proc_dir_entry *create_src_dir_file(void *data, struct proc_dir_entry *dir) {
	return proc_create_data(PROC_SRC_DIR_FILE, 0444, dir, &proc_src_dir_fops, data);
}

