/*
 * Copyright (c) 2014-2015 Ricardo Padilha for Drobo Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "notifyfs.h"

#define STRINGIFY_EVENT 1

/* maximum length in decimal of a 64 bit integer */
#define STR_U64 20
/* maximum length in decimal of a 32 bit integer */
#define STR_U32 10


/* directory containing all proc files */
static struct proc_dir_entry *proc_folder;

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
	header->time = ts.tv_sec;
	header->time_ns = ts.tv_nsec;
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
	struct fs_event_header last_event = spd->last_event;
	u32 event_mask;
	int contains_pid;

	event_mask = atomic_read(&spd->event_mask);
	if (event_mask & header->operation) {
		spin_lock(&(spd->pids_lock));
		contains_pid = int_list_contains(&spd->pids, header->pid);
		spin_unlock(&(spd->pids_lock));
		/* contains_pid could be greater than zero if found,
		 * or less than zero if error */
		if (!contains_pid) {
			if (
				last_event.operation != header->operation ||
				last_event.inode != header->inode ||
				last_event.time != header->time ||
				last_event.time_ns != header->time_ns ||
				last_event.pid != header->pid
				) {
				return 1;
			}
		}
	}
	return 0;
}

#if STRINGIFY_EVENT
int minimumStringLength(const void* event) {
	const fs_event_header * header = (fs_event_header *) event;
	// an additional 96 bytes is over-estimated, I think the exact number is 77
	return header->path_len1 + header->path_len2 + 128;
}
#endif

#if STRINGIFY_EVENT
/*
 * Return -EINVAL if given str is too short.
 */
int eventToString(const void* event, char *str, const size_t strlen) {
	const fs_event_header * header = (fs_event_header *) event;
	const size_t headerLen = sizeof(fs_event_header);
	const char *old_name = event + headerLen;
	const char *new_name =
			(header->path_len2 > 0) ?
					event + headerLen + header->path_len1 : NULL;

	if (strlen < minimumStringLength(event)) {
		return -EINVAL;
	}

	if (header->path_len2 > 0) {
		sprintf(str,
				"id %llu op %u ino %lu ts %lu ns %lu pid %u from %s to %s\n",
				header->event_id, header->operation, header->inode, header->time,
				header->time_ns, header->pid, old_name, new_name);
	} else { // header->pathLen2 == 0
		sprintf(str,
				"id %llu op %u ino %lu ts %lu ns %lu pid %u name %s\n",
				header->event_id, header->operation, header->inode, header->time,
				header->time_ns, header->pid, old_name);
	}
	return 0;
}
#endif

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
#if STRINGIFY_EVENT
	int strlen = 0;
	char *str = NULL;
#endif

	CHECK_NULL(sb, out);
	spd = sb->s_fs_info;
	CHECK_NULL(spd, out);
	CHECK_NULL(inode, out);

	event = create_notifyfs_event(current->pid, op, inode->i_ino,
			inode->i_mtime, old_name, new_name, &eventlen);
	CHECK_PTR(event, out);

	if (should_send(sb, (fs_event_header *) event)) {
		fifo_block = atomic_read(&spd->fifo_block);
		if ((fifo_block == BLOCKING_FIFO) && kfifo_is_full(&(spd->fifo))) {
			err = wait_event_interruptible(spd->writeable, !kfifo_is_full(&(spd->fifo)));
			if (err) {
				goto out_free_event;
			}
		}

		spin_lock(&(spd->fifo_lock));

		((fs_event_header *) event)->event_id = atomic64_inc_return(&spd->event_id);
		memcpy(&spd->last_event, event, sizeof(fs_event_header));

#if STRINGIFY_EVENT
		strlen = minimumStringLength(event);
		str = kzalloc(strlen, GFP_KERNEL);
		CHECK_PTR(str, out_free_event);

		err = eventToString(event, str, strlen);
		if (err != 0) {
			goto out_free_str;
		}
		kfifo_in(&(spd->fifo), str, strlen);
#else
		kfifo_in(&(spd->fifo), event, eventlen);
#endif

		spin_unlock(&(spd->fifo_lock));
#ifdef DEBUG
		printk("send_event %d %d\n", strlen, kfifo_avail(&(spd->fifo)));
#endif

		if ((fifo_block == BLOCKING_FIFO) && !kfifo_is_empty(&(spd->fifo))) {
			wake_up_interruptible(&spd->readable);
		}
	}

#if STRINGIFY_EVENT
out_free_str:
	kfree(str);
#endif
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
 * Same as send_dentry_event(data, opType, fileFrom->f_path.dentry);
 *
 * return:
 *   0 if ok
 *   -EINVAL if file, file->f_path, file->f_path.dentry or file->f_path.dentry->inode are null
 *   -ENOMEM if unable to allocate memory for strings
 *   -ENAMETOOLONG from path to string conversion
 */
int send_file_event(struct super_block *sb, const fs_operation_type opType, const struct file *file) {
	int err = 0;

	CHECK_NULL(sb, out);
	CHECK_NULL(file, out);
	err = send_dentry_event(sb, opType, file->f_path.dentry);

out:
	return err;
}

/*
 * Create the /proc folder.
 *
 * return:
 *   0 if ok
 *   -ENOMEM if unable to create folder
 */
int create_proc_dir(void) {
	proc_folder = proc_mkdir(NOTIFYFS_NAME, NULL);
	if (proc_folder == NULL) {
		pr_warn(NOTIFYFS_NAME ": Unable to create proc directory\n");
		return -ENOMEM;
	}
	return 0;
}

void destroy_proc_dir(void) {
	/*
	 * We can only unload the module if all mounts were removed,
	 * so there should be no files left inside the folder.
	 */
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

static ssize_t proc_events_read(struct file *file, char *buf, size_t count,
		loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	int fifo_block;
	unsigned int copied;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}
	fifo_block = atomic_read(&spd->fifo_block);
	if ((fifo_block == BLOCKING_FIFO) && kfifo_is_empty(&(spd->fifo))) {
		err = wait_event_interruptible(spd->readable, !kfifo_is_empty(&(spd->fifo)));
		if (err) {
			goto out;
		}
	}
	/* This mount is being shutdown. Return 0 to close the events proc file. */
	if (atomic_read(&spd->unmounting)) {
		return 0;
	}
	spin_lock(&(spd->fifo_lock));
	err = kfifo_to_user(&(spd->fifo), buf, count, &copied);
	spin_unlock(&(spd->fifo_lock));

#ifdef DEBUG
	printk("proc_fifo_read %d %d\n", copied, kfifo_avail(&(spd->fifo)));
#endif
	if ((fifo_block == BLOCKING_FIFO) && !kfifo_is_full(&(spd->fifo))) {
		wake_up_interruptible(&spd->writeable);
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

static unsigned int proc_events_poll(struct file *file,
		struct poll_table_struct *pt) {
	struct notifyfs_sb_info *spd;
	unsigned int mask = 0;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		mask |= POLLERR;
		goto out;
	}
	poll_wait(file, &spd->writeable, pt);
	poll_wait(file, &spd->readable, pt);

	if (atomic_read(&spd->unmounting) || !kfifo_is_empty(&spd->fifo)) {
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
	.poll = proc_events_poll
};

struct proc_dir_entry *create_events_file(void *data, struct proc_dir_entry *dir) {
	return proc_create_data(PROC_EVENTS_FILE, 0444, dir, &proc_events_fops, data);
}

/***** mask file *****/

static ssize_t proc_mask_read(struct file *file, char *buf, size_t count,
		loff_t *offp) {
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
		event_mask = atomic_read(&spd->event_mask);
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
static ssize_t proc_mask_write(struct file *file, const char *buf, size_t count,
		loff_t *offp) {
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
		pr_warn(NOTIFYFS_NAME ": unable to set mask %s on mount %s\n", buf, spd->proc_dir->name);
		goto out;
	}

	atomic_set(&spd->event_mask, event_mask);
	err = count; /* consider all data written */

out:
	return err;
}

static const struct file_operations proc_mask_fops = {
	.read = proc_mask_read,
	.write = proc_mask_write
};

struct proc_dir_entry *create_mask_file(void *data, struct proc_dir_entry *dir) {
	return proc_create_data(PROC_EVENT_MASK_FILE, 0664, dir, &proc_mask_fops, data);
}

/***** fifo block file *****/

static ssize_t proc_fifo_block_read(struct file *file, char *buf, size_t count,
		loff_t *offp) {
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
		fifo_block = atomic_read(&spd->fifo_block);
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
static ssize_t proc_fifo_block_write(struct file *file, const char *buf, size_t count,
		loff_t *offp) {
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
		pr_warn(NOTIFYFS_NAME ": unable to set fifo_block %s on mount %s\n", buf, spd->proc_dir->name);
		goto out;
	}

	atomic_set(&spd->fifo_block, (fifo_block != 0) ? BLOCKING_FIFO : NONBLOCKING_FIFO);
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

static ssize_t proc_fifo_size_read(struct file *file, char *buf, size_t count,
		loff_t *offp) {
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
		err = snprintf(buf, count, "%d\n", kfifo_size(&spd->fifo));
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

static ssize_t proc_pid_blacklist_read(struct file *file, char *buf, size_t count,
		loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	int pid_count = 0;

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
		spin_lock(&(spd->pids_lock));
		err = int_list_count(&spd->pids, &pid_count);
		spin_unlock(&(spd->pids_lock));
		if (err) {
			goto out;
		}
		err = snprintf(buf, count, "%d\n", pid_count);
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
static ssize_t proc_pid_blacklist_write(struct file *file, const char *buf, size_t count,
		loff_t *offp) {
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
			pr_warn(NOTIFYFS_NAME ": unable to parse pid list %s on mount %s\n", buf, spd->proc_dir->name);
			goto out;
		}
		if (pid == 0) {
			spin_lock(&(spd->pids_lock));
			err = int_list_clear(&spd->pids);
			spin_unlock(&(spd->pids_lock));
			if (err) {
				goto out;
			}
		} else if (pid < 0) {
			spin_lock(&(spd->pids_lock));
			int_list_remove(&spd->pids, -pid);
			spin_unlock(&(spd->pids_lock));
			if (err) {
				goto out;
			}
		} else {
			spin_lock(&(spd->pids_lock));
			err = int_list_add(&spd->pids, pid);
			if (!err) {
				err = int_list_sort(&spd->pids);
			}
			spin_unlock(&(spd->pids_lock));
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

static ssize_t proc_src_dir_read(struct file *file, char *buf, size_t count,
		loff_t *offp) {
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

