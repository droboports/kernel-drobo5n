/*
 * Copyright (c) 2014-2015 Ricardo Padilha, Drobo Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "notifyfs.h"

#define STRINGIFY_EVENT 1
#define COPY_TO_KMESG 0

/* directory containing all proc files */
static struct proc_dir_entry *proc_folder;

/*
 * All operations have an oldName.
 * Only rename operations have a newName argument.
 */
void * create_notifyfs_event(const pid_t pid, const FsOperationType opType,
		const ino_t inode, const struct timespec ts, const char *oldName,
		const char *newName, int *size) {
	const size_t headerLen = sizeof(FsEventHeader);
	const size_t oldNameLen = strlen(oldName) + 1; // +1 for null terminator
	const size_t newNameLen = (newName != NULL) ? strlen(newName) + 1 : 0;
	const size_t len = headerLen + oldNameLen + newNameLen;

	void *buffer = NULL;
	FsEventHeader *header = NULL;

	buffer = kzalloc(len, GFP_KERNEL);
	if (buffer == NULL) {
		return ERR_PTR(-ENOMEM);
	}

	header = (FsEventHeader *) buffer;
	header->pid = pid;
	header->operation = opType;
	header->inode = inode;
	header->timestamp = ts.tv_sec;
	header->oldPathLen = oldNameLen;
	header->newPathLen = newNameLen;

	strncpy(buffer + headerLen, oldName, oldNameLen);
	strncpy(buffer + headerLen + oldNameLen, newName, newNameLen);
	*size = len;
	return buffer;
}

void destroy_notifyfs_event(void *buffer) {
	kfree(buffer);
}

/*
 * return: 1 if should send the event, 0 otherwise
 */
int should_send(struct super_block *sb, FsEventHeader *header) {
	struct notifyfs_sb_info *spd = sb->s_fs_info;
	struct FsEventHeader last_event = spd->last_event;

	if (last_event.pid != header->pid ||
		last_event.operation != header->operation ||
		last_event.inode != header->inode ||
		last_event.timestamp != header->timestamp) {
		return 1;
	}
	return 0;
}

#if STRINGIFY_EVENT
int minimumStringLength(const void* event) {
	const FsEventHeader * header = (FsEventHeader *) event;
	// an additional 96 bytes is over-estimated, I think the exact number is 77
	return header->oldPathLen + header->newPathLen + 96;
}
#endif

#if STRINGIFY_EVENT
/*
 * Return -EINVAL if given str is too short.
 */
int eventToString(const void* event, char *str, const size_t strlen) {
	const FsEventHeader * header = (FsEventHeader *) event;
	const size_t headerLen = sizeof(FsEventHeader);
	const char *oldName = event + headerLen;
	const char *newName =
			(header->newPathLen > 0) ?
					event + headerLen + header->oldPathLen : NULL;

	if (strlen < minimumStringLength(event)) {
		return -EINVAL;
	}

	if (header->newPathLen > 0) {
		sprintf(str, "pid %u op %u ino %lu ts %lu id %llu from %s to %s\n", header->pid,
				header->operation, header->inode, header->timestamp, header->id, oldName,
				newName);
	} else { // header->pathLen2 == 0
		sprintf(str, "pid %u op %u ino %lu ts %lu id %llu name %s\n", header->pid,
				header->operation, header->inode, header->timestamp, header->id, oldName);
	}
	return 0;
}
#endif

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
int send_event(struct super_block *sb, const FsOperationType op, struct inode *inode,
		const char *oldName, const char *newName) {
	int err = 0;
	struct notifyfs_sb_info *spd = NULL;
	char *event = NULL;
	int eventlen = 0;
//	unsigned long long id;
#if STRINGIFY_EVENT
	int strlen = 0;
	char *str = NULL;
#endif

	if (sb == NULL) {
		err = -EINVAL;
		goto out;
	}
	spd = sb->s_fs_info;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}
	if (inode == NULL) {
		err = -EINVAL;
		goto out;
	}

	event = create_notifyfs_event(current->pid, op, inode->i_ino,
			inode->i_mtime, oldName, newName, &eventlen);
	if (IS_ERR(event)) {
		err = PTR_ERR(event);
		goto out;
	}

#if STRINGIFY_EVENT
	strlen = minimumStringLength(event);
	str = kzalloc(strlen, GFP_KERNEL);
	if (str == NULL) {
		err = -ENOMEM;
		goto out_free_event;
	}

	err = eventToString(event, str, strlen);
	if (err != 0) {
		goto out_free_str;
	}
#endif

#if STRINGIFY_EVENT && COPY_TO_KMESG
	printk(str);
#endif

	if (should_send(sb, (FsEventHeader *) event)) {
//		id = spd->event_id + 1;
//		((FsEventHeader *) event)->id = id;
//		spd->event_id = id;

		if (kfifo_is_full(&(spd->fifo))) {
			err = wait_event_interruptible(spd->writeable, !kfifo_is_full(&(spd->fifo)));
			if (err) {
#if STRINGIFY_EVENT
				goto out_free_str;
#else
				goto out_free_event;
#endif
			}
		}

#if STRINGIFY_EVENT
		kfifo_in_spinlocked(&(spd->fifo), str, strlen, &(spd->fifo_lock));
#else
		kfifo_in_spinlocked(&(spd->fifo), event, eventlen, &(spd->fifo_lock));
#endif
//		printk("send_event %d %d\n", strlen, kfifo_avail(&(spd->fifo)));
		if (!kfifo_is_empty(&(spd->fifo))) {
			wake_up_interruptible(&spd->readable);
		}

		memcpy(&spd->last_event, event, sizeof(FsEventHeader));
	}

//	mutex_unlock(&(spd->write_lock));

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
 * @op:
 *   FileCreate = 0,
 *   FileModify = 1,
 *   FileDelete = 2,
 *   DirectoryCreate = 4,
 *   DirectoryDelete = 5,
 *   SetAttribute = 7,
 *   Unknown = 99
 *
 * return:
 *   0 if ok
 *   -EINVAL if dentry or dentry->inode is null
 *   -ENOMEM if unable to allocate memory to string conversion
 *   -ENAMETOOLONG from path to string conversion
 */
int send_dentry_event(struct super_block *sb, const FsOperationType op, struct dentry *dentry) {
	int err;
	char *buffer = NULL;
	char *name = NULL;

	if (sb == NULL) {
		err = -EINVAL;
		goto out;
	}
	if (dentry == NULL) {
		err = -EINVAL;
		goto out;
	}

	buffer = kzalloc(MAX_PATH_LENGTH, GFP_KERNEL);
	if (buffer == NULL) {
		err = -ENOMEM;
		goto out;
	}

	/*
	 * Can return ERR_PTR(-ENAMETOOLONG)
	 */
	name = dentry_path_raw(dentry, buffer, MAX_PATH_LENGTH);
	if (IS_ERR(name)) {
		err = PTR_ERR(name);
		goto out_free_buffer;
	}
	err = send_event(sb, op, dentry->d_inode, name, NULL);

out_free_buffer:
	kfree(buffer);
out:
	return err;
}

/*
 * Same as send_event(data, op, dentry, oldName, newName);
 *
 * @op:
 *   FileMove = 3,
 *   DirectoryMove = 6
 *
 * return:
 *   0 if ok
 *   -EINVAL if dentry or dentry->inode is null
 *   -ENOMEM if unable to allocate memory to string conversion
 *   -ENAMETOOLONG from path to string conversion
 */
int send_dentry_rename(struct super_block *sb, const FsOperationType op, struct inode *inode,
		const char *oldName, const char *newName) {
	if (sb == NULL) {
		return -EINVAL;
	}
	if (inode == NULL) {
		return -EINVAL;
	}
	if (oldName == NULL) {
		return -EINVAL;
	}
	if (newName == NULL) {
		return -EINVAL;
	}
	return send_event(sb, op, inode, oldName, newName);
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
int send_file_event(struct super_block *sb, const FsOperationType opType, const struct file *file) {
	if (sb == NULL) {
		return -EINVAL;
	}
	if (file == NULL) {
		return -EINVAL;
	}
	return send_dentry_event(sb, opType, file->f_path.dentry);
}

/*
 * return:
 *   0 if ok
 *   -ENOMEM if unable to create folder
 */
int create_proc_folder(void) {
	/* Create the /proc folder */
	proc_folder = proc_mkdir(NOTIFYFS_NAME, NULL);
	if (proc_folder == NULL) {
		pr_warn("NotifyFS: Unable to create proc directory");
		return -ENOMEM;
	}
	return 0;
}

void destroy_proc_folder(void) {
	/*
	 * We can only unload the module if all mounts were removed,
	 * so there should be no files left inside the folder.
	 */
	remove_proc_entry(NOTIFYFS_NAME, NULL);
}

static ssize_t proc_fifo_read(struct file *file, char *buf, size_t count,
		loff_t *offp) {
	int err;
	struct notifyfs_sb_info *spd;
	unsigned int copied;

	spd = PDE(file->f_path.dentry->d_inode)->data;
	if (spd == NULL) {
		err = -EINVAL;
		goto out;
	}
	if (kfifo_is_empty(&(spd->fifo))) {
		err = wait_event_interruptible(spd->readable, !kfifo_is_empty(&(spd->fifo)));
		if (err) {
			goto out;
		}
	}
	spin_lock(&(spd->fifo_lock));
	err = kfifo_to_user(&(spd->fifo), buf, count, &copied);
	spin_unlock(&(spd->fifo_lock));

//	printk("proc_fifo_read %d %d\n", copied, kfifo_avail(&(spd->fifo)));
	if (!kfifo_is_full(&(spd->fifo))) {
		wake_up_interruptible(&spd->writeable);
	}
	/* If no errors up to now, then return bytes copied */
	if (!err) {
		err = copied;
	}
out:
	return err;
}

static unsigned int proc_fifo_poll(struct file *file,
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

	if (!kfifo_is_empty(&spd->fifo)) {
		mask |= POLLIN | POLLRDNORM;
	}
//	if (!kfifo_is_full(&spd->fifo)) {
//		mask |= POLLOUT | POLLWRNORM;
//	}
out:
	return mask;
}

static const struct file_operations proc_fifo_fops = {
	.read = proc_fifo_read,
	.poll = proc_fifo_poll
};

struct proc_dir_entry *create_proc_file(const char *name, void *data) {
	return proc_create_data(name, 0444, proc_folder, &proc_fifo_fops, data);
}

void destroy_proc_file(const char *name) {
	remove_proc_entry(name, proc_folder);
}
