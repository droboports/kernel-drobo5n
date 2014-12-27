/*
 * Copyright (c) 2014-2015 Ricardo Padilha, Drobo Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "notifyfs.h"

/*
 * @opType: valid input:
 *  FileCreate = 0,
 *  FileModify = 1,
 *  FileDelete = 2,
 *  DirectoryCreate = 4,
 *  DirectoryDelete = 5,
 *  SetAttribute = 7,
 *  Unknown = 99
 *
 * return: either -EINVAL if fileFrom or fileFrom->f_path is null,
 *         or -ENAMETOOLONG from path to string conversion.
 */
int send_file_event(const FsOperationType opType, const struct file *fileFrom) {
	if (!fileFrom) {
		return -EINVAL;
	}
	return send_dentry_event(opType, fileFrom->f_path.dentry);
}

/*
 * @opType: valid input:
 *  FileCreate = 0,
 *  FileModify = 1,
 *  FileDelete = 2,
 *  DirectoryCreate = 4,
 *  DirectoryDelete = 5,
 *  SetAttribute = 7,
 *  Unknown = 99
 *
 * return: either -EINVAL if dentryFrom is null,
 *         or -ENAMETOOLONG from path to string conversion.
 */
int send_dentry_event(const FsOperationType opType, struct dentry *dentryFrom) {
	/* support paths up to 4K characters */
	int buflen = 4096;
	char bufferFrom[buflen];
	char *nameFrom;
	const struct inode *ino = dentryFrom->d_inode;

	if (!dentryFrom) {
		return -EINVAL;
	}

	nameFrom = dentry_path_raw(dentryFrom, bufferFrom, buflen);
	if (IS_ERR(nameFrom)) {
		/* it can only be -ENAMETOOLONG */
		return PTR_ERR(nameFrom);
	}
	printk(KERN_INFO "pid %u op %u ino %lu sec %lu nsec %.9ld from %s\n",
	current->pid, opType, ino->i_ino, ino->i_mtime.tv_sec,
			(long) ino->i_mtime.tv_nsec, nameFrom);
	return 0;
}

int send_dentry_rename(const FsOperationType opType, struct dentry *dentryFrom, const char *oldPath) {
	/* support paths up to 4K characters */
	int buflen = 4096;
	char bufferFrom[buflen];
	char *nameFrom;
	const struct inode *ino = dentryFrom->d_inode;

	if (!dentryFrom) {
		return -EINVAL;
	}

	nameFrom = dentry_path_raw(dentryFrom, bufferFrom, buflen);
	if (IS_ERR(nameFrom)) {
		/* it can only be -ENAMETOOLONG */
		return PTR_ERR(nameFrom);
	}

	printk(KERN_INFO "pid %u op %u ino %lu sec %lu nsec %.9ld from %s to %s\n",
	current->pid, opType, ino->i_ino, ino->i_mtime.tv_sec,
			(long) ino->i_mtime.tv_nsec, oldPath, nameFrom);
	return 0;
}

