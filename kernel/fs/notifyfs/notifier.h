/*
 * Copyright (c) 2014-2015 Ricardo Padilha, Drobo Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* notifyfs_d_path requires get_fs_root */
#include <linux/fs_struct.h>
/* notifications are accessed under proc */
#include <linux/proc_fs.h>
#include <linux/poll.h>
/* message queues between kernel and user space */
#include <linux/kfifo.h>

/* fifo size in elements (events), this must be a power of 2 */
static const unsigned int FIFO_SIZE = 128;

// support paths up to 1 KiB characters
#define MAX_PATH_LENGTH 1024

/*
 * FsEvent is a buffer containing:
 * - offset 0:                                 struct header
 * - offset sizeof(header):                    char[] oldPath
 * - offset sizeof(header)+header->oldPathLen: char[] newPath
 *
 * Total length of FsEvent: sizeof(header) + strlen(path1) + strlen(path2)
 */

/* Duplicate of FsOpTypes.h */
typedef enum FsOperationType {
	FileCreate = 0,
	FileModify = 1,
	FileDelete = 2,
	FileMove = 3,
	DirectoryCreate = 4,
	DirectoryDelete = 5,
	DirectoryMove = 6,
	SetAttribute = 7,
	Unknown = 99
} FsOperationType;

typedef struct FsEventHeader {
	pid_t pid;
	unsigned char operation;
	ino_t inode;
	time_t timestamp;
	unsigned long long id;
	size_t oldPathLen;
	size_t newPathLen;
} FsEventHeader;

/* maximum size of an FsEvent */
#define MAX_EVENT_SIZE sizeof(FsEventHeader) + 2 * MAX_PATH_LENGTH

int send_file_event(struct super_block *sb, const FsOperationType op, const struct file *file);

int send_dentry_event(struct super_block *sb, const FsOperationType op, struct dentry *dentry);

int send_dentry_rename(struct super_block *sb, const FsOperationType op, struct inode *inode, const char *oldName, const char *newName);

int create_proc_folder(void);

void destroy_proc_folder(void);

struct proc_dir_entry *create_proc_file(const char *name, void *data);

void destroy_proc_file(const char *name);
