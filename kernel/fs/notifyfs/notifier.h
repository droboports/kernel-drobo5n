/*
 * Copyright (c) 2014-2015 Ricardo Padilha for Drobo Inc
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
/* array list for pid blacklist */
#include "array_list.h"
/* event definitions */
#include "events.h"

#define PROC_SRC_DIR_FILE "source"
#define PROC_EVENTS_FILE "events"
#define PROC_EVENT_MASK_FILE "event_mask"
#define PROC_FIFO_BLOCK_FILE "fifo_block"
#define PROC_FIFO_SIZE_FILE "fifo_size"
#define PROC_PID_BLACKLIST_FILE "pid_blacklist"

int send_file_event(struct super_block *sb, const fs_operation_type op, const struct file *file);

int send_dentry_event(struct super_block *sb, const fs_operation_type op, struct dentry *dentry);

int send_dentry_rename(struct super_block *sb, const fs_operation_type op, struct inode *inode, const char *old_name, const char *new_name);

int create_proc_dir(void);

void destroy_proc_dir(void);

struct proc_dir_entry *create_proc_mount_dir(ino_t inode);

void destroy_proc_mount_dir(struct proc_dir_entry *dir);

struct proc_dir_entry *create_src_dir_file(void *data, struct proc_dir_entry *dir);

struct proc_dir_entry *create_events_file(void *data, struct proc_dir_entry *dir);

struct proc_dir_entry *create_mask_file(void *data, struct proc_dir_entry *dir);

struct proc_dir_entry *create_fifo_block_file(void *data, struct proc_dir_entry *dir);

struct proc_dir_entry *create_fifo_size_file(void *data, struct proc_dir_entry *dir);

struct proc_dir_entry *create_pid_blacklist_file(void *data, struct proc_dir_entry *dir);

#define CHECK_NULL(ptr, label) \
	if (IS_ERR_OR_NULL(ptr)) {\
		err = !(ptr) ? -EINVAL : PTR_ERR(ptr);\
		goto label;\
	}

#define CHECK_PTR(ptr, label) \
	if (IS_ERR_OR_NULL(ptr)) {\
		err = !(ptr) ? -ENOMEM : PTR_ERR(ptr);\
		goto label;\
	}
