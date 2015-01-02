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

#ifndef _NOTIFYFS_H_
#define _NOTIFYFS_H_

/* Notification support */
#include "notifier.h"

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
/* atomic values in notifyfs_sb_info */
#include <linux/atomic.h>

/* the file system name */
#define NOTIFYFS_NAME "notifyfs"

/* notifyfs root inode number */
#define NOTIFYFS_ROOT_INO     1

/* useful for tracking code reachability */
#ifdef DEBUG
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)
#else
#define UDBG ;
#endif

/* operations vectors defined in specific files */
extern const struct file_operations notifyfs_main_fops;
extern const struct file_operations notifyfs_dir_fops;
extern const struct inode_operations notifyfs_main_iops;
extern const struct inode_operations notifyfs_dir_iops;
extern const struct inode_operations notifyfs_symlink_iops;
extern const struct super_operations notifyfs_sops;
extern const struct dentry_operations notifyfs_dops;
extern const struct address_space_operations notifyfs_aops, notifyfs_dummy_aops;
extern const struct vm_operations_struct notifyfs_vm_ops;

extern int notifyfs_init_inode_cache(void);
extern void notifyfs_destroy_inode_cache(void);
extern int notifyfs_init_dentry_cache(void);
extern void notifyfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *notifyfs_lookup(struct inode *dir, struct dentry *dentry,
		struct nameidata *nd);
extern struct inode *notifyfs_iget(struct super_block *sb,
		struct inode *lower_inode);
extern int notifyfs_interpose(struct dentry *dentry, struct super_block *sb,
		struct path *lower_path);

/* file private data */
struct notifyfs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};

/* notifyfs inode data in memory */
struct notifyfs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
};

/* notifyfs dentry data in memory */
struct notifyfs_dentry_info {
	spinlock_t lock; /* protects lower_path */
	struct path lower_path;
};

/* notifyfs super-block data in memory */
struct notifyfs_sb_info {
	struct super_block *lower_sb;

	/* notifier support */
	// configuration
	atomic_t event_mask;	/* current event mask -- mount option */
	atomic_t fifo_block;	/* mount option */

	// proc entries
	struct proc_dir_entry *proc_dir;	/* proc mount dir, named after inode */
	struct proc_dir_entry *proc_source;	/* source folder file */
	struct proc_dir_entry *proc_events;	/* events file */
	struct proc_dir_entry *proc_event_mask;	/* event mask */
	struct proc_dir_entry *proc_fifo_block;	/* fifo block */
	struct proc_dir_entry *proc_fifo_size;	/* fifo size */
	struct proc_dir_entry *proc_pid_blacklist;	/* pid blacklist file */
//	struct proc_dir_entry *proc_open;	/* blocking open */

	// event fifo
	struct kfifo fifo;
	spinlock_t fifo_lock;
	wait_queue_head_t writeable;
	wait_queue_head_t readable;

	// event management
	atomic64_t event_id;	/* current event number -- counter */
	// last event
	struct fs_event_header last_event;

	// pid blacklist
	struct int_list_t pids;
	spinlock_t pids_lock;

	// graceful shutdown
	atomic_t unmounting;	/* if != 0, then fs is being unmounted */
	/* end notifier support */
};

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * notifyfs_inode_info structure, NOTIFYFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct notifyfs_inode_info *NOTIFYFS_I(const struct inode *inode) {
	return container_of(inode, struct notifyfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define NOTIFYFS_D(dent) ((struct notifyfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define NOTIFYFS_SB(super) ((struct notifyfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define NOTIFYFS_F(file) ((struct notifyfs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *notifyfs_lower_file(const struct file *f) {
	return NOTIFYFS_F(f)->lower_file;
}

static inline void notifyfs_set_lower_file(struct file *f, struct file *val) {
	NOTIFYFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *notifyfs_lower_inode(const struct inode *i) {
	return NOTIFYFS_I(i)->lower_inode;
}

static inline void notifyfs_set_lower_inode(struct inode *i, struct inode *val) {
	NOTIFYFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *notifyfs_lower_super(
		const struct super_block *sb) {
	return NOTIFYFS_SB(sb)->lower_sb;
}

static inline void notifyfs_set_lower_super(struct super_block *sb,
		struct super_block *val) {
	NOTIFYFS_SB(sb)->lower_sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src) {
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void notifyfs_get_lower_path(const struct dentry *dent,
		struct path *lower_path) {
	spin_lock(&NOTIFYFS_D(dent)->lock);
	pathcpy(lower_path, &NOTIFYFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&NOTIFYFS_D(dent)->lock);
	return;
}
static inline void notifyfs_put_lower_path(const struct dentry *dent,
		struct path *lower_path) {
	path_put(lower_path);
	return;
}
static inline void notifyfs_set_lower_path(const struct dentry *dent,
		struct path *lower_path) {
	spin_lock(&NOTIFYFS_D(dent)->lock);
	pathcpy(&NOTIFYFS_D(dent)->lower_path, lower_path);
	spin_unlock(&NOTIFYFS_D(dent)->lock);
	return;
}
static inline void notifyfs_reset_lower_path(const struct dentry *dent) {
	spin_lock(&NOTIFYFS_D(dent)->lock);
	NOTIFYFS_D(dent)->lower_path.dentry = NULL;
	NOTIFYFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&NOTIFYFS_D(dent)->lock);
	return;
}
static inline void notifyfs_put_reset_lower_path(const struct dentry *dent) {
	struct path lower_path;
	spin_lock(&NOTIFYFS_D(dent)->lock);
	pathcpy(&lower_path, &NOTIFYFS_D(dent)->lower_path);
	NOTIFYFS_D(dent)->lower_path.dentry = NULL;
	NOTIFYFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&NOTIFYFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry) {
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir) {
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}
#endif	/* not _NOTIFYFS_H_ */
