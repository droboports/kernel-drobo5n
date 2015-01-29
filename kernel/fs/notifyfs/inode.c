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

static int notifyfs_create(struct inode *dir, struct dentry *dentry, int mode,
		struct nameidata *nd) {
	int err = 0;
	int unlock = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path, saved_path;

	vfs_lock_acquire(dentry->d_sb, &unlock, FS_FILE_CREATE);

	notifyfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err) {
		goto out_unlock;
	}

	pathcpy(&saved_path, &nd->path);
	pathcpy(&nd->path, &lower_path);
	err = vfs_create(lower_parent_dentry->d_inode, lower_dentry, mode, nd);
	pathcpy(&nd->path, &saved_path);
	if (err) {
		goto out;
	}

	err = notifyfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err) {
		goto out;
	}
	fsstack_copy_attr_times(dir, notifyfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

	/* notifier support */
	UDBG;
	err = send_dentry_event(dentry->d_sb, FS_FILE_CREATE, lower_dentry);
	/* end notifier support */

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	notifyfs_put_lower_path(dentry, &lower_path);

	vfs_lock_release(dentry->d_sb, &unlock);
	return err;
}

static int notifyfs_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry) {
	int err = 0;
	int unlock = 0;
	u64 file_size_save;
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	struct path lower_old_path, lower_new_path;

	vfs_lock_acquire(old_dentry->d_sb, &unlock, FS_FILE_CREATE);

	file_size_save = i_size_read(old_dentry->d_inode);
	notifyfs_get_lower_path(old_dentry, &lower_old_path);
	notifyfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = mnt_want_write(lower_new_path.mnt);
	if (err) {
		goto out_unlock;
	}

	err = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
			lower_new_dentry);
	if (err || !lower_new_dentry->d_inode) {
		goto out;
	}

	err = notifyfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err) {
		goto out;
	}
	fsstack_copy_attr_times(dir, lower_new_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_new_dentry->d_inode);
	set_nlink(old_dentry->d_inode,
			notifyfs_lower_inode(old_dentry->d_inode)->i_nlink);
	i_size_write(new_dentry->d_inode, file_size_save);

	/* notifier support */
	UDBG;
	err = send_dentry_event(old_dentry->d_sb, FS_FILE_CREATE, lower_new_dentry);
	/* end notifier support */

out:
	mnt_drop_write(lower_new_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	notifyfs_put_lower_path(old_dentry, &lower_old_path);
	notifyfs_put_lower_path(new_dentry, &lower_new_path);

	vfs_lock_release(old_dentry->d_sb, &unlock);
	return err;
}

static int notifyfs_unlink(struct inode *dir, struct dentry *dentry) {
	int err = 0;
	int unlock = 0;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = notifyfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;

	vfs_lock_acquire(dentry->d_sb, &unlock, FS_FILE_DELETE);

	notifyfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err) {
		goto out_unlock;
	}
	err = vfs_unlink(lower_dir_inode, lower_dentry);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && (lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)) {
		err = 0;
	}
	if (err) {
		goto out;
	}
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(dentry->d_inode, notifyfs_lower_inode(dentry->d_inode)->i_nlink);
	dentry->d_inode->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */

	/* notifier support */
	UDBG;
	err = send_dentry_event(dentry->d_sb, FS_FILE_DELETE, lower_dentry);
	/* end notifier support */

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	notifyfs_put_lower_path(dentry, &lower_path);

	vfs_lock_release(dentry->d_sb, &unlock);
	return err;
}

static int notifyfs_symlink(struct inode *dir, struct dentry *dentry,
		const char *symname) {
	int err = 0;
	int unlock = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	vfs_lock_acquire(dentry->d_sb, &unlock, FS_FILE_CREATE);

	notifyfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err) {
		goto out_unlock;
	}
	err = vfs_symlink(lower_parent_dentry->d_inode, lower_dentry, symname);
	if (err) {
		goto out;
	}
	err = notifyfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err) {
		goto out;
	}
	fsstack_copy_attr_times(dir, notifyfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

	/* notifier support */
	UDBG;
	err = send_dentry_event(dentry->d_sb, FS_FILE_CREATE, lower_dentry);
	/* end notifier support */

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	notifyfs_put_lower_path(dentry, &lower_path);

	vfs_lock_release(dentry->d_sb, &unlock);
	return err;
}

static int notifyfs_mkdir(struct inode *dir, struct dentry *dentry, int mode) {
	int err = 0;
	int unlock = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	vfs_lock_acquire(dentry->d_sb, &unlock, FS_DIR_CREATE);

	notifyfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err) {
		goto out_unlock;
	}
	err = vfs_mkdir(lower_parent_dentry->d_inode, lower_dentry, mode);
	if (err) {
		goto out;
	}

	err = notifyfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err) {
		goto out;
	}

	fsstack_copy_attr_times(dir, notifyfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
	/* update number of links on parent directory */
	set_nlink(dir, notifyfs_lower_inode(dir)->i_nlink);

	/* notifier support */
	UDBG;
	err = send_dentry_event(dentry->d_sb, FS_DIR_CREATE, lower_dentry);
	/* end notifier support */

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	notifyfs_put_lower_path(dentry, &lower_path);

	vfs_lock_release(dentry->d_sb, &unlock);
	return err;
}

static int notifyfs_rmdir(struct inode *dir, struct dentry *dentry) {
	int err = 0;
	int unlock = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	struct path lower_path;

	vfs_lock_acquire(dentry->d_sb, &unlock, FS_DIR_DELETE);

	notifyfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err) {
		goto out_unlock;
	}
	err = vfs_rmdir(lower_dir_dentry->d_inode, lower_dentry);
	if (err) {
		goto out;
	}

	d_drop(dentry); /* drop our dentry on success (why not VFS's job?) */
	if (dentry->d_inode) {
		clear_nlink(dentry->d_inode);
	}
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);

	/* notifier support */
	UDBG;
	err = send_dentry_event(dentry->d_sb, FS_DIR_DELETE, lower_dentry);
	/* end notifier support */

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	notifyfs_put_lower_path(dentry, &lower_path);

	vfs_lock_release(dentry->d_sb, &unlock);
	return err;
}

static int notifyfs_mknod(struct inode *dir, struct dentry *dentry, int mode,
		dev_t dev) {
	int err = 0;
	int unlock = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	vfs_lock_acquire(dentry->d_sb, &unlock, FS_UNSUPPORTED);

	notifyfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err) {
		goto out_unlock;
	}
	err = vfs_mknod(lower_parent_dentry->d_inode, lower_dentry, mode, dev);
	if (err) {
		goto out;
	}

	err = notifyfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err) {
		goto out;
	}
	fsstack_copy_attr_times(dir, notifyfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

	/* notifier support */
	UDBG;
	err = send_dentry_event(dentry->d_sb, FS_UNSUPPORTED, lower_dentry);
	/* end notifier support */

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	notifyfs_put_lower_path(dentry, &lower_path);

	vfs_lock_release(dentry->d_sb, &unlock);
	return err;
}

/*
 * The locking rules in notifyfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int notifyfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry) {
	int err = 0;
	int unlock = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;
	/* notifier support */
	fs_operation_type op = S_ISDIR(old_dentry->d_inode->i_mode) ? FS_DIR_MOVE : \
			S_ISREG(old_dentry->d_inode->i_mode) ? FS_FILE_MOVE : FS_UNSUPPORTED;
	char *oldNameBuffer = NULL;
	char *oldName;
	char *newNameBuffer = NULL;
	char *newName;
	/* end notifier support */

	vfs_lock_acquire(old_dentry->d_sb, &unlock, op);

	notifyfs_get_lower_path(old_dentry, &lower_old_path);
	notifyfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = mnt_want_write(lower_old_path.mnt);
	if (err) {
		goto out;
	}
	err = mnt_want_write(lower_new_path.mnt);
	if (err) {
		goto out_drop_old_write;
	}

	/* notifier support */
	// We have to save the names before forwarding the rename call because
	// the names get overwritten.
	oldNameBuffer = kzalloc(MAX_PATH_LENGTH, GFP_KERNEL);
	CHECK_PTR(oldNameBuffer, out_err);
	oldName = dentry_path_raw(lower_old_dentry, oldNameBuffer, MAX_PATH_LENGTH);
	// Can only be -ENAMETOOLONG
	CHECK_PTR(oldName, out_free_old_name);
	newNameBuffer = kzalloc(MAX_PATH_LENGTH, GFP_KERNEL);
	CHECK_PTR(newNameBuffer, out_free_old_name);
	newName = dentry_path_raw(lower_new_dentry, newNameBuffer, MAX_PATH_LENGTH);
	// Can only be -ENAMETOOLONG
	CHECK_PTR(oldName, out_free_new_name);
	/* end notifier support */

	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			lower_new_dir_dentry->d_inode, lower_new_dentry);
	if (err) {
		goto out_free_new_name;
	}

	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
	fsstack_copy_inode_size(new_dir, lower_new_dir_dentry->d_inode);
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir, lower_old_dir_dentry->d_inode);
		fsstack_copy_inode_size(old_dir, lower_old_dir_dentry->d_inode);
	}

	/* notifier support */
	UDBG;
	err = send_dentry_rename(old_dentry->d_sb, op, lower_old_dentry->d_inode,
			oldName, newName);
	/* end notifier support */

	/* notifier support */
out_free_new_name:
	kfree(newNameBuffer);
out_free_old_name:
	kfree(oldNameBuffer);
	/* end notifier support */
out_err:
	mnt_drop_write(lower_new_path.mnt);
out_drop_old_write:
	mnt_drop_write(lower_old_path.mnt);
out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	notifyfs_put_lower_path(old_dentry, &lower_old_path);
	notifyfs_put_lower_path(new_dentry, &lower_new_path);

	vfs_lock_release(old_dentry->d_sb, &unlock);
	return err;
}

int notifyfs_readlink(struct dentry *dentry, char __user *buf,
		int bufsiz) {
	int err = 0;
	struct dentry *lower_dentry;
	struct path lower_path;

	notifyfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_inode->i_op
			|| !lower_dentry->d_inode->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->readlink(lower_dentry, buf, bufsiz);
	if (err < 0) {
		goto out;
	}
	fsstack_copy_attr_atime(dentry->d_inode, lower_dentry->d_inode);

out:
	notifyfs_put_lower_path(dentry, &lower_path);
	return err;
}

static void *notifyfs_follow_link(struct dentry *dentry, struct nameidata *nd) {
	int unlock = 0;
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto out;
	}

	vfs_lock_acquire(dentry->d_sb, &unlock, FS_UNSUPPORTED);

	// XXX: intercept stale symlink inodes here

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = notifyfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
out:
	nd_set_link(nd, buf);

	vfs_lock_release(dentry->d_sb, &unlock);
	return NULL;
}

/* this @nd *IS* still used */
static void notifyfs_put_link(struct dentry *dentry, struct nameidata *nd,
		void *cookie) {
	char *buf = nd_get_link(nd);
	if (!IS_ERR(buf)) {
		kfree(buf);
	}
}

/**
 * inode_permission - Check for access rights to a given inode
 * @inode: Inode to check permission on
 * @mask: Right to check for (%MAY_READ, %MAY_WRITE, %MAY_EXEC)
 *
 * Check for read/write/execute permissions on an inode.  We use fs[ug]id for
 * this, letting us set arbitrary permissions for filesystem access without
 * changing the "normal" UIDs which are used for other things.
 *
 * When checking for MAY_APPEND, MAY_WRITE must also be set in @mask.
 */
static int notifyfs_permission(struct inode *inode, int mask) {
	int err = 0;
	struct inode *lower_inode;

	lower_inode = notifyfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int notifyfs_setattr(struct dentry *dentry, struct iattr *ia) {
	int err = 0;
	int unlock = 0;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;
	fs_operation_type op = S_ISDIR(dentry->d_inode->i_mode) ? FS_DIR_WATTRIB : \
			S_ISREG(dentry->d_inode->i_mode) ? FS_FILE_WATTRIB : FS_UNSUPPORTED;

	inode = dentry->d_inode;

	vfs_lock_acquire(dentry->d_sb, &unlock, op);

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err) {
		goto out_err;
	}

	notifyfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = notifyfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE) {
		lower_ia.ia_file = notifyfs_lower_file(ia->ia_file);
	}

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err) {
			goto out;
		}
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID)) {
		lower_ia.ia_valid &= ~ATTR_MODE;
	}

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use lower_dentry->d_inode, because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	err = notify_change(lower_dentry, &lower_ia); /* note: lower_ia */
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
	if (err) {
		goto out;
	}

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

	/* notifier support */
	UDBG;
	err = send_dentry_event(dentry->d_sb, op, lower_dentry);
	/* end notifier support */

out:
	notifyfs_put_lower_path(dentry, &lower_path);
out_err:
	vfs_lock_release(dentry->d_sb, &unlock);
	return err;
}

static int notifyfs_setxattr(struct dentry *dentry, const char *name,
		const void *value, size_t size, int flags) {
	int err = 0;
	int unlock = 0;
	struct dentry *lower_dentry;
	struct path lower_path;
	fs_operation_type op = S_ISDIR(dentry->d_inode->i_mode) ? FS_DIR_WXATTRIB : \
			S_ISREG(dentry->d_inode->i_mode) ? FS_FILE_WXATTRIB : FS_UNSUPPORTED;

	vfs_lock_acquire(dentry->d_sb, &unlock, op);

	notifyfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_inode->i_op
			|| !lower_dentry->d_inode->i_op->setxattr) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->setxattr(lower_dentry, name, value, size,
			flags);
	if (err)
		goto out;

	/* notifier support */
	UDBG;
	err = send_dentry_event(dentry->d_sb, op, lower_dentry);
	/* end notifier support */

out:
	notifyfs_put_lower_path(dentry, &lower_path);

	vfs_lock_release(dentry->d_sb, &unlock);
	return err;
}

static ssize_t notifyfs_getxattr(struct dentry *dentry, const char *name,
		void *buffer, size_t size) {
	int err = 0;
	int unlock = 0;
	struct dentry *lower_dentry;
	struct path lower_path;
	fs_operation_type op = S_ISDIR(dentry->d_inode->i_mode) ? FS_DIR_RXATTRIB : \
			S_ISREG(dentry->d_inode->i_mode) ? FS_FILE_RXATTRIB : FS_UNSUPPORTED;

	vfs_lock_acquire(dentry->d_sb, &unlock, op);

	notifyfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_inode->i_op
			|| !lower_dentry->d_inode->i_op->getxattr) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->getxattr(lower_dentry, name, buffer,
			size);

out:
	notifyfs_put_lower_path(dentry, &lower_path);

	vfs_lock_release(dentry->d_sb, &unlock);
	return err;
}

static ssize_t notifyfs_listxattr(struct dentry *dentry, char *buffer,
		size_t buffer_size) {
	int err = 0;
	int unlock = 0;
	struct dentry *lower_dentry;
	struct path lower_path;
	fs_operation_type op = S_ISDIR(dentry->d_inode->i_mode) ? FS_DIR_RXATTRIB : \
			S_ISREG(dentry->d_inode->i_mode) ? FS_FILE_RXATTRIB : FS_UNSUPPORTED;

	vfs_lock_acquire(dentry->d_sb, &unlock, op);

	notifyfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_inode->i_op
			|| !lower_dentry->d_inode->i_op->listxattr) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->listxattr(lower_dentry, buffer,
			buffer_size);

out:
	notifyfs_put_lower_path(dentry, &lower_path);

	vfs_lock_release(dentry->d_sb, &unlock);
	return err;
}

static int notifyfs_removexattr(struct dentry *dentry, const char *name) {
	int err = 0;
	int unlock = 0;
	struct dentry *lower_dentry;
	struct path lower_path;
	fs_operation_type op = S_ISDIR(dentry->d_inode->i_mode) ? FS_DIR_WXATTRIB : \
			S_ISREG(dentry->d_inode->i_mode) ? FS_FILE_WXATTRIB : FS_UNSUPPORTED;

	vfs_lock_acquire(dentry->d_sb, &unlock, op);

	notifyfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_inode->i_op
			|| !lower_dentry->d_inode->i_op->removexattr) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->removexattr(lower_dentry, name);
	if (err)
		goto out;

	/* notifier support */
	UDBG;
	err = send_dentry_event(dentry->d_sb, op, lower_dentry);
	/* end notifier support */

out:
	notifyfs_put_lower_path(dentry, &lower_path);

	vfs_lock_release(dentry->d_sb, &unlock);
	return err;
}

const struct inode_operations notifyfs_symlink_iops = {
	.readlink = notifyfs_readlink,
	.permission = notifyfs_permission,
	.follow_link = notifyfs_follow_link,
	.setattr = notifyfs_setattr,
	.put_link = notifyfs_put_link,
	.setxattr = notifyfs_setxattr,
	.getxattr = notifyfs_getxattr,
	.listxattr = notifyfs_listxattr,
	.removexattr = notifyfs_removexattr
};

const struct inode_operations notifyfs_dir_iops = {
	.create = notifyfs_create,
	.lookup = notifyfs_lookup,
	.link = notifyfs_link,
	.unlink = notifyfs_unlink,
	.symlink = notifyfs_symlink,
	.mkdir = notifyfs_mkdir,
	.rmdir = notifyfs_rmdir,
	.mknod = notifyfs_mknod,
	.rename = notifyfs_rename,
	.permission = notifyfs_permission,
	.setattr = notifyfs_setattr,
	.setxattr = notifyfs_setxattr,
	.getxattr = notifyfs_getxattr,
	.listxattr = notifyfs_listxattr,
	.removexattr = notifyfs_removexattr
};

const struct inode_operations notifyfs_main_iops = {
	.permission = notifyfs_permission,
	.setattr = notifyfs_setattr,
	.setxattr = notifyfs_setxattr,
	.getxattr = notifyfs_getxattr,
	.listxattr = notifyfs_listxattr,
	.removexattr = notifyfs_removexattr
};
