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

static ssize_t notifyfs_read(struct file *file, char __user *buf, size_t count,
		loff_t *ppos) {
	int err;
	int err_notify = 0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = notifyfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0) {
		fsstack_copy_attr_atime(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
	}

	/* notifier support */
	if (err >= 0) {
		UDBG;
		err_notify = send_file_event(dentry->d_sb, FS_FILE_READ, lower_file);
		if (err_notify) {
			err = err_notify;
		}
	}
	/* end notifier support */

	return err;
}

static ssize_t notifyfs_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos) {
	int err = 0;
	int err_notify = 0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = notifyfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
		fsstack_copy_attr_times(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
	}

	/* notifier support */
	if (err >= 0) {
		UDBG;
		err_notify = send_file_event(dentry->d_sb, FS_FILE_WRITE, lower_file);
		if (err_notify) {
			err = err_notify;
		}
	}
	/* end notifier support */

	return err;
}

static int notifyfs_readdir(struct file *file, void *dirent, filldir_t filldir) {
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = notifyfs_lower_file(file);
	err = vfs_readdir(lower_file, filldir, dirent);
	file->f_pos = lower_file->f_pos;
	if (err >= 0) {
		/* copy the atime */
		fsstack_copy_attr_atime(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
	}
	return err;
}

static long notifyfs_unlocked_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg) {
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = notifyfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op) {
		goto out;
	}
	if (lower_file->f_op->unlocked_ioctl) {
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);
	}

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err) {
		fsstack_copy_attr_all(file->f_path.dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
	}
	out: return err;
}

#ifdef CONFIG_COMPAT
static long notifyfs_compat_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg) {
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = notifyfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

	out: return err;
}
#endif

static int notifyfs_mmap(struct file *file, struct vm_area_struct *vma) {
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = notifyfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		pr_err(NOTIFYFS_NAME ": lower file system does not "
		"support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!NOTIFYFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			pr_err(NOTIFYFS_NAME ": lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &notifyfs_vm_ops;
	vma->vm_flags |= VM_CAN_NONLINEAR;

	file->f_mapping->a_ops = &notifyfs_aops; /* set our aops */
	if (!NOTIFYFS_F(file)->lower_vm_ops) {
		/* save for our ->fault */
		NOTIFYFS_F(file)->lower_vm_ops = saved_vm_ops;
	}

out:
	return err;
}

static int notifyfs_open(struct inode *inode, struct file *file) {
	int err = 0;
	int err_notify = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data = kzalloc(sizeof(struct notifyfs_file_info), GFP_KERNEL);
	if (!NOTIFYFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link notifyfs's file struct to lower's */
	notifyfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(lower_path.dentry, lower_path.mnt, file->f_flags,
	current_cred());
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = notifyfs_lower_file(file);
		goto out_err;
	}

	notifyfs_set_lower_file(file, lower_file);
	fsstack_copy_attr_all(inode, notifyfs_lower_inode(inode));

	/* notifier support */
	UDBG;
	err_notify = send_file_event(file->f_path.dentry->d_sb, FS_FILE_OPEN, lower_file);
	if (err_notify) {
		err = err_notify;
		goto out_err;
	}
	/* end notifier support */
	goto out;

out_err:
	if (lower_file) {
		notifyfs_set_lower_file(file, NULL);
		fput(lower_file); /* fput calls dput for lower_dentry */
	}
	kfree(NOTIFYFS_F(file));
out:
	return err;
}

static int notifyfs_flush(struct file *file, fl_owner_t id) {
	int err = 0;
	int err_notify = 0;
	struct file *lower_file = NULL;

	lower_file = notifyfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		err = lower_file->f_op->flush(lower_file, id);
	}

	/* notifier support */
	if (!err) {
		UDBG;
		if (S_ISDIR(lower_file->f_path.dentry->d_inode->i_mode)) {
			err_notify = send_file_event(file->f_path.dentry->d_sb, FS_DIR_FLUSH, lower_file);
		} else {
			err_notify = send_file_event(file->f_path.dentry->d_sb, FS_FILE_FLUSH, lower_file);
		}
		if (err_notify) {
			err = err_notify;
		}
	}
	/* end notifier support */

	return err;
}

/* release all lower object references & free the file info structure */
static int notifyfs_file_release(struct inode *inode, struct file *file) {
	int err = 0;
	struct file *lower_file;

	lower_file = notifyfs_lower_file(file);
	if (lower_file) {
		/* notifier support */
		UDBG;
		if (S_ISREG(lower_file->f_path.dentry->d_inode->i_mode)) {
			err = send_file_event(file->f_path.dentry->d_sb, FS_FILE_CLOSE, lower_file);
		}
		if (err) {
			goto out;
		}
		/* end notifier support */
		notifyfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(NOTIFYFS_F(file));

out:
	return err;
}

static int notifyfs_fsync(struct file *file, loff_t start, loff_t end,
		int datasync) {
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = generic_file_fsync(file, start, end, datasync);
	if (err) {
		goto out;
	}
	lower_file = notifyfs_lower_file(file);
	notifyfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	notifyfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int notifyfs_fasync(int fd, struct file *file, int flag) {
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = notifyfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync) {
		err = lower_file->f_op->fasync(fd, lower_file, flag);
	}

	return err;
}

static ssize_t notifyfs_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos) {
	int err = -EINVAL;
	int err_notify = 0;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = notifyfs_lower_file(file);
	if (!lower_file->f_op->aio_read) {
		goto out;
	}
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_read(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_attr_atime(file->f_path.dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
	}

	/* notifier support */
	if (err >= 0 || err == -EIOCBQUEUED) {
		UDBG;
		err_notify = send_file_event(file->f_path.dentry->d_sb, FS_FILE_READ,
				lower_file);
		if (err_notify) {
			err = err_notify;
		}
	}
	/* end notifier support */

out:
	return err;
}

static ssize_t notifyfs_aio_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos) {
	int err = -EINVAL;
	int err_notify = 0;
	struct file *file, *lower_file;

	file = iocb->ki_filp;
	lower_file = notifyfs_lower_file(file);
	if (!lower_file->f_op->aio_write) {
		goto out;
	}
	/*
	 * It appears safe to rewrite this iocb, because in
	 * do_io_submit@fs/aio.c, iocb is a just copy from user.
	 */
	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->aio_write(iocb, iov, nr_segs, pos);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(file->f_path.dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
		fsstack_copy_attr_times(file->f_path.dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
	}

	/* notifier support */
	if (err >= 0 || err == -EIOCBQUEUED) {
		UDBG;
		err_notify = send_file_event(file->f_path.dentry->d_sb, FS_FILE_READ,
				lower_file);
		if (err_notify) {
			err = err_notify;
		}
	}
	/* end notifier support */

out:
	return err;
}

/*
 * Wrapfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t notifyfs_file_llseek(struct file *file, loff_t offset, int whence) {
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0) {
		goto out;
	}

	lower_file = notifyfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

const struct file_operations notifyfs_main_fops = {
	.llseek = generic_file_llseek,
	.read = notifyfs_read,
	.write = notifyfs_write,
	.unlocked_ioctl = notifyfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = notifyfs_compat_ioctl,
#endif
	.mmap = notifyfs_mmap,
	.open = notifyfs_open,
	.flush = notifyfs_flush,
	.release = notifyfs_file_release,
	.fsync = notifyfs_fsync,
	.fasync = notifyfs_fasync,
	.aio_read = notifyfs_aio_read,
	.aio_write = notifyfs_aio_write
};

/* trimmed directory options */
const struct file_operations notifyfs_dir_fops = {
	.llseek = notifyfs_file_llseek,
	.read = generic_read_dir,
	.readdir = notifyfs_readdir,
	.unlocked_ioctl = notifyfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = notifyfs_compat_ioctl,
#endif
	.open = notifyfs_open,
	.release = notifyfs_file_release,
	.flush = notifyfs_flush,
	.fsync = notifyfs_fsync,
	.fasync = notifyfs_fasync
};
