/*
 * Copyright (c) 2014-2015 Ricardo Padilha for Drobo Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef KERNEL_FS_NOTIFYFS_EVENTS_H_
#define KERNEL_FS_NOTIFYFS_EVENTS_H_

#ifndef __KERNEL__
#include <stdint.h>    // uint
#include <sys/types.h> // ino_t
#include <unistd.h>    // size_t
#endif

typedef uint64_t ino64_t;

/*
 * Version of the interface between
 * kernel and user land.
 */
#define NOTIFYFS_API_VERSION 1

/*
 * fs_event is a buffer containing:
 * - offset 0:                                struct fs_event_header
 * - offset sizeof(header):                   char[] path1 (old path in move)
 * - offset sizeof(header)+header->path_len1: char[] path2 (new path in moves, empty on other ops)
 *
 * Total length of fs_event: sizeof(header) + strlen(path1) + strlen(path2)
 */
typedef struct fs_event_header {
	uint64_t event_id;   /* event id, a monotonically increasing counter */
	uint32_t operation;  /* see FsOperationType */
	ino64_t  inode;      /* inode affected -- forced to 64 bit for better portability */
	time_t   mtime;      /* see timespec.tv_sec */
	long     mtime_ns;   /* see timespec.tv_nsec */
	pid_t    pid;        /* PID that caused the event */
	size_t   path_len1;  /* size of the string that follows the header */
	size_t   path_len2;  /* size of the string that follows the previous string */
} fs_event_header;

/*
 * This enum of operation types tries to replicate the values of
 * <linux/fsnotify_backend.h>. The values are not the same, but
 * the operations should overlap.
 */
typedef enum fs_operation_type {
	FS_UNSUPPORTED   = 0x00000000,	/* reserved for unsupported operations */

	FS_FILE_MASK     = 0x00000FFF,	/* all file events mask */
	FS_FILE_CREATE   = 0x00000001,	/* new file */
	FS_FILE_FLUSH    = 0x00000002,	/* flush file */
	FS_FILE_MOVE     = 0x00000004,	/* file moved or renamed */
	FS_FILE_DELETE   = 0x00000008,	/* file deleted */
	FS_FILE_OPEN     = 0x00000010,	/* file opened */
	FS_FILE_READ     = 0x00000020,	/* read access to file */
	FS_FILE_WRITE    = 0x00000040,	/* write access to file */
	FS_FILE_CLOSE    = 0x00000080,	/* file closed */
	FS_FILE_RATTRIB  = 0x00000100,	/* reading metadata (e.g. mtime) */
	FS_FILE_WATTRIB  = 0x00000200,	/* changing metadata (e.g. mtime) */
	FS_FILE_RXATTRIB = 0x00000400,	/* reading extended attributes */
	FS_FILE_WXATTRIB = 0x00000800,	/* changing extended attributes */

	FS_DIR_MASK      = 0x00FFF000,	/* all dir events mask */
	FS_DIR_CREATE    = 0x00001000,	/* new directory */
	FS_DIR_FLUSH     = 0x00002000,	/* flush dir */
	FS_DIR_MOVE      = 0x00004000,	/* directory moved or renamed */
	FS_DIR_DELETE    = 0x00008000,	/* directory deleted */
	FS_DIR_OPEN      = 0x00010000,	/* dir opened */
	FS_DIR_READ      = 0x00020000,	/* readdir */
	FS_DIR_WRITE     = 0x00040000,	/* unused / reserved */
	FS_DIR_CLOSE     = 0x00080000,	/* dir closed */
	FS_DIR_RATTRIB   = 0x00100000,	/* reading metadata (e.g. mtime) */
	FS_DIR_WATTRIB   = 0x00200000,	/* changing metadata (e.g. mtime) */
	FS_DIR_RXATTRIB  = 0x00400000,	/* reading extended attributes */
	FS_DIR_WXATTRIB  = 0x00800000,	/* changing extended attributes */

	FS_MNT_MASK      = 0x0F000000,	/* all mount events mask */
	FS_MNT_MOUNT     = 0x01000000,	/* new mount */
	FS_MNT_REMOUNT   = 0x02000000,	/* remounting fs -- currently unsupported */
	FS_MNT_MOVE      = 0x04000000,	/* moving the mount to another location -- currently unsupported */
	FS_MNT_UMOUNT    = 0x08000000,	/* unmount fs */
} fs_operation_type;

/* Default event mask captures all changes */
#define DEFAULT_EVENTS_MASK (FS_FILE_CREATE | FS_FILE_MOVE | FS_FILE_DELETE \
							| FS_FILE_WRITE | FS_FILE_WATTRIB | FS_FILE_WXATTRIB \
							| FS_DIR_CREATE | FS_DIR_MOVE | FS_DIR_DELETE \
							| FS_DIR_WATTRIB | FS_DIR_WXATTRIB \
							| FS_MNT_MOUNT | FS_MNT_UMOUNT);

/* Default lock mask captures all events */
#define DEFAULT_LOCKS_MASK (FS_FILE_MASK | FS_DIR_MASK);

typedef enum fs_fifo_block {
	NONBLOCKING_FIFO = 0,
	BLOCKING_FIFO    = 1
} fs_fifo_block;

/* Default FIFO mode */
#define DEFAULT_FIFO_BLOCK BLOCKING_FIFO

/* fifo size in bytes, this must be a power of 2 */
#define DEFAULT_FIFO_SIZE 65536;

/* support paths up to 1 KiB characters */
// up to 1024 characters in UTF-32
#define MAX_PATH_LENGTH 4096

/* maximum size of an FsEvent */
#define MAX_EVENT_SIZE (sizeof(fs_event_header) + 2 * MAX_PATH_LENGTH);


#endif /* KERNEL_FS_NOTIFYFS_EVENTS_H_ */
