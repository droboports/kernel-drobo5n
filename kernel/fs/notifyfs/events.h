/*
 * Copyright (c) 2014-2015 Ricardo Padilha for Drobo Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef KERNEL_FS_NOTIFYFS_EVENTS_H_
#define KERNEL_FS_NOTIFYFS_EVENTS_H_

/*
 * fs_event is a buffer containing:
 * - offset 0:                                struct fs_event_header
 * - offset sizeof(header):                   char[] path1 (old path in move)
 * - offset sizeof(header)+header->path_len1: char[] path2 (new path in moves, empty on other ops)
 *
 * Total length of fs_event: sizeof(header) + strlen(path1) + strlen(path2)
 */
typedef struct fs_event_header {
	u64    event_id;   /* event id, a monotonically increasing counter */
	u32    operation;  /* see FsOperationType */
	ino_t  inode;      /* inode affected */
	time_t time;       /* see timespec.tv_sec */
	long   time_ns;    /* see timespec.tv_nsec */
	pid_t  pid;        /* PID that caused the event */
	size_t path_len1;  /* size of the string that follows the header */
	size_t path_len2;  /* size of the string that follows the previous string */
} fs_event_header;

/*
 * This enum of operation types tries to replicate the values of
 * <linux/fsnotify_backend.h>. The values are not the same, but
 * the operations should overlap.
 */
typedef enum fs_operation_type {
	FS_UNSUPPORTED   = 0x00000000,	/* reserved for unsupported operations */

	FS_FILE_MASK     = 0x00001000,	/* all file events mask */
	FS_FILE_CREATE   = 0x00001001,	/* new file */
	FS_FILE_FLUSH    = 0x00001002,	/* flush file */
	FS_FILE_MOVE     = 0x00001004,	/* file moved or renamed */
	FS_FILE_DELETE   = 0x00001008,	/* file deleted */
	FS_FILE_OPEN     = 0x00001010,	/* file opened */
	FS_FILE_READ     = 0x00001020,	/* read access to file */
	FS_FILE_WRITE    = 0x00001040,	/* write access to file */
	FS_FILE_CLOSE    = 0x00001080,	/* file closed */
	FS_FILE_RATTRIB  = 0x00001100,	/* reading metadata (e.g. mtime) */
	FS_FILE_WATTRIB  = 0x00001200,	/* changing metadata (e.g. mtime) */
	FS_FILE_RXATTRIB = 0x00001400,	/* reading extended attributes */
	FS_FILE_WXATTRIB = 0x00001800,	/* changing extended attributes */

	FS_DIR_MASK      = 0x00002000,	/* all dir events mask */
	FS_DIR_CREATE    = 0x00002001,	/* new directory */
	FS_DIR_FLUSH     = 0x00002002,	/* flush dir */
	FS_DIR_MOVE      = 0x00002004,	/* directory moved or renamed */
	FS_DIR_DELETE    = 0x00002008,	/* directory deleted */
	FS_DIR_OPEN      = 0x00002010,	/* dir opened */
	FS_DIR_READ      = 0x00002020,	/* readdir */
	FS_DIR_WRITE     = 0x00002040,	/* unused / reserved */
	FS_DIR_CLOSE     = 0x00002080,	/* dir closed */
	FS_DIR_RATTRIB   = 0x00002100,	/* reading metadata (e.g. mtime) */
	FS_DIR_WATTRIB   = 0x00002200,	/* changing metadata (e.g. mtime) */
	FS_DIR_RXATTRIB  = 0x00002400,	/* reading extended attributes */
	FS_DIR_WXATTRIB  = 0x00002800	/* changing extended attributes */
} fs_operation_type;

/* Default event mask captures all changes */
#define DEFAULT_EVENTS_MASK (FS_FILE_CREATE | FS_FILE_MOVE | FS_FILE_DELETE \
							| FS_FILE_WRITE | FS_FILE_WATTRIB | FS_FILE_WXATTRIB \
							| FS_DIR_CREATE | FS_DIR_MOVE | FS_DIR_DELETE \
							| FS_DIR_WATTRIB | FS_DIR_WXATTRIB);

/* Default lock mask captures all events */
#define DEFAULT_LOCKS_MASK (FS_FILE_MASK | FS_DIR_MASK);

typedef enum fs_fifo_block {
	NONBLOCKING_FIFO = 0,
	BLOCKING_FIFO    = 1
} fs_fifo_block;

/* Default FIFO mode */
#define DEFAULT_FIFO_BLOCK BLOCKING_FIFO

/* fifo size in bytes, this must be a power of 2 */
#define DEFAULT_FIFO_SIZE 4096;

/* support paths up to 1 KiB characters */
// up to 1024 characters in UTF-32
#define MAX_PATH_LENGTH 4096

/* maximum size of an FsEvent */
#define MAX_EVENT_SIZE (sizeof(fs_event_header) + 2 * MAX_PATH_LENGTH);


#endif /* KERNEL_FS_NOTIFYFS_EVENTS_H_ */
