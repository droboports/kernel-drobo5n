/*
 * Copyright (c) 2014-2015 Ricardo Padilha, Drobo Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _NOTIFIER_H_
#define _NOTIFIER_H_

/* notifyfs_d_path requires get_fs_root */
#include <linux/fs_struct.h>

//const unsigned int ExpectedSignature = 0x79647899;

/* Duplicate of FsOpTypes.h */
typedef enum _FsOperationType {
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

/* Duplicate of FrontEndMonitor.h */
typedef enum _MsgOriginator {
	Originator_API,
	Originator_SAMBA,
	Originator_Replication,
	Originator_LastCode
} MsgOriginator;

/* Duplicate of definition in FrontEndMonitor.h */
typedef struct _UserIOEventHeader {
	unsigned int signature;
	unsigned int numPacketsInMsg;
	unsigned int timeOfChange;
	unsigned int timeOfChange_ns;
	FsOperationType typeOfChange;
	MsgOriginator originator; // User change or replication engine?
	ino_t inode;
	unsigned int pathLen1;
	unsigned int pathLen2;
	unsigned char peerUUID[12];
	unsigned char userUUID[12];
} UserIOEventHeader;

int send_file_event(const FsOperationType opType, const struct file *fileFrom);

int send_dentry_event(const FsOperationType opType, struct dentry *dentryFrom);

int send_dentry_rename(const FsOperationType opType, struct dentry *dentryFrom, const char *oldPath);

#endif	/* not _NOTIFIER_H_ */
