NOTIFYFS_VERSION="0.6"

EXTRA_CFLAGS += -DNOTIFYFS_VERSION=\"$(NOTIFYFS_VERSION)\"

obj-$(CONFIG_NOTIFY_FS) += notifyfs.o

notifyfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o notifier.o array_list.o
