# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_STRATAFS_FS) += stratafs.o

stratafs-y := super.o lookup.o inode.o file.o dir.o xattr.o copy_up.o
stratafs-$(CONFIG_STRATAFS_KUNIT_TEST) += kunit.o
