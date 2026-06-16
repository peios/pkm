# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_SECURITY_PKM) += pkm.o

pkm-y := kacs/lsm.o kacs/access_check.o kacs/caap_cache.o kacs/token_fd.o \
	kmes/kmes.o lcs/key_fd.o lcs/transaction_fd.o lcs/rsi.o \
	lcs/source_device.o kacs/kacs_rust.o
pkm-$(CONFIG_SECURITY_PKM_KUNIT) += \
	kacs/kunit_common.o kacs/kunit_access.o kacs/kunit_token.o \
	kacs/kunit_file.o kacs/kunit_process.o kacs/kunit_signing.o \
	kacs/kunit_kmes.o kacs/kunit_misc.o \
	lcs/kunit_common.o lcs/kunit_key.o lcs/kunit_open.o \
	lcs/kunit_source.o lcs/kunit_transaction.o lcs/kunit_layer.o \
	lcs/kunit_rsi.o lcs/kunit_backup.o lcs/kunit_symlink.o \
	lcs/kunit_kmes.o lcs/kunit_misc.o

# Only explicit slow-track scaffolds live here today. New objects should be
# added deliberately as their implementation slices are opened.

# Tell kacs-core it's compiling for the kernel (switches alloc compat layer)
rustflags-y += --cfg 'feature="kernel"'
