# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_SECURITY_KACS) += kacs.o
kacs-y := lsm.o kacs_rust.o

# Tell kacs-core it's compiling for the kernel (switches alloc compat layer)
rustflags-y += --cfg 'feature="kernel"'
