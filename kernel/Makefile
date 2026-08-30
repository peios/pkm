# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_SECURITY_PKM) += pkm.o

pkm-y := kacs/lsm.o kacs/pkm_trace.o kacs/securityfs.o kacs/kmes_rate.o kacs/tlp.o \
	kacs/capability.o kacs/cred_lifecycle.o kacs/cred_projection.o \
	kacs/file_sd_cache.o kacs/signing.o kacs/firmware.o kacs/process_sd.o kacs/process_access.o \
	kacs/primary_token.o kacs/process_state.o kacs/process_token.o kacs/runtime.o kacs/socket.o kacs/ipc.o \
	kacs/exec.o kacs/psb.o kacs/object_lifecycle.o kacs/file_access.o \
	kacs/file_metadata.o kacs/mount_policy.o kacs/namespace.o kacs/sd_access.o \
	kacs/access_check.o kacs/native_open.o kacs/copy_up.o \
	kacs/caap_cache.o kacs/task_lifecycle.o kacs/token_fd.o kacs/token_logon_session.o \
	kacs/port_reservations.o \
	kmes/kmes.o lcs/key_fd.o lcs/transaction_fd.o lcs/rsi.o \
	lcs/access_planning.o lcs/audit.o lcs/runtime_limits.o lcs/self_config.o \
	lcs/layer_metadata.o lcs/layer_table.o lcs/path_materialization.o \
	lcs/path_walk.o lcs/source_auth.o lcs/source_bootstrap.o \
	lcs/source_create.o lcs/source_dispatch.o lcs/source_late_effect.o \
	lcs/source_layer_operation.o lcs/source_open.o \
	lcs/source_protocol.o lcs/source_registration.o lcs/source_request.o \
	lcs/source_response.o lcs/source_response_plan.o lcs/source_routing.o \
	lcs/source_table.o \
	lcs/source_symlink.o lcs/source_device.o lcs/syscall_inputs.o \
	kacs/kacs_rust.o
pkm-$(CONFIG_SECURITY_PKM_KUNIT) += \
	kacs/kunit_support.o kacs/kunit_common.o kacs/kunit_access.o kacs/kunit_token.o \
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
