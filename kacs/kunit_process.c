// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_kunit_capget_reports_allow_substrate(struct kunit *test)
{
	u64 allow_mask;
	u64 effective_out = 0;
	u64 inheritable_out = 0;
	u64 permitted_out = 0;

	allow_mask = pkm_kacs_kunit_allow_cap_mask();
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_capget_fixup_masks(
				0ULL, 0ULL, 0ULL, &effective_out,
				&inheritable_out, &permitted_out),
			0L);
	KUNIT_EXPECT_EQ(test, effective_out, allow_mask);
	KUNIT_EXPECT_EQ(test, inheritable_out, allow_mask);
	KUNIT_EXPECT_EQ(test, permitted_out, allow_mask);
}


static void pkm_kunit_capget_preserves_non_allow_compat_bits(
	struct kunit *test)
{
	u64 allow_mask;
	u64 effective_in;
	u64 inheritable_in;
	u64 permitted_in;
	u64 effective_out = 0;
	u64 inheritable_out = 0;
	u64 permitted_out = 0;

	allow_mask = pkm_kacs_kunit_allow_cap_mask();
	effective_in = 1ULL << CAP_SYS_BOOT;
	inheritable_in = 1ULL << CAP_SYS_TIME;
	permitted_in = 1ULL << CAP_PERFMON;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_capget_fixup_masks(
				effective_in, inheritable_in, permitted_in,
				&effective_out, &inheritable_out,
				&permitted_out),
			0L);
	KUNIT_EXPECT_EQ(test, effective_out, allow_mask | effective_in);
	KUNIT_EXPECT_EQ(test, inheritable_out, allow_mask | inheritable_in);
	KUNIT_EXPECT_EQ(test, permitted_out, allow_mask | permitted_in);
}


static void pkm_kunit_capget_cross_process_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_capget_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	ret = pkm_kacs_kunit_check_capget_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_capget_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_capget_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	ret = pkm_kacs_kunit_check_capget_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_capget_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_capget_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	ret = pkm_kacs_kunit_check_capget_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_capget_debug_still_fails_on_pip(struct kunit *test)
{
	struct pkm_kacs_kunit_process_capget_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;

	ret = pkm_kacs_kunit_check_capget_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_capget_self_target_bypasses_boundary_gate(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_capget_check_args args = {
		.self_target = 1U,
	};

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_capget_for_subject(&args),
			0L);
}


static void pkm_kunit_capget_null_args_fail_closed(struct kunit *test)
{
	u64 effective_out = 0;
	u64 inheritable_out = 0;
	u64 permitted_out = 0;

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_capget_for_subject(NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_capget_fixup_masks(
				0ULL, 0ULL, 0ULL, NULL, &inheritable_out,
				&permitted_out),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_capget_fixup_masks(
				0ULL, 0ULL, 0ULL, &effective_out, NULL,
				&permitted_out),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_capget_fixup_masks(
				0ULL, 0ULL, 0ULL, &effective_out,
				&inheritable_out, NULL),
			(long)-EINVAL);
}


static void pkm_kunit_proc_status_caps_report_allow_substrate(
	struct kunit *test)
{
	u64 allow_mask;
	u64 inheritable_out = 0;
	u64 permitted_out = 0;
	u64 effective_out = 0;
	u64 bset_out = 0;
	u64 ambient_out = ~0ULL;

	allow_mask = pkm_kacs_kunit_allow_cap_mask();
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_proc_status_cap_fixup_masks(
				0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
				&inheritable_out, &permitted_out,
				&effective_out, &bset_out, &ambient_out),
			0L);
	KUNIT_EXPECT_EQ(test, inheritable_out, allow_mask);
	KUNIT_EXPECT_EQ(test, permitted_out, allow_mask);
	KUNIT_EXPECT_EQ(test, effective_out, allow_mask);
	KUNIT_EXPECT_EQ(test, bset_out, allow_mask);
	KUNIT_EXPECT_EQ(test, ambient_out, 0ULL);
}


static void pkm_kunit_proc_status_caps_preserve_non_allow_and_ambient(
	struct kunit *test)
{
	u64 allow_mask;
	u64 inheritable_in;
	u64 permitted_in;
	u64 effective_in;
	u64 bset_in;
	u64 ambient_in;
	u64 inheritable_out = 0;
	u64 permitted_out = 0;
	u64 effective_out = 0;
	u64 bset_out = 0;
	u64 ambient_out = 0;

	allow_mask = pkm_kacs_kunit_allow_cap_mask();
	inheritable_in = 1ULL << CAP_SYS_BOOT;
	permitted_in = 1ULL << CAP_SYS_TIME;
	effective_in = 1ULL << CAP_PERFMON;
	bset_in = 1ULL << CAP_SYS_ADMIN;
	ambient_in = 1ULL << CAP_SYS_NICE;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_proc_status_cap_fixup_masks(
				inheritable_in, permitted_in, effective_in,
				bset_in, ambient_in, &inheritable_out,
				&permitted_out, &effective_out, &bset_out,
				&ambient_out),
			0L);
	KUNIT_EXPECT_EQ(test, inheritable_out, allow_mask | inheritable_in);
	KUNIT_EXPECT_EQ(test, permitted_out, allow_mask | permitted_in);
	KUNIT_EXPECT_EQ(test, effective_out, allow_mask | effective_in);
	KUNIT_EXPECT_EQ(test, bset_out, allow_mask | bset_in);
	KUNIT_EXPECT_EQ(test, ambient_out, ambient_in);
}


static void pkm_kunit_proc_status_caps_null_args_fail_closed(
	struct kunit *test)
{
	u64 inheritable_out = 0;
	u64 permitted_out = 0;
	u64 effective_out = 0;
	u64 bset_out = 0;
	u64 ambient_out = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_proc_status_cap_fixup_masks(
				0ULL, 0ULL, 0ULL, 0ULL, 0ULL, NULL,
				&permitted_out, &effective_out, &bset_out,
				&ambient_out),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_proc_status_cap_fixup_masks(
				0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
				&inheritable_out, NULL, &effective_out,
				&bset_out, &ambient_out),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_proc_status_cap_fixup_masks(
				0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
				&inheritable_out, &permitted_out, NULL,
				&bset_out, &ambient_out),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_proc_status_cap_fixup_masks(
				0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
				&inheritable_out, &permitted_out,
				&effective_out, NULL, &ambient_out),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_proc_status_cap_fixup_masks(
				0ULL, 0ULL, 0ULL, 0ULL, 0ULL,
				&inheritable_out, &permitted_out,
				&effective_out, &bset_out, NULL),
			(long)-EINVAL);
}


static void pkm_kunit_capability_allow_succeeds_without_privilege(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &before));

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capability_for_subject(token,
								     CAP_CHOWN),
			0L);

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_capability_privilege_success_marks_used(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		PKM_KUNIT_SE_SHUTDOWN_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &before));

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capability_for_subject(
				token, CAP_SYS_BOOT),
			0L);

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_SHUTDOWN_PRIVILEGE);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_remote_shutdown_denies_without_remote_privilege(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };

	token = kacs_rust_kunit_create_logon_type_token(
		PKM_KUNIT_LOGON_TYPE_NETWORK,
		PKM_KUNIT_SE_SHUTDOWN_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &before));
	KUNIT_ASSERT_EQ(test, before.logon_type,
			(u32)PKM_KUNIT_LOGON_TYPE_NETWORK);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capability_for_subject(
				token, CAP_SYS_BOOT),
			(long)-EPERM);

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_remote_shutdown_denies_without_shutdown_privilege(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };

	token = kacs_rust_kunit_create_logon_type_token(
		PKM_KUNIT_LOGON_TYPE_NETWORK,
		PKM_KUNIT_SE_REMOTE_SHUTDOWN_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &before));
	KUNIT_ASSERT_EQ(test, before.logon_type,
			(u32)PKM_KUNIT_LOGON_TYPE_NETWORK);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capability_for_subject(
				token, CAP_SYS_BOOT),
			(long)-EPERM);

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_remote_shutdown_success_requires_both_privileges(
	struct kunit *test)
{
	static const u32 remote_logon_types[] = {
		PKM_KUNIT_LOGON_TYPE_NETWORK,
		PKM_KUNIT_LOGON_TYPE_NETWORK_CLEARTEXT,
		PKM_KUNIT_LOGON_TYPE_NEW_CREDENTIALS,
	};
	const u64 privileges = PKM_KUNIT_SE_SHUTDOWN_PRIVILEGE |
			       PKM_KUNIT_SE_REMOTE_SHUTDOWN_PRIVILEGE;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(remote_logon_types); i++) {
		const void *token;
		struct pkm_kacs_boot_snapshot before = { };
		struct pkm_kacs_boot_snapshot after = { };

		token = kacs_rust_kunit_create_logon_type_token(
			remote_logon_types[i], privileges);
		KUNIT_ASSERT_NOT_NULL(test, token);
		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(token,
								 &before));
		KUNIT_ASSERT_EQ(test, before.logon_type, remote_logon_types[i]);

		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_check_capability_for_subject(
					token, CAP_SYS_BOOT),
				0L);

		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(token, &after));
		KUNIT_EXPECT_EQ(test, after.privileges_used,
				before.privileges_used | privileges);
		kacs_rust_token_drop(token);
	}
}


static void pkm_kunit_capability_privilege_mapping_matrix(struct kunit *test)
{
	static const struct {
		int cap;
		u64 privilege;
	} cases[] = {
		{ CAP_LINUX_IMMUTABLE, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_NET_ADMIN, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_NET_RAW, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_SYS_RAWIO, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_SYS_CHROOT, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_SYS_PACCT, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_SYS_ADMIN, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_SYS_TTY_CONFIG, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_MKNOD, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_SYSLOG, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_WAKE_ALARM, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_BLOCK_SUSPEND, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_BPF, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_CHECKPOINT_RESTORE, PKM_KUNIT_SE_TCB_PRIVILEGE },
		{ CAP_NET_BIND_SERVICE,
		  PKM_KUNIT_SE_BIND_PRIVILEGED_PORT_PRIVILEGE },
		{ CAP_IPC_LOCK, PKM_KUNIT_SE_LOCK_MEMORY_PRIVILEGE },
		{ CAP_SYS_MODULE, PKM_KUNIT_SE_LOAD_DRIVER_PRIVILEGE },
		{ CAP_SYS_PTRACE, PKM_KUNIT_SE_DEBUG_PRIVILEGE },
		{ CAP_SYS_BOOT, PKM_KUNIT_SE_SHUTDOWN_PRIVILEGE },
		{ CAP_SYS_NICE,
		  PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE },
		{ CAP_SYS_RESOURCE, PKM_KUNIT_SE_INCREASE_QUOTA_PRIVILEGE },
		{ CAP_SYS_TIME, PKM_KUNIT_SE_SYSTEMTIME_PRIVILEGE },
		{ CAP_AUDIT_WRITE, PKM_KUNIT_SE_AUDIT_PRIVILEGE },
		{ CAP_AUDIT_CONTROL, PKM_KUNIT_SE_SECURITY_PRIVILEGE },
		{ CAP_MAC_ADMIN, PKM_KUNIT_SE_SECURITY_PRIVILEGE },
		{ CAP_AUDIT_READ, PKM_KUNIT_SE_SECURITY_PRIVILEGE },
		{ CAP_PERFMON, PKM_KUNIT_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE },
	};
	u32 i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		const void *token;
		struct pkm_kacs_boot_snapshot before = { };
		struct pkm_kacs_boot_snapshot after = { };

		token = kacs_rust_kunit_create_impersonation_variant_token(
			PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U,
			PKM_KUNIT_IL_SYSTEM, 0U, cases[i].privilege);
		KUNIT_ASSERT_NOT_NULL(test, token);
		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(token,
								 &before));

		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_check_capability_for_subject(
					token, cases[i].cap),
				0L);

		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(token, &after));
		KUNIT_EXPECT_EQ(test, after.privileges_used,
				before.privileges_used | cases[i].privilege);
		kacs_rust_token_drop(token);
	}
}


static void pkm_kunit_capability_switchboard_full_matrix(struct kunit *test)
{
	static const enum {
		PKM_KUNIT_CAP_ALLOW,
		PKM_KUNIT_CAP_PRIVILEGE,
		PKM_KUNIT_CAP_DENY,
	} expected[CAP_LAST_CAP + 1] = {
		[CAP_CHOWN] = PKM_KUNIT_CAP_ALLOW,
		[CAP_DAC_OVERRIDE] = PKM_KUNIT_CAP_ALLOW,
		[CAP_DAC_READ_SEARCH] = PKM_KUNIT_CAP_ALLOW,
		[CAP_FOWNER] = PKM_KUNIT_CAP_ALLOW,
		[CAP_FSETID] = PKM_KUNIT_CAP_ALLOW,
		[CAP_KILL] = PKM_KUNIT_CAP_ALLOW,
		[CAP_SETGID] = PKM_KUNIT_CAP_ALLOW,
		[CAP_SETUID] = PKM_KUNIT_CAP_ALLOW,
		[CAP_SETPCAP] = PKM_KUNIT_CAP_DENY,
		[CAP_LINUX_IMMUTABLE] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_NET_BIND_SERVICE] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_NET_BROADCAST] = PKM_KUNIT_CAP_ALLOW,
		[CAP_NET_ADMIN] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_NET_RAW] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_IPC_LOCK] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_IPC_OWNER] = PKM_KUNIT_CAP_ALLOW,
		[CAP_SYS_MODULE] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_SYS_RAWIO] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_SYS_CHROOT] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_SYS_PTRACE] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_SYS_PACCT] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_SYS_ADMIN] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_SYS_BOOT] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_SYS_NICE] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_SYS_RESOURCE] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_SYS_TIME] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_SYS_TTY_CONFIG] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_MKNOD] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_LEASE] = PKM_KUNIT_CAP_ALLOW,
		[CAP_AUDIT_WRITE] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_AUDIT_CONTROL] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_SETFCAP] = PKM_KUNIT_CAP_DENY,
		[CAP_MAC_OVERRIDE] = PKM_KUNIT_CAP_DENY,
		[CAP_MAC_ADMIN] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_SYSLOG] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_WAKE_ALARM] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_BLOCK_SUSPEND] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_AUDIT_READ] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_PERFMON] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_BPF] = PKM_KUNIT_CAP_PRIVILEGE,
		[CAP_CHECKPOINT_RESTORE] = PKM_KUNIT_CAP_PRIVILEGE,
	};
	const void *token;
	int cap;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		PKM_KUNIT_SYSTEM_PRIVILEGES_ALL);
	KUNIT_ASSERT_NOT_NULL(test, token);

	for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
		long ret;

		ret = pkm_kacs_kunit_check_capability_for_subject(token, cap);
		if (expected[cap] == PKM_KUNIT_CAP_DENY)
			KUNIT_EXPECT_EQ(test, ret, (long)-EPERM);
		else
			KUNIT_EXPECT_EQ(test, ret, 0L);
	}

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capability_for_subject(token, -1),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capability_for_subject(
				token, CAP_LAST_CAP + 1),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capability_for_subject(
				token, CAP_LAST_CAP + 32),
			(long)-EINVAL);

	kacs_rust_token_drop(token);
}


static void pkm_kunit_capability_privilege_denied_without_privilege(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &before));

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capability_for_subject(
				token, CAP_SYS_BOOT),
			(long)-EPERM);

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_capability_denied_caps_fail_closed(struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		PKM_KUNIT_SYSTEM_PRIVILEGES_ALL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &before));

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capability_for_subject(
				token, CAP_SETPCAP),
			(long)-EPERM);

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_capability_deny_caps_matrix(struct kunit *test)
{
	static const int denied_caps[] = {
		CAP_SETPCAP,
		CAP_SETFCAP,
		CAP_MAC_OVERRIDE,
	};
	const void *token;
	u32 i;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		PKM_KUNIT_SYSTEM_PRIVILEGES_ALL);
	KUNIT_ASSERT_NOT_NULL(test, token);

	for (i = 0; i < ARRAY_SIZE(denied_caps); i++) {
		struct pkm_kacs_boot_snapshot before = { };
		struct pkm_kacs_boot_snapshot after = { };

		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(token,
								 &before));
		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_check_capability_for_subject(
					token, denied_caps[i]),
				(long)-EPERM);
		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(token,
								 &after));
		KUNIT_EXPECT_EQ(test, after.privileges_used,
				before.privileges_used);
	}

	kacs_rust_token_drop(token);
}


static void pkm_kunit_capset_preserves_allow_and_rejects_clear(
	struct kunit *test)
{
	const void *token;
	u64 allow_mask;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	allow_mask = pkm_kacs_kunit_allow_cap_mask();

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capset_for_subject(
				token, allow_mask | (1ULL << CAP_SYS_BOOT),
				allow_mask | (1ULL << CAP_SYS_BOOT),
				allow_mask | (1ULL << CAP_SYS_BOOT)),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capset_for_subject(
				token,
				allow_mask & ~(1ULL << CAP_CHOWN),
				allow_mask, allow_mask),
			(long)-EPERM);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_capset_rejects_each_allow_clear(struct kunit *test)
{
	const void *token;
	u64 allow_mask;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	allow_mask = pkm_kacs_kunit_allow_cap_mask();

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capset_for_subject(
				token, allow_mask & ~(1ULL << CAP_CHOWN),
				allow_mask, allow_mask),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capset_for_subject(
				token, allow_mask,
				allow_mask & ~(1ULL << CAP_CHOWN),
				allow_mask),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capset_for_subject(
				token, allow_mask, allow_mask,
				allow_mask & ~(1ULL << CAP_CHOWN)),
			(long)-EPERM);

	kacs_rust_token_drop(token);
}


static void pkm_kunit_capset_preserves_non_allow_and_repairs_bset(
	struct kunit *test)
{
	const void *token;
	u64 allow_mask;
	u64 effective_in;
	u64 inheritable_in;
	u64 permitted_in;
	u64 bset_in;
	u64 effective_out = 0;
	u64 inheritable_out = 0;
	u64 permitted_out = 0;
	u64 bset_out = 0;
	u64 ambient_out = 0;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	allow_mask = pkm_kacs_kunit_allow_cap_mask();
	effective_in = allow_mask | (1ULL << CAP_SYS_BOOT);
	inheritable_in = allow_mask | (1ULL << CAP_SYS_TIME);
	permitted_in = effective_in | (1ULL << CAP_PERFMON);
	bset_in = 1ULL << CAP_SYS_ADMIN;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_capset_result_masks(
				token, effective_in, inheritable_in,
				permitted_in, bset_in, 0ULL, &effective_out,
				&inheritable_out, &permitted_out, &bset_out,
				&ambient_out),
			0L);
	KUNIT_EXPECT_EQ(test, effective_out, effective_in);
	KUNIT_EXPECT_EQ(test, inheritable_out, inheritable_in);
	KUNIT_EXPECT_EQ(test, permitted_out, permitted_in);
	KUNIT_EXPECT_EQ(test, bset_out, allow_mask | bset_in);
	KUNIT_EXPECT_EQ(test, ambient_out, 0ULL);

	kacs_rust_token_drop(token);
}


static void pkm_kunit_capset_masks_ambient_to_permitted_inheritable(
	struct kunit *test)
{
	const void *token;
	u64 allow_mask;
	u64 requested;
	u64 ambient_in;
	u64 effective_out = 0;
	u64 inheritable_out = 0;
	u64 permitted_out = 0;
	u64 bset_out = 0;
	u64 ambient_out = 0;
	u64 expected_ambient;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	allow_mask = pkm_kacs_kunit_allow_cap_mask();
	requested = allow_mask | (1ULL << CAP_SYS_BOOT);
	ambient_in = (1ULL << CAP_CHOWN) | (1ULL << CAP_SYS_BOOT) |
		     (1ULL << CAP_SYS_TIME);
	expected_ambient = (1ULL << CAP_CHOWN) | (1ULL << CAP_SYS_BOOT);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_capset_result_masks(
				token, requested, requested, requested,
				allow_mask, ambient_in, &effective_out,
				&inheritable_out, &permitted_out, &bset_out,
				&ambient_out),
			0L);
	KUNIT_EXPECT_EQ(test, effective_out, requested);
	KUNIT_EXPECT_EQ(test, inheritable_out, requested);
	KUNIT_EXPECT_EQ(test, permitted_out, requested);
	KUNIT_EXPECT_EQ(test, bset_out, allow_mask);
	KUNIT_EXPECT_EQ(test, ambient_out, expected_ambient);

	kacs_rust_token_drop(token);
}


static void pkm_kunit_capset_null_and_tokenless_fail_closed(struct kunit *test)
{
	u64 allow_mask;
	const void *token;
	u64 effective_out = 0;
	u64 inheritable_out = 0;
	u64 permitted_out = 0;
	u64 bset_out = 0;
	u64 ambient_out = 0;

	allow_mask = pkm_kacs_kunit_allow_cap_mask();
	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capset_for_subject(
				NULL, allow_mask, allow_mask, allow_mask),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_capset_result_masks(
				NULL, allow_mask, allow_mask, allow_mask,
				allow_mask, 0ULL, &effective_out,
				&inheritable_out, &permitted_out, &bset_out,
				&ambient_out),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_capset_result_masks(
				token, allow_mask, allow_mask, allow_mask,
				allow_mask, 0ULL, NULL, &inheritable_out,
				&permitted_out, &bset_out, &ambient_out),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_capset_result_masks(
				token, allow_mask, allow_mask, allow_mask,
				allow_mask, 0ULL, &effective_out, NULL,
				&permitted_out, &bset_out, &ambient_out),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_capset_result_masks(
				token, allow_mask, allow_mask, allow_mask,
				allow_mask, 0ULL, &effective_out,
				&inheritable_out, NULL, &bset_out,
				&ambient_out),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_capset_result_masks(
				token, allow_mask, allow_mask, allow_mask,
				allow_mask, 0ULL, &effective_out,
				&inheritable_out, &permitted_out, NULL,
				&ambient_out),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_capset_result_masks(
				token, allow_mask, allow_mask, allow_mask,
				allow_mask, 0ULL, &effective_out,
				&inheritable_out, &permitted_out, &bset_out,
				NULL),
			(long)-EINVAL);

	kacs_rust_token_drop(token);
}


static void pkm_kunit_prctl_capability_guard_rejects_allow_mutations(
	struct kunit *test)
{
	const void *token;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prctl_capability_guard_for_subject(
				token, 0ULL, PR_CAPBSET_DROP, CAP_CHOWN, 0, 0,
				0),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prctl_capability_guard_for_subject(
				token, 1ULL << CAP_CHOWN, PR_CAP_AMBIENT,
				PR_CAP_AMBIENT_LOWER, CAP_CHOWN, 0, 0),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prctl_capability_guard_for_subject(
				token, 1ULL << CAP_SYS_BOOT, PR_CAP_AMBIENT,
				PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0),
			0L);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_prctl_capability_guard_rejects_each_allow(
	struct kunit *test)
{
	static const int allow_caps[] = {
		CAP_CHOWN,
		CAP_DAC_OVERRIDE,
		CAP_DAC_READ_SEARCH,
		CAP_FOWNER,
		CAP_FSETID,
		CAP_KILL,
		CAP_SETGID,
		CAP_SETUID,
		CAP_NET_BROADCAST,
		CAP_IPC_OWNER,
		CAP_LEASE,
	};
	const void *token;
	u32 i;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, 1U, 0U, PKM_KUNIT_IL_SYSTEM, 0U,
		0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);

	for (i = 0; i < ARRAY_SIZE(allow_caps); i++) {
		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_check_prctl_capability_guard_for_subject(
					token, 0ULL, PR_CAPBSET_DROP,
					allow_caps[i], 0, 0, 0),
				(long)-EPERM);
		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_check_prctl_capability_guard_for_subject(
					token, 1ULL << allow_caps[i],
					PR_CAP_AMBIENT,
					PR_CAP_AMBIENT_LOWER,
					allow_caps[i], 0, 0),
				(long)-EPERM);
		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_check_prctl_capability_guard_for_subject(
					token, 0ULL, PR_CAP_AMBIENT,
					PR_CAP_AMBIENT_RAISE,
					allow_caps[i], 0, 0),
				(long)-EPERM);
	}

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prctl_capability_guard_for_subject(
				token, pkm_kacs_kunit_allow_cap_mask(),
				PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL,
				0, 0, 0),
			(long)-EPERM);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_exec_cap_reprojection_suppresses_filecap_grants(
	struct kunit *test)
{
	u64 allow_mask;
	u64 effective_out = 0;
	u64 inheritable_out = 0;
	u64 permitted_out = 0;
	u64 ambient_out = 0;

	allow_mask = pkm_kacs_kunit_allow_cap_mask();
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_reproject_exec_caps(
				allow_mask | (1ULL << CAP_SYS_BOOT),
				allow_mask | (1ULL << CAP_SYS_BOOT),
				allow_mask | (1ULL << CAP_SYS_BOOT),
				1ULL << CAP_SYS_BOOT, &effective_out,
				&inheritable_out, &permitted_out,
				&ambient_out),
			0);
	KUNIT_EXPECT_EQ(test, effective_out, allow_mask);
	KUNIT_EXPECT_EQ(test, inheritable_out, allow_mask);
	KUNIT_EXPECT_EQ(test, permitted_out, allow_mask);
	KUNIT_EXPECT_EQ(test, ambient_out, 0ULL);
}


static void pkm_kunit_setuid_fixup_suppresses_unprivileged_change(
	struct kunit *test)
{
	const void *token;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_setuid_fixup_for_subject(
				token, LSM_SETID_RES),
			0L);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_setuid_fixup_privileged_path_fails_closed(
	struct kunit *test)
{
	const void *token;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_setuid_fixup_for_subject(
				token, LSM_SETID_RES),
			(long)-EOPNOTSUPP);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_setuid_fixup_unknown_flags_fail_closed(
	struct kunit *test)
{
	const void *token;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_setuid_fixup_for_subject(token,
								      99),
			(long)-EINVAL);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_setgid_fixup_suppresses_unprivileged_change(
	struct kunit *test)
{
	const void *token;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_setgid_fixup_for_subject(
				token, LSM_SETID_RES),
			0L);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_setgroups_fixup_suppresses_unprivileged_change(
	struct kunit *test)
{
	const void *token;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_setgroups_fixup_for_subject(token),
			0L);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_peercred_projection_uses_token_ids(struct kunit *test)
{
	const void *token;
	u32 uid = 0;
	u32 gid = 0;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_project_peer_cred_for_subject(
				token, 0U, 0U, &uid, &gid),
			0);
	KUNIT_EXPECT_EQ(test, uid, 65534U);
	KUNIT_EXPECT_EQ(test, gid, 65534U);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_project_peer_cred_for_subject(
				NULL, 4242U, 4343U, &uid, &gid),
			0);
	KUNIT_EXPECT_EQ(test, uid, 4242U);
	KUNIT_EXPECT_EQ(test, gid, 4343U);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_exec_setid_uid_compat_rewrites_visible_uid_only(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kacs_kunit_exec_setid_view view = { };

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &before));

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_check_exec_setid_compat_for_subject(
				token, PKM_KUNIT_EXEC_SETID_UID, &view),
			0L);

	KUNIT_EXPECT_EQ(test, view.uid, 5000U);
	KUNIT_EXPECT_EQ(test, view.euid, 5000U);
	KUNIT_EXPECT_EQ(test, view.suid, 5000U);
	KUNIT_EXPECT_EQ(test, view.fsuid, 3234U);
	KUNIT_EXPECT_EQ(test, view.gid, 2234U);
	KUNIT_EXPECT_EQ(test, view.egid, 2234U);
	KUNIT_EXPECT_EQ(test, view.sgid, 2234U);
	KUNIT_EXPECT_EQ(test, view.fsgid, 4234U);
	KUNIT_EXPECT_EQ(test, view.projected_fsuid, before.projected_uid);
	KUNIT_EXPECT_EQ(test, view.projected_fsgid, before.projected_gid);

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.token_id, before.token_id);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id);
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_exec_setid_gid_compat_rewrites_visible_gid_only(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kacs_kunit_exec_setid_view view = { };

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &before));

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_check_exec_setid_compat_for_subject(
				token, PKM_KUNIT_EXEC_SETID_GID, &view),
			0L);

	KUNIT_EXPECT_EQ(test, view.uid, 1234U);
	KUNIT_EXPECT_EQ(test, view.euid, 1234U);
	KUNIT_EXPECT_EQ(test, view.suid, 1234U);
	KUNIT_EXPECT_EQ(test, view.fsuid, 3234U);
	KUNIT_EXPECT_EQ(test, view.gid, 6000U);
	KUNIT_EXPECT_EQ(test, view.egid, 6000U);
	KUNIT_EXPECT_EQ(test, view.sgid, 6000U);
	KUNIT_EXPECT_EQ(test, view.fsgid, 4234U);
	KUNIT_EXPECT_EQ(test, view.projected_fsuid, before.projected_uid);
	KUNIT_EXPECT_EQ(test, view.projected_fsgid, before.projected_gid);

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.token_id, before.token_id);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id);
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_exec_setid_compat_rewrites_visible_uid_and_gid_only(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kacs_kunit_exec_setid_view view = { };

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &before));

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_check_exec_setid_compat_for_subject(
				token,
				PKM_KUNIT_EXEC_SETID_UID |
					PKM_KUNIT_EXEC_SETID_GID,
				&view),
			0L);

	KUNIT_EXPECT_EQ(test, view.uid, 5000U);
	KUNIT_EXPECT_EQ(test, view.euid, 5000U);
	KUNIT_EXPECT_EQ(test, view.suid, 5000U);
	KUNIT_EXPECT_EQ(test, view.fsuid, 3234U);
	KUNIT_EXPECT_EQ(test, view.gid, 6000U);
	KUNIT_EXPECT_EQ(test, view.egid, 6000U);
	KUNIT_EXPECT_EQ(test, view.sgid, 6000U);
	KUNIT_EXPECT_EQ(test, view.fsgid, 4234U);
	KUNIT_EXPECT_EQ(test, view.projected_fsuid, before.projected_uid);
	KUNIT_EXPECT_EQ(test, view.projected_fsgid, before.projected_gid);

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.token_id, before.token_id);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id);
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_exec_setid_without_token_fails_closed(struct kunit *test)
{
	struct pkm_kacs_kunit_exec_setid_view view = { };

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_exec_setid_compat_for_subject(
				NULL, PKM_KUNIT_EXEC_SETID_UID, &view),
			(long)-EACCES);
}


static void pkm_kunit_exec_setid_privileged_path_fails_closed(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_kunit_exec_setid_view view = { };

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_exec_setid_compat_for_subject(
				token,
				PKM_KUNIT_EXEC_SETID_UID |
					PKM_KUNIT_EXEC_SETID_GID,
				&view),
			(long)-EOPNOTSUPP);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_exec_new_process_min_lowers_to_file_label(
	struct kunit *test)
{
	struct pkm_kacs_kunit_exec_new_process_min_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 changed = 0;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &before));

	file_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_LOW,
							 &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = token;
	args.primary_token = token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_check_exec_new_process_min(
				&args, &after, &changed),
			0L);
	KUNIT_EXPECT_EQ(test, changed, 1U);
	KUNIT_EXPECT_NE(test, after.token_id, before.token_id);
	KUNIT_EXPECT_EQ(test, after.modified_id, after.token_id);
	KUNIT_EXPECT_EQ(test, after.integrity_level, PKM_KUNIT_IL_LOW);
	KUNIT_EXPECT_EQ(test, after.token_type, KACS_TOKEN_TYPE_PRIMARY);
	KUNIT_EXPECT_EQ(test, after.impersonation_level, KACS_IMLEVEL_ANONYMOUS);
	KUNIT_EXPECT_EQ(test, after.elevation_type, KACS_ELEVATION_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.session_id, before.session_id);
	KUNIT_EXPECT_EQ(test, after.user_sid_len, before.user_sid_len);
	KUNIT_EXPECT_EQ(test, after.mandatory_policy, before.mandatory_policy);
	KUNIT_EXPECT_EQ(test, after.privileges_present,
			before.privileges_present);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled,
			before.privileges_enabled);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_exec_new_process_min_unlabeled_defaults_medium(
	struct kunit *test)
{
	struct pkm_kacs_kunit_exec_new_process_min_args args = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 changed = 0;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);

	file_sd = kacs_rust_kunit_create_file_sd(
		token, PKM_KUNIT_FILE_SD_ADMIN_MASK,
		PKM_KUNIT_FILE_SD_ADMIN_MASK, PKM_KUNIT_FILE_SD_ADMIN_MASK,
		0, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = token;
	args.primary_token = token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_check_exec_new_process_min(
				&args, &after, &changed),
			0L);
	KUNIT_EXPECT_EQ(test, changed, 1U);
	KUNIT_EXPECT_EQ(test, after.integrity_level, PKM_KUNIT_IL_MEDIUM);
	KUNIT_EXPECT_EQ(test, after.modified_id, after.token_id);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_exec_new_process_min_equal_label_noops(
	struct kunit *test)
{
	struct pkm_kacs_kunit_exec_new_process_min_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *token;
	const u8 *file_sd;
	size_t file_sd_len = 0;
	u32 changed = 0;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &before));

	file_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_SYSTEM,
							 &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = token;
	args.primary_token = token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_check_exec_new_process_min(
				&args, &after, &changed),
			0L);
	KUNIT_EXPECT_EQ(test, changed, 0U);
	KUNIT_EXPECT_EQ(test, after.token_id, before.token_id);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id);
	KUNIT_EXPECT_EQ(test, after.integrity_level, PKM_KUNIT_IL_SYSTEM);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_exec_new_process_min_corrupt_sd_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_exec_new_process_min_args args = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *token;
	u32 changed = 1;
	u32 label = 0;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	args.subject_token = token;
	args.primary_token = token;
	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_CORRUPT;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_exec_new_process_min(
				&args, &after, &changed),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, changed, 0U);
	KUNIT_EXPECT_EQ(test,
			kacs_rust_file_sd_integrity_label(NULL, 0, &label),
			-EINVAL);
	KUNIT_EXPECT_EQ(test,
			kacs_rust_token_new_process_min_exec(
				token, PKM_KUNIT_IL_LOW, NULL),
			-EINVAL);

	kacs_rust_token_drop(token);
}


static void pkm_kunit_process_state_clone_thread_shares_live_object(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view current_view = { };
	struct pkm_kacs_kunit_process_state_view shared_view = { };
	const void *current_state;
	const void *shared_state;

	current_state = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, current_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				current_state, &current_view),
			0);

	shared_state = pkm_kacs_kunit_inherit_current_process_state(
		CLONE_THREAD);
	KUNIT_ASSERT_NOT_NULL(test, shared_state);
	KUNIT_EXPECT_PTR_EQ(test, shared_state, current_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				shared_state, &shared_view),
			0);
	KUNIT_EXPECT_PTR_EQ(test, shared_view.rate_bucket_ptr,
			    current_view.rate_bucket_ptr);
	KUNIT_EXPECT_PTR_EQ(test, shared_view.process_sd_ptr,
			    current_view.process_sd_ptr);
	pkm_kunit_expect_guid_v4(test, current_view.process_guid);
	pkm_kunit_expect_guid_eq(test, shared_view.process_guid,
				 current_view.process_guid);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(
				KACS_MIT_UI_ACCESS | KACS_MIT_WXP),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				shared_state, &shared_view),
			0);
	KUNIT_EXPECT_EQ(test, shared_view.mitigation_bits,
			KACS_MIT_UI_ACCESS | KACS_MIT_WXP);

	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				shared_state, &shared_view),
			0);
	KUNIT_EXPECT_EQ(test, shared_view.pip_type,
			PKM_KUNIT_PIP_TYPE_PROTECTED);
	KUNIT_EXPECT_EQ(test, shared_view.pip_trust,
			PKM_KUNIT_PIP_TRUST_TEST);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(0),
			0);
	pkm_kacs_kunit_set_current_pip_context(0, 0);
	pkm_kacs_kunit_put_process_state(shared_state);
}


static void pkm_kunit_process_state_fork_gets_fresh_sd_and_rate_bucket(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view current_view = { };
	struct pkm_kacs_kunit_process_state_view child_view = { };
	const void *current_state;
	const void *child_state;

	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);
	current_state = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, current_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				current_state, &current_view),
			0);

	child_state = pkm_kacs_kunit_inherit_current_process_state(0);
	KUNIT_ASSERT_NOT_NULL(test, child_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(child_state,
							      &child_view),
			0);
	KUNIT_EXPECT_TRUE(test, child_state != current_state);
	KUNIT_EXPECT_TRUE(test,
			  child_view.rate_bucket_ptr !=
				  current_view.rate_bucket_ptr);
	KUNIT_EXPECT_TRUE(test,
			  child_view.process_sd_ptr !=
				  current_view.process_sd_ptr);
	pkm_kunit_expect_guid_v4(test, current_view.process_guid);
	pkm_kunit_expect_guid_v4(test, child_view.process_guid);
	pkm_kunit_expect_guid_ne(test, child_view.process_guid,
				 current_view.process_guid);
	KUNIT_EXPECT_EQ(test, child_view.pip_type,
			PKM_KUNIT_PIP_TYPE_PROTECTED);
	KUNIT_EXPECT_EQ(test, child_view.pip_trust,
			PKM_KUNIT_PIP_TRUST_TEST);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(
				KACS_MIT_UI_ACCESS | KACS_MIT_WXP),
			0);
	pkm_kacs_kunit_put_process_state(child_state);

	child_state = pkm_kacs_kunit_inherit_current_process_state(0);
	KUNIT_ASSERT_NOT_NULL(test, child_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(child_state,
							      &child_view),
			0);
	KUNIT_EXPECT_EQ(test, child_view.mitigation_bits,
			KACS_MIT_UI_ACCESS | KACS_MIT_WXP);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(0),
			0);
	pkm_kacs_kunit_set_current_pip_context(0, 0);
	pkm_kacs_kunit_put_process_state(child_state);
}


static void pkm_kunit_process_state_fork_inherits_no_child(struct kunit *test)
{
	const u32 mitigation_bits = KACS_MIT_NO_CHILD | KACS_MIT_UI_ACCESS;
	struct pkm_kacs_kunit_process_state_view saved = { };
	struct pkm_kacs_kunit_process_state_view child_view = { };
	const void *current_state;
	const void *child_state;

	current_state = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, current_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(current_state,
							      &saved),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(
				mitigation_bits),
			0);

	child_state = pkm_kacs_kunit_inherit_current_process_state(0);
	KUNIT_ASSERT_NOT_NULL(test, child_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(child_state,
							      &child_view),
			0);
	KUNIT_EXPECT_TRUE(test, child_state != current_state);
	KUNIT_EXPECT_EQ(test, child_view.mitigation_bits, mitigation_bits);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_no_child_process(
				child_view.mitigation_bits, 0),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_no_child_process(
				child_view.mitigation_bits, CLONE_THREAD),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(
				saved.mitigation_bits),
			0);
	pkm_kacs_kunit_put_process_state(child_state);
}


static void pkm_kunit_process_state_impersonation_preserves_psb(
	struct kunit *test)
{
	const u32 test_mitigations = KACS_MIT_UI_ACCESS | KACS_MIT_WXP;
	struct pkm_kacs_kunit_process_state_view original = { };
	struct pkm_kacs_kunit_process_state_view before = { };
	struct pkm_kacs_kunit_process_state_view after_install = { };
	struct pkm_kacs_kunit_process_state_view after_revert = { };
	const void *primary_token;
	const void *client_token = NULL;
	const void *state_ptr;
	u32 old_pip_type = 0;
	u32 old_pip_trust = 0;
	u32 pip_type = 0;
	u32 pip_trust = 0;
	long fd = -1;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_pip_type,
						     &old_pip_trust),
			0);
	state_ptr = pkm_kacs_kunit_current_process_state_ptr();
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, state_ptr);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr,
							      &original),
			0);

	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_set_current_process_mitigation_bits(
		test_mitigations);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_cleanup;
	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);
	ret = pkm_kacs_kunit_process_state_snapshot(state_ptr, &before);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_restore;
	KUNIT_EXPECT_PTR_EQ(
		test, pkm_kacs_kunit_current_effective_cred_process_state_ptr(),
		state_ptr);
	KUNIT_EXPECT_PTR_EQ(test,
			    pkm_kacs_kunit_current_real_cred_process_state_ptr(),
			    state_ptr);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, primary_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_restore;
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() != primary_token);
	KUNIT_EXPECT_PTR_EQ(
		test, pkm_kacs_kunit_current_process_state_ptr(), state_ptr);
	KUNIT_EXPECT_PTR_EQ(
		test, pkm_kacs_kunit_current_effective_cred_process_state_ptr(),
		state_ptr);
	KUNIT_EXPECT_PTR_EQ(test,
			    pkm_kacs_kunit_current_real_cred_process_state_ptr(),
			    state_ptr);
	KUNIT_EXPECT_EQ(test, pkm_kacs_current_pip_context(&pip_type,
							   &pip_trust),
			0);
	KUNIT_EXPECT_EQ(test, pip_type, PKM_KUNIT_PIP_TYPE_PROTECTED);
	KUNIT_EXPECT_EQ(test, pip_trust, PKM_KUNIT_PIP_TRUST_TEST);
	ret = pkm_kacs_kunit_process_state_snapshot(state_ptr, &after_install);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_restore;
	pkm_kunit_expect_process_state_snapshot_eq(test, &before,
						   &after_install);

	ret = pkm_kacs_revert_impersonation();
	KUNIT_EXPECT_EQ(test, ret, 0);
	if (ret)
		goto out_restore;
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_PTR_EQ(
		test, pkm_kacs_kunit_current_process_state_ptr(), state_ptr);
	KUNIT_EXPECT_PTR_EQ(
		test, pkm_kacs_kunit_current_effective_cred_process_state_ptr(),
		state_ptr);
	KUNIT_EXPECT_PTR_EQ(test,
			    pkm_kacs_kunit_current_real_cred_process_state_ptr(),
			    state_ptr);
	KUNIT_EXPECT_EQ(test, pkm_kacs_current_pip_context(&pip_type,
							   &pip_trust),
			0);
	KUNIT_EXPECT_EQ(test, pip_type, PKM_KUNIT_PIP_TYPE_PROTECTED);
	KUNIT_EXPECT_EQ(test, pip_trust, PKM_KUNIT_PIP_TRUST_TEST);
	ret = pkm_kacs_kunit_process_state_snapshot(state_ptr, &after_revert);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_restore;
	pkm_kunit_expect_process_state_snapshot_eq(test, &before, &after_revert);

out_restore:
	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_EQ(
		test,
		pkm_kacs_kunit_set_current_process_mitigation_bits(
			original.mitigation_bits),
		0);
	pkm_kacs_kunit_set_current_pip_context(old_pip_type, old_pip_trust);
out_cleanup:
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_clone_process_impersonation_uses_primary_copy(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot parent_primary = { };
	struct pkm_kacs_boot_snapshot parent_effective = { };
	struct pkm_kacs_boot_snapshot child_effective = { };
	const void *client_token;
	const void *primary_token;
	u32 child_token_is_parent_primary = 1;
	u32 child_cred_is_parent_real = 1;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_impersonate((int)fd,
							   primary_token),
			0L);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  primary_token);

	ret = pkm_kacs_kunit_clone_token_lifecycle_probe(
		0, 0, &parent_primary, &parent_effective, &child_effective,
		&child_token_is_parent_primary, &child_cred_is_parent_real);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, parent_primary.token_ptr, primary_token);
	KUNIT_EXPECT_TRUE(test,
			  parent_effective.token_ptr != parent_primary.token_ptr);
	KUNIT_EXPECT_NE(test, child_effective.token_id, parent_primary.token_id);
	KUNIT_EXPECT_EQ(test, child_effective.modified_id,
			child_effective.token_id);
	pkm_kunit_expect_boot_snapshot_eq_except_identity(test, &parent_primary,
							  &child_effective);
	KUNIT_EXPECT_EQ(test, child_token_is_parent_primary, 0U);
	KUNIT_EXPECT_EQ(test, child_cred_is_parent_real, 0U);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_clone_thread_impersonation_starts_on_primary(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot parent_primary = { };
	struct pkm_kacs_boot_snapshot parent_effective = { };
	struct pkm_kacs_boot_snapshot child_effective = { };
	const void *client_token;
	const void *primary_token;
	u32 child_token_is_parent_primary = 0;
	u32 child_cred_is_parent_real = 0;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_impersonate((int)fd,
							   primary_token),
			0L);

	ret = pkm_kacs_kunit_clone_token_lifecycle_probe(
		CLONE_THREAD, 1, &parent_primary, &parent_effective,
		&child_effective, &child_token_is_parent_primary,
		&child_cred_is_parent_real);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_TRUE(test,
			  parent_effective.token_ptr != parent_primary.token_ptr);
	pkm_kunit_expect_boot_snapshot_eq(test, &parent_primary,
					  &child_effective);
	KUNIT_EXPECT_EQ(test, child_token_is_parent_primary, 1U);
	KUNIT_EXPECT_EQ(test, child_cred_is_parent_real, 1U);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_clone_thread_shared_token_mutation_visible(
	struct kunit *test)
{
	struct pkm_kacs_kunit_clone_mutation_probe probe = { };
	long ret;

	ret = pkm_kacs_kunit_clone_thread_shared_token_mutation_probe(
		&probe);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, probe.child_token_is_source, 1U);
	pkm_kunit_expect_boot_snapshot_scalars_eq(test, &probe.source_before,
						  &probe.child_before);
	KUNIT_EXPECT_EQ(test,
			probe.source_after_source_mutation
				.interactive_session_id,
			probe.source_before.interactive_session_id ^ 1U);
	KUNIT_EXPECT_EQ(test,
			probe.source_after_source_mutation.modified_id,
			probe.source_before.modified_id + 1);
	pkm_kunit_expect_boot_snapshot_scalars_eq(
		test, &probe.source_after_source_mutation,
		&probe.child_after_source_mutation);
	KUNIT_EXPECT_EQ(test,
			probe.source_after_child_mutation.interactive_session_id,
			probe.child_after_source_mutation.interactive_session_id ^
				2U);
	KUNIT_EXPECT_EQ(test, probe.source_after_child_mutation.modified_id,
			probe.source_before.modified_id + 2);
	pkm_kunit_expect_boot_snapshot_scalars_eq(
		test, &probe.source_after_child_mutation,
		&probe.child_after_child_mutation);
}


static void pkm_kunit_clone_process_deep_copy_mutation_isolated(
	struct kunit *test)
{
	struct pkm_kacs_kunit_clone_mutation_probe probe = { };
	long ret;

	ret = pkm_kacs_kunit_clone_process_deep_copy_mutation_probe(&probe);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, probe.child_token_is_source, 0U);
	KUNIT_EXPECT_NE(test, probe.child_before.token_id,
			probe.source_before.token_id);
	KUNIT_EXPECT_EQ(test, probe.child_before.modified_id,
			probe.child_before.token_id);
	pkm_kunit_expect_boot_snapshot_scalars_eq_except_identity(
		test, &probe.source_before, &probe.child_before);
	KUNIT_EXPECT_EQ(test,
			probe.source_after_source_mutation
				.interactive_session_id,
			probe.source_before.interactive_session_id ^ 1U);
	KUNIT_EXPECT_EQ(test,
			probe.source_after_source_mutation.modified_id,
			probe.source_before.modified_id + 1);
	pkm_kunit_expect_boot_snapshot_scalars_eq(
		test, &probe.child_before,
		&probe.child_after_source_mutation);
	pkm_kunit_expect_boot_snapshot_scalars_eq(
		test, &probe.source_after_source_mutation,
		&probe.source_after_child_mutation);
	KUNIT_EXPECT_EQ(test,
			probe.child_after_child_mutation.interactive_session_id,
			probe.child_before.interactive_session_id ^ 2U);
	KUNIT_EXPECT_EQ(test, probe.child_after_child_mutation.modified_id,
			probe.child_before.modified_id + 1);
}


static void pkm_kunit_exec_committing_reverts_impersonation(struct kunit *test)
{
	const void *client_token;
	const void *primary_token;
	long fd;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_impersonate((int)fd,
							   primary_token),
			0L);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  primary_token);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_exec_committing_creds_for_current(),
			0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    primary_token);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_set_psb_self_supported_bits_success(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = {
		.requested_mitigations = KACS_MIT_WXP | KACS_MIT_UI_ACCESS |
					 KACS_MIT_NO_CHILD | KACS_MIT_PIE |
					 KACS_MIT_SML,
		.self_target = 1,
		.ibt_supported = 1,
		.shstk_supported = 1,
	};
	u32 resulting_bits = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			0L);
	KUNIT_EXPECT_EQ(test, resulting_bits, args.requested_mitigations);
}


static void pkm_kunit_set_psb_cross_process_success(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	u32 resulting_bits = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.requested_mitigations = KACS_MIT_UI_ACCESS;
	args.ibt_supported = 1;
	args.shstk_supported = 1;

	ret = pkm_kacs_kunit_set_psb_for_subject(&args, &resulting_bits);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, resulting_bits, KACS_MIT_UI_ACCESS);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_set_psb_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	u32 resulting_bits = 0xDEADBEEFU;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.requested_mitigations = KACS_MIT_UI_ACCESS;
	args.ibt_supported = 1;
	args.shstk_supported = 1;

	ret = pkm_kacs_kunit_set_psb_for_subject(&args, &resulting_bits);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, resulting_bits, 0xDEADBEEFU);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_psb_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	u32 resulting_bits = 0;
	long ret;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.requested_mitigations = KACS_MIT_UI_ACCESS;
	args.ibt_supported = 1;
	args.shstk_supported = 1;

	ret = pkm_kacs_kunit_set_psb_for_subject(&args, &resulting_bits);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, resulting_bits, KACS_MIT_UI_ACCESS);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_psb_debug_still_fails_on_pip(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	u32 resulting_bits = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.requested_mitigations = KACS_MIT_UI_ACCESS;
	args.ibt_supported = 1;
	args.shstk_supported = 1;

	ret = pkm_kacs_kunit_set_psb_for_subject(&args, &resulting_bits);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_process_pip_dominance_matrix(struct kunit *test)
{
	static const struct {
		u32 caller_type;
		u32 caller_trust;
		u32 target_type;
		u32 target_trust;
		bool expected;
	} cases[] = {
		{ 0U, 0U, 0U, PKM_KUNIT_PIP_TRUST_TEST, true },
		{ 0U, 0U, PKM_KUNIT_PIP_TYPE_PROTECTED, 0U, false },
		{ PKM_KUNIT_PIP_TYPE_PROTECTED, PKM_KUNIT_PIP_TRUST_TEST,
		  PKM_KUNIT_PIP_TYPE_PROTECTED, PKM_KUNIT_PIP_TRUST_TEST,
		  true },
		{ PKM_KUNIT_PIP_TYPE_ISOLATED, PKM_KUNIT_PIP_TRUST_TEST,
		  PKM_KUNIT_PIP_TYPE_PROTECTED, PKM_KUNIT_PIP_TRUST_TEST,
		  true },
		{ PKM_KUNIT_PIP_TYPE_PROTECTED, PKM_KUNIT_PIP_TRUST_TEST + 1U,
		  PKM_KUNIT_PIP_TYPE_PROTECTED, PKM_KUNIT_PIP_TRUST_TEST,
		  true },
		{ PKM_KUNIT_PIP_TYPE_PROTECTED, PKM_KUNIT_PIP_TRUST_TEST,
		  PKM_KUNIT_PIP_TYPE_ISOLATED, PKM_KUNIT_PIP_TRUST_TEST,
		  false },
		{ PKM_KUNIT_PIP_TYPE_PROTECTED, PKM_KUNIT_PIP_TRUST_TEST - 1U,
		  PKM_KUNIT_PIP_TYPE_PROTECTED, PKM_KUNIT_PIP_TRUST_TEST,
		  false },
		{ PKM_KUNIT_PIP_TYPE_ISOLATED, PKM_KUNIT_PIP_TRUST_TEST - 1U,
		  PKM_KUNIT_PIP_TYPE_PROTECTED, PKM_KUNIT_PIP_TRUST_TEST,
		  false },
		{ PKM_KUNIT_PIP_TYPE_PROTECTED, PKM_KUNIT_PIP_TRUST_TEST + 1U,
		  PKM_KUNIT_PIP_TYPE_ISOLATED, PKM_KUNIT_PIP_TRUST_TEST,
		  false },
	};
	u32 i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		KUNIT_EXPECT_EQ(
			test,
			pkm_kacs_kunit_pip_dominates(
				cases[i].caller_type, cases[i].caller_trust,
				cases[i].target_type, cases[i].target_trust),
			cases[i].expected);
	}
}


static void pkm_kunit_set_psb_cfi_alias_expands(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = {
		.requested_mitigations = KACS_MIT_CFI,
		.self_target = 1,
		.ibt_supported = 1,
		.shstk_supported = 1,
	};
	u32 resulting_bits = 0;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			0L);
	KUNIT_EXPECT_EQ(test, resulting_bits,
			KACS_MIT_CFIF | KACS_MIT_CFIB);
}


static void pkm_kunit_set_psb_cfi_requires_cpu_support(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = {
		.requested_mitigations = KACS_MIT_CFI,
		.self_target = 1,
		.ibt_supported = 0,
		.shstk_supported = 1,
	};
	u32 resulting_bits = 0xABCDU;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			(long)-ENODEV);
	KUNIT_EXPECT_EQ(test, resulting_bits, 0xABCDU);
}


static void pkm_kunit_set_psb_tlp_lsv_supported(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = {
		.initial_mitigation_bits = KACS_MIT_UI_ACCESS,
		.requested_mitigations = KACS_MIT_WXP | KACS_MIT_TLP,
		.self_target = 1,
		.ibt_supported = 1,
		.shstk_supported = 1,
	};
	u32 resulting_bits = 0xBADCAFEU;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			0L);
	KUNIT_EXPECT_EQ(test, resulting_bits,
			KACS_MIT_UI_ACCESS | KACS_MIT_WXP | KACS_MIT_TLP);

	args.requested_mitigations = KACS_MIT_WXP | KACS_MIT_LSV;
	resulting_bits = 0xBADCAFEU;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			0L);
	KUNIT_EXPECT_EQ(test, resulting_bits,
			KACS_MIT_UI_ACCESS | KACS_MIT_WXP | KACS_MIT_LSV);

	args.requested_mitigations = KACS_MIT_TLP | KACS_MIT_LSV;
	resulting_bits = 0xBADCAFEU;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			0L);
	KUNIT_EXPECT_EQ(test, resulting_bits,
			KACS_MIT_UI_ACCESS | KACS_MIT_TLP | KACS_MIT_LSV);
}


static void pkm_kunit_set_psb_activation_failure_preserves_bits(
	struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = {
		.initial_mitigation_bits = KACS_MIT_UI_ACCESS,
		.requested_mitigations = KACS_MIT_WXP | KACS_MIT_LSV,
		.self_target = 1,
		.ibt_supported = 1,
		.shstk_supported = 1,
		.kunit_fail_activation_bits = KACS_MIT_LSV,
	};
	u32 resulting_bits = 0xBADCAFEU;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, resulting_bits, 0xBADCAFEU);

	args.requested_mitigations = KACS_MIT_CFIF;
	args.kunit_fail_activation_bits = KACS_MIT_CFIF;
	resulting_bits = 0xBADCAFEU;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, resulting_bits, 0xBADCAFEU);

	args.requested_mitigations = KACS_MIT_CFIB;
	args.kunit_fail_activation_bits = KACS_MIT_CFIB;
	resulting_bits = 0xBADCAFEU;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, resulting_bits, 0xBADCAFEU);

	args.requested_mitigations = KACS_MIT_SML;
	args.kunit_fail_activation_bits = KACS_MIT_SML;
	resulting_bits = 0xBADCAFEU;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, resulting_bits, 0xBADCAFEU);
}


static void pkm_kunit_set_psb_cfif_real_activation_fails_closed(
	struct kunit *test)
{
	const void *state_ptr = pkm_kacs_kunit_current_process_state_ptr();
	struct pkm_kacs_kunit_process_state_view saved = {};
	struct pkm_kacs_kunit_process_state_view after = {};
	u32 resulting_bits = 0xBADCAFEU;
	long ret;

	KUNIT_ASSERT_NOT_NULL(test, state_ptr);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &saved),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(0),
			0);

	ret = pkm_kacs_kunit_set_current_psb_with_platform(
		KACS_MIT_CFIF, 1, 1, &resulting_bits);
	KUNIT_EXPECT_EQ(test, ret, (long)-ENODEV);
	KUNIT_EXPECT_EQ(test, resulting_bits, 0xBADCAFEU);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &after),
			0);
	KUNIT_EXPECT_EQ(test, after.mitigation_bits, 0U);

	KUNIT_EXPECT_EQ(
		test,
		pkm_kacs_kunit_set_current_process_mitigation_bits(
			saved.mitigation_bits),
		0);
}


static void pkm_kunit_set_psb_unknown_bits_fail_closed(struct kunit *test)
{
	struct pkm_kacs_kunit_set_psb_args args = {
		.requested_mitigations = KACS_MIT_UI_ACCESS | 0x80000000U,
		.self_target = 1,
		.ibt_supported = 1,
		.shstk_supported = 1,
	};
	u32 resulting_bits = 0xBADF00DU;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_psb_for_subject(&args,
							   &resulting_bits),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, resulting_bits, 0xBADF00DU);
}


static void pkm_kunit_no_child_blocks_process_fork_only(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_no_child_process(
				KACS_MIT_NO_CHILD, 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_no_child_process(
				KACS_MIT_NO_CHILD, CLONE_THREAD),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_no_child_process(0, 0),
			0);
}


static void pkm_kunit_wxp_rejects_wx_map_and_transition(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_wxp_mmap(
				KACS_MIT_WXP, PROT_WRITE | PROT_EXEC),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_wxp_mprotect(
				KACS_MIT_WXP, VM_WRITE, PROT_EXEC),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_wxp_mprotect(
				KACS_MIT_WXP, VM_EXEC, PROT_WRITE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_wxp_mmap(KACS_MIT_WXP, PROT_READ),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_wxp_existing_vma(
				KACS_MIT_WXP, VM_WRITE | VM_EXEC),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_wxp_existing_vma(
				KACS_MIT_WXP, VM_EXEC),
			0);
}


static void pkm_kunit_tlp_cache_validation(struct kunit *test)
{
	const char *prefixes[] = { "/usr/lib/" };
	size_t prefix_lens[] = { sizeof("/usr/lib/") - 1 };
	const char *empty_prefixes[] = { "" };
	size_t empty_lens[] = { 0 };
	const char *relative_prefixes[] = { "usr/lib/" };
	size_t relative_lens[] = { sizeof("usr/lib/") - 1 };
	const char *unterminated_prefixes[] = { "/usr/lib" };
	size_t unterminated_lens[] = { sizeof("/usr/lib") - 1 };
	const char *overlong_prefixes[1];
	size_t overlong_lens[] = { 4097 };
	char *overlong;

	pkm_kacs_kunit_clear_tlp_prefixes();
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_replace_tlp_prefixes(
				prefixes, prefix_lens, ARRAY_SIZE(prefixes)),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC, "/usr/lib/libok.so",
				1),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_replace_tlp_prefixes(
				empty_prefixes, empty_lens,
				ARRAY_SIZE(empty_prefixes)),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC, "/usr/lib/libok.so",
				1),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_replace_tlp_prefixes(
				relative_prefixes, relative_lens,
				ARRAY_SIZE(relative_prefixes)),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC, "/usr/lib/libok.so",
				1),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_replace_tlp_prefixes(
				unterminated_prefixes, unterminated_lens,
				ARRAY_SIZE(unterminated_prefixes)),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC, "/usr/lib/libok.so",
				1),
			0);

	overlong = kunit_kmalloc(test, 4097, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, overlong);
	memset(overlong, 'a', 4097);
	overlong_prefixes[0] = overlong;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_replace_tlp_prefixes(
				overlong_prefixes, overlong_lens,
				ARRAY_SIZE(overlong_prefixes)),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC, "/usr/lib/libok.so",
				1),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_replace_tlp_prefixes(NULL, NULL, 65),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC, "/usr/lib/libok.so",
				1),
			0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_replace_tlp_prefixes(NULL, NULL,
								  0),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC, "/usr/lib/libok.so",
				1),
			-EACCES);
	pkm_kacs_kunit_clear_tlp_prefixes();
}


static void pkm_kunit_tlp_executable_mapping_enforcement(struct kunit *test)
{
	const char *prefixes[] = { "/usr/lib/" };
	size_t prefix_lens[] = { sizeof("/usr/lib/") - 1 };

	pkm_kacs_kunit_clear_tlp_prefixes();
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC, "/usr/lib/libc.so",
				1),
			-EACCES);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_replace_tlp_prefixes(
				prefixes, prefix_lens, ARRAY_SIZE(prefixes)),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC, "/usr/lib/libc.so",
				1),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC, "/tmp/libevil.so",
				1),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC,
				"/usr/libevil/libc.so", 1),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_READ, "/tmp/libevil.so",
				1),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC, NULL, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				0, PROT_EXEC, "/tmp/libevil.so", 1),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mmap_path(
				KACS_MIT_TLP, PROT_EXEC, NULL, 1),
			-EACCES);

	pkm_kacs_kunit_clear_tlp_prefixes();
}


static void pkm_kunit_tlp_mprotect_checks_new_exec_only(struct kunit *test)
{
	const char *prefixes[] = { "/trusted/" };
	size_t prefix_lens[] = { sizeof("/trusted/") - 1 };

	pkm_kacs_kunit_clear_tlp_prefixes();
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_replace_tlp_prefixes(
				prefixes, prefix_lens, ARRAY_SIZE(prefixes)),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mprotect_path(
				KACS_MIT_TLP, 0, PROT_EXEC,
				"/trusted/libok.so", 1),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mprotect_path(
				KACS_MIT_TLP, 0, PROT_EXEC,
				"/tmp/libevil.so", 1),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mprotect_path(
				KACS_MIT_TLP, VM_EXEC, PROT_EXEC,
				"/tmp/libevil.so", 1),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mprotect_path(
				KACS_MIT_TLP, 0, PROT_READ,
				"/tmp/libevil.so", 1),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_tlp_mprotect_path(
				KACS_MIT_TLP, 0, PROT_EXEC, NULL, 0),
			0);

	pkm_kacs_kunit_clear_tlp_prefixes();
}


static void pkm_kunit_exec_pip_signed_material_sets_tcb_trust(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe material = {};
	struct pkm_kacs_kunit_signing_verify_out out = {};

	pkm_kunit_signing_fill_tcb_vector_material(&material);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_determine_exec_pip_from_signing_material(
				&material, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 1U);
	KUNIT_EXPECT_EQ(test, out.pip_type,
			PKM_KUNIT_SIGNING_PIP_PROTECTED);
	KUNIT_EXPECT_EQ(test, out.pip_trust, PKM_KUNIT_SIGNING_TRUST_TCB);
}


static void pkm_kunit_exec_pip_bad_signature_resets_none(struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe material = {};
	struct pkm_kacs_kunit_signing_verify_out out = {};

	pkm_kunit_signing_fill_tcb_vector_material(&material);
	material.signature[0] ^= 0x01;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_determine_exec_pip_from_signing_material(
				&material, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_type, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_trust, 0U);
}


static void pkm_kunit_exec_pip_pending_is_transactional(struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view saved = {};
	struct pkm_kacs_kunit_process_state_view staged = {};
	struct pkm_kacs_kunit_process_state_view committed = {};
	struct pkm_kacs_kunit_signing_probe material = {};
	const void *state_ptr;
	int ret;

	state_ptr = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &saved),
			0);

	pkm_kacs_kunit_set_current_pip_context(0, 0);
	pkm_kunit_signing_fill_tcb_vector_material(&material);

	ret = pkm_kacs_kunit_stage_exec_pip_from_signing_material(
		&material, 0, &staged);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, staged.pip_type, 0U);
	KUNIT_EXPECT_EQ(test, staged.pip_trust, 0U);

	ret = pkm_kacs_kunit_stage_exec_pip_from_signing_material(
		&material, 1, &committed);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, committed.pip_type,
			PKM_KUNIT_SIGNING_PIP_PROTECTED);
	KUNIT_EXPECT_EQ(test, committed.pip_trust,
			PKM_KUNIT_SIGNING_TRUST_TCB);
	KUNIT_EXPECT_PTR_EQ(test, committed.process_sd_ptr,
			    saved.process_sd_ptr);
	KUNIT_EXPECT_PTR_EQ(test, committed.rate_bucket_ptr,
			    saved.rate_bucket_ptr);
	KUNIT_EXPECT_EQ(test, committed.mitigation_bits,
			saved.mitigation_bits);

	pkm_kacs_kunit_set_current_pip_context(saved.pip_type,
					       saved.pip_trust);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(
				saved.mitigation_bits),
			0);
}


static void pkm_kunit_exec_pip_unsigned_commit_clears_existing_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view saved = {};
	struct pkm_kacs_kunit_process_state_view before = {};
	struct pkm_kacs_kunit_process_state_view after = {};
	struct pkm_kacs_kunit_signing_probe material = {};
	const void *state_ptr;
	int ret;

	state_ptr = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &saved),
			0);

	pkm_kacs_kunit_set_current_pip_context(
		PKM_KUNIT_SIGNING_PIP_PROTECTED, PKM_KUNIT_SIGNING_TRUST_TCB);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(
				KACS_MIT_TLP),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &before),
			0);

	material.source = PKM_KACS_KUNIT_SIGNING_SOURCE_NONE;
	ret = pkm_kacs_kunit_stage_exec_pip_from_signing_material(
		&material, 1, &after);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, after.pip_type, 0U);
	KUNIT_EXPECT_EQ(test, after.pip_trust, 0U);
	KUNIT_EXPECT_PTR_EQ(test, after.process_sd_ptr, before.process_sd_ptr);
	KUNIT_EXPECT_PTR_EQ(test, after.rate_bucket_ptr, before.rate_bucket_ptr);
	KUNIT_EXPECT_EQ(test, after.mitigation_bits, before.mitigation_bits);

	pkm_kacs_kunit_set_current_pip_context(saved.pip_type,
					       saved.pip_trust);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(
				saved.mitigation_bits),
			0);
}


static void pkm_kunit_exec_commit_preserves_mitigations_and_no_child(
	struct kunit *test)
{
	const u32 mitigation_bits = KACS_MIT_NO_CHILD | KACS_MIT_TLP |
				    KACS_MIT_WXP;
	struct pkm_kacs_kunit_process_state_view saved = {};
	struct pkm_kacs_kunit_process_state_view before = {};
	struct pkm_kacs_kunit_process_state_view after = {};
	struct pkm_kacs_kunit_signing_probe material = {};
	const void *state_ptr;
	int ret;

	state_ptr = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, state_ptr);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &saved),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(
				mitigation_bits),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr,
							      &before),
			0);
	KUNIT_EXPECT_EQ(test, before.mitigation_bits, mitigation_bits);

	material.source = PKM_KACS_KUNIT_SIGNING_SOURCE_NONE;
	ret = pkm_kacs_kunit_stage_exec_pip_from_signing_material(
		&material, 1, &after);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, after.process_sd_ptr, before.process_sd_ptr);
	KUNIT_EXPECT_PTR_EQ(test, after.rate_bucket_ptr,
			    before.rate_bucket_ptr);
	KUNIT_EXPECT_EQ(test, after.mitigation_bits, mitigation_bits);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_no_child_process(
				after.mitigation_bits, 0),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_no_child_process(
				after.mitigation_bits, CLONE_THREAD),
			0L);

	pkm_kacs_kunit_set_current_pip_context(saved.pip_type,
					       saved.pip_trust);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_current_process_mitigation_bits(
				saved.mitigation_bits),
			0);
}


static void pkm_kunit_exec_dumpable_decision_tracks_pip(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_exec_dumpable_after_pip(
				PKM_KUNIT_SIGNING_PIP_PROTECTED,
				SUID_DUMP_USER),
			(long)SUID_DUMP_DISABLE);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_exec_dumpable_after_pip(
				PKM_KUNIT_SIGNING_PIP_PROTECTED,
				SUID_DUMP_ROOT),
			(long)SUID_DUMP_DISABLE);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_exec_dumpable_after_pip(
				0, SUID_DUMP_USER),
			(long)SUID_DUMP_USER);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_exec_dumpable_after_pip(
				0, SUID_DUMP_DISABLE),
			(long)SUID_DUMP_DISABLE);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_exec_dumpable_after_pip(0, 3),
			(long)-EINVAL);
}


static void pkm_kunit_exec_dumpable_signed_material_clears_if_mm(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe material = {};
	long saved_dumpable;

	saved_dumpable = pkm_kacs_kunit_get_current_dumpable();
	if (saved_dumpable == -ENODEV)
		kunit_skip(test, "current task has no mm");
	KUNIT_ASSERT_GE(test, saved_dumpable, 0L);

	pkm_kunit_signing_fill_tcb_vector_material(&material);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_stage_exec_dumpable_from_signing_material(
				&material, SUID_DUMP_USER),
			(long)SUID_DUMP_DISABLE);

	material.source = PKM_KACS_KUNIT_SIGNING_SOURCE_NONE;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_stage_exec_dumpable_from_signing_material(
				&material, SUID_DUMP_USER),
			(long)SUID_DUMP_USER);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_current_dumpable((u32)saved_dumpable),
			0L);
}


static void pkm_kunit_lsv_signed_tcb_allows_none_and_tcb_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe material = {};

	pkm_kunit_signing_fill_tcb_vector_material(&material);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_lsv_mmap_material(
				KACS_MIT_LSV, PROT_EXEC, 0, 0, 1,
				&material),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_lsv_mmap_material(
				KACS_MIT_LSV, PROT_EXEC,
				PKM_KUNIT_SIGNING_PIP_PROTECTED,
				PKM_KUNIT_SIGNING_TRUST_TCB, 1, &material),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_lsv_mprotect_material(
				KACS_MIT_LSV, 0, PROT_EXEC,
				PKM_KUNIT_SIGNING_PIP_PROTECTED,
				PKM_KUNIT_SIGNING_TRUST_TCB, 1, &material),
			0);
}


static void pkm_kunit_lsv_unsigned_and_bad_signature_deny(struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe material = {};

	material.source = PKM_KACS_KUNIT_SIGNING_SOURCE_NONE;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_lsv_mmap_material(
				KACS_MIT_LSV, PROT_EXEC, 0, 0, 1,
				&material),
			-EACCES);

	pkm_kunit_signing_fill_tcb_vector_material(&material);
	material.signature[0] ^= 0x01;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_lsv_mmap_material(
				KACS_MIT_LSV, PROT_EXEC, 0, 0, 1,
				&material),
			-EACCES);
}


static void pkm_kunit_lsv_insufficient_trust_denies(struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe material = {};

	pkm_kunit_signing_fill_tcb_vector_material(&material);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_lsv_mmap_material(
				KACS_MIT_LSV, PROT_EXEC,
				PKM_KUNIT_SIGNING_PIP_PROTECTED,
				PKM_KUNIT_SIGNING_TRUST_TCB + 1U, 1,
				&material),
			-EACCES);
}


static void pkm_kunit_lsv_bypasses_non_exec_and_anonymous(struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe material = {};

	material.source = PKM_KACS_KUNIT_SIGNING_SOURCE_NONE;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_lsv_mmap_material(
				0, PROT_EXEC, PKM_KUNIT_SIGNING_PIP_PROTECTED,
				PKM_KUNIT_SIGNING_TRUST_TCB, 1, &material),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_lsv_mmap_material(
				KACS_MIT_LSV, PROT_READ,
				PKM_KUNIT_SIGNING_PIP_PROTECTED,
				PKM_KUNIT_SIGNING_TRUST_TCB, 1, &material),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_lsv_mmap_material(
				KACS_MIT_LSV, PROT_EXEC,
				PKM_KUNIT_SIGNING_PIP_PROTECTED,
				PKM_KUNIT_SIGNING_TRUST_TCB, 0, NULL),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_lsv_mprotect_material(
				KACS_MIT_LSV, VM_EXEC, PROT_EXEC,
				PKM_KUNIT_SIGNING_PIP_PROTECTED,
				PKM_KUNIT_SIGNING_TRUST_TCB, 1, NULL),
			0);
}


static void pkm_kunit_pie_rejects_et_exec(struct kunit *test)
{
	u8 exec_buf[18] = { 0x7f, 'E', 'L', 'F' };
	u8 pie_buf[18] = { 0x7f, 'E', 'L', 'F' };
	u8 script_buf[4] = { '#', '!', '/', 'b' };

	exec_buf[16] = ET_EXEC & 0xFF;
	exec_buf[17] = (ET_EXEC >> 8) & 0xFF;
	pie_buf[16] = ET_DYN & 0xFF;
	pie_buf[17] = (ET_DYN >> 8) & 0xFF;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_pie_bprm(KACS_MIT_PIE, exec_buf,
						      sizeof(exec_buf)),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_pie_bprm(KACS_MIT_PIE, pie_buf,
						      sizeof(pie_buf)),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_pie_bprm(KACS_MIT_PIE, script_buf,
						      sizeof(script_buf)),
			0);
}


static void pkm_kunit_bprm_file_execute_live_success(struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(
		subject_token, PKM_KUNIT_FILE_EXECUTE, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_EXPECT_EQ(
		test, pkm_kacs_kunit_check_bprm_file_execute_for_subject(&args),
		0L);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_bprm_file_execute_live_denied_by_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
	};
	const void *subject_token;
	const u8 *file_sd;
	size_t file_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	file_sd = pkm_kunit_create_precise_file_sd(
		subject_token, KACS_ACCESS_READ_CONTROL, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = file_sd;
	args.target_file_sd_len = file_sd_len;

	KUNIT_EXPECT_EQ(
		test, pkm_kacs_kunit_check_bprm_file_execute_for_subject(&args),
		(long)-EACCES);

	pkm_kacs_free((void *)file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_bprm_file_execute_missing_or_corrupt_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.subject_token = pkm_kacs_current_effective_token_ptr(),
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_MISSING,
		.mount_policy_override = KACS_MOUNT_POLICY_DENY_MISSING,
	};

	KUNIT_ASSERT_NOT_NULL(test, args.subject_token);

	KUNIT_EXPECT_EQ(
		test, pkm_kacs_kunit_check_bprm_file_execute_for_subject(&args),
		(long)-EACCES);

	args.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_CORRUPT;
	KUNIT_EXPECT_EQ(
		test, pkm_kacs_kunit_check_bprm_file_execute_for_subject(&args),
		(long)-EACCES);
}


static void pkm_kunit_bprm_file_execute_unmanaged_skips_facs(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_open_args args = {
		.subject_token = pkm_kacs_current_effective_token_ptr(),
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_MISSING,
		.mount_policy_override = KACS_MOUNT_POLICY_UNMANAGED,
	};

	KUNIT_ASSERT_NOT_NULL(test, args.subject_token);
	KUNIT_EXPECT_EQ(
		test, pkm_kacs_kunit_check_bprm_file_execute_for_subject(&args),
		0L);
}


static void pkm_kunit_task_prctl_sml_and_cfib_block_disable_paths(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_task_prctl_mitigations(
				KACS_MIT_SML, PR_SET_SPECULATION_CTRL,
				PR_SPEC_STORE_BYPASS, PR_SPEC_ENABLE, 0, 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_task_prctl_mitigations(
				KACS_MIT_SML, PR_SET_SPECULATION_CTRL,
				PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE, 0, 0),
			-ENOSYS);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_task_prctl_mitigations(
				KACS_MIT_SML, PR_SET_SPECULATION_CTRL,
				PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE_NOEXEC,
				0, 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_task_prctl_mitigations(
				KACS_MIT_SML, PR_SET_SPECULATION_CTRL,
				PR_SPEC_L1D_FLUSH, PR_SPEC_ENABLE, 0, 0),
			-ENOSYS);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_task_prctl_mitigations(
				KACS_MIT_SML, PR_SET_SPECULATION_CTRL,
				PR_SPEC_L1D_FLUSH, PR_SPEC_DISABLE, 0, 0),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_task_prctl_mitigations(
				KACS_MIT_CFIB, ARCH_SHSTK_DISABLE, 0, 0, 0, 0),
			-EACCES);
}


static void pkm_kunit_task_prctl_pip_blocks_dumpable_reenable(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_task_prctl_pip(
				PKM_KUNIT_SIGNING_PIP_PROTECTED,
				PR_SET_DUMPABLE, SUID_DUMP_USER),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_task_prctl_pip(
				PKM_KUNIT_SIGNING_PIP_PROTECTED,
				PR_SET_DUMPABLE, SUID_DUMP_DISABLE),
			-ENOSYS);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_task_prctl_pip(
				0, PR_SET_DUMPABLE, SUID_DUMP_USER),
			-ENOSYS);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_task_prctl_pip(
				PKM_KUNIT_SIGNING_PIP_PROTECTED,
				PR_SET_DUMPABLE, SUID_DUMP_ROOT),
			-ENOSYS);
}


static void pkm_kunit_process_boundary_under_impersonation_uses_psb_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
	const void *primary_token;
	const void *client_token;
	u32 old_pip_type = 0;
	u32 old_pip_trust = 0;
	long impersonation_fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_pip_type,
						     &old_pip_trust),
			0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	impersonation_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, impersonation_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)impersonation_fd,
						  primary_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_cleanup;
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    client_token);

	args.target_process_sd_ptr = pkm_kunit_everyone_process_query_pip_sd;
	args.target_process_sd_len =
		sizeof(pkm_kunit_everyone_process_query_pip_sd);
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.sig = 0;

	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);
	ret = pkm_kacs_kunit_check_signal_for_current(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_kunit_set_current_pip_context(0, 0);
	ret = pkm_kacs_kunit_check_signal_for_current(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

out_cleanup:
	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	pkm_kacs_kunit_set_current_pip_context(old_pip_type, old_pip_trust);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)impersonation_fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_proc_token_inspection_query_only_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_token_open_args args = { };
	struct pkm_kacs_token_fd_view view = { };
	struct kacs_duplicate_args duplicate = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.result_fd = -1,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	fd = pkm_kacs_kunit_open_process_token_inspection_for_subject(&args);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_PTR_EQ(test, view.token, target_token);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)fd,
						  KACS_TOKEN_CLASS_TYPE),
			KACS_TOKEN_TYPE_PRIMARY);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_duplicate(
				(int)fd, subject_token, subject_token,
				&duplicate),
			(long)-EACCES);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_proc_token_inspection_statistics_auth_id(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_token_open_args args = { };
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot snapshot = { };
	struct kacs_query_args query = {
		.token_class = KACS_TOKEN_CLASS_STATISTICS,
		.buf_len = 40U,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	u8 stats[40] = { };
	long fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token,
							 &snapshot));

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	fd = pkm_kacs_kunit_open_process_token_inspection_for_subject(&args);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_PTR_EQ(test, view.token, target_token);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);

	query.buf_ptr = (u64)(unsigned long)stats;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &query, stats),
			0L);
	KUNIT_EXPECT_EQ(test, query.buf_len, 40U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(stats, 0), snapshot.token_id);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(stats, 8), snapshot.auth_id);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(stats, 16),
			snapshot.modified_id);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_proc_token_inspection_self_bypasses_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_token_open_args args = { };
	struct pkm_kacs_token_fd_view view = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.self_target = 1;

	fd = pkm_kacs_kunit_open_process_token_inspection_for_subject(&args);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_PTR_EQ(test, view.token, target_token);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_proc_token_inspection_denied_by_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_token_open_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	ret = pkm_kacs_kunit_open_process_token_inspection_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_proc_token_inspection_denied_by_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_token_open_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;

	ret = pkm_kacs_kunit_open_process_token_inspection_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_signal_terminate_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.sig = SIGTERM;

	ret = pkm_kacs_kunit_check_signal_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_signal_info_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.sig = SIGWINCH;

	ret = pkm_kacs_kunit_check_signal_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_process_sd_access_uses_caller_psb_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = {
		.subject_token = pkm_kacs_current_effective_token_ptr(),
		.target_process_sd_ptr = pkm_kunit_everyone_process_query_pip_sd,
		.target_process_sd_len =
			sizeof(pkm_kunit_everyone_process_query_pip_sd),
		.sig = 0,
	};

	KUNIT_ASSERT_NOT_NULL(test, args.subject_token);

	args.caller_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.caller_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signal_for_subject(&args),
			0L);

	args.caller_pip_type = 0;
	args.caller_pip_trust = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signal_for_subject(&args),
			(long)-EACCES);
}


static void pkm_kunit_signal_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.sig = SIGTERM;

	ret = pkm_kacs_kunit_check_signal_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_signal_suspend_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.sig = SIGSTOP;

	ret = pkm_kacs_kunit_check_signal_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_signal_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.sig = SIGTERM;

	ret = pkm_kacs_kunit_check_signal_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_signal_debug_still_fails_on_pip(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.sig = SIGTERM;

	ret = pkm_kacs_kunit_check_signal_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_signal_kernel_originated_bypasses_checks(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = {
		.kernel_originated = 1,
		.sig = SIGTERM,
	};

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_signal_for_subject(&args), 0L);
}


static void pkm_kunit_signal_origin_classification(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_signal_origin_is_kernel(
				PKM_KUNIT_SIGNAL_ORIGIN_NOINFO),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_signal_origin_is_kernel(
				PKM_KUNIT_SIGNAL_ORIGIN_USER),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_signal_origin_is_kernel(
				PKM_KUNIT_SIGNAL_ORIGIN_TKILL),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_signal_origin_is_kernel(
				PKM_KUNIT_SIGNAL_ORIGIN_STORED_CRED),
			0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_signal_origin_is_kernel(
				PKM_KUNIT_SIGNAL_ORIGIN_PRIV),
			1L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_signal_origin_is_kernel(
				PKM_KUNIT_SIGNAL_ORIGIN_KERNEL),
			1L);
}


static void pkm_kunit_signal_table_exact_rights(struct kunit *test)
{
	static const struct {
		int sig;
		u32 process_right;
	} cases[] = {
		{ 0, KACS_PROCESS_QUERY_LIMITED },
		{ SIGHUP, KACS_PROCESS_TERMINATE },
		{ SIGINT, KACS_PROCESS_TERMINATE },
		{ SIGQUIT, KACS_PROCESS_TERMINATE },
		{ SIGILL, KACS_PROCESS_TERMINATE },
		{ SIGTRAP, KACS_PROCESS_TERMINATE },
		{ SIGABRT, KACS_PROCESS_TERMINATE },
		{ SIGBUS, KACS_PROCESS_TERMINATE },
		{ SIGFPE, KACS_PROCESS_TERMINATE },
		{ SIGKILL, KACS_PROCESS_TERMINATE },
		{ SIGUSR1, KACS_PROCESS_TERMINATE },
		{ SIGSEGV, KACS_PROCESS_TERMINATE },
		{ SIGUSR2, KACS_PROCESS_TERMINATE },
		{ SIGPIPE, KACS_PROCESS_TERMINATE },
		{ SIGALRM, KACS_PROCESS_TERMINATE },
		{ SIGTERM, KACS_PROCESS_TERMINATE },
		{ SIGSTKFLT, KACS_PROCESS_TERMINATE },
		{ SIGXCPU, KACS_PROCESS_TERMINATE },
		{ SIGXFSZ, KACS_PROCESS_TERMINATE },
		{ SIGVTALRM, KACS_PROCESS_TERMINATE },
		{ SIGPROF, KACS_PROCESS_TERMINATE },
		{ SIGIO, KACS_PROCESS_TERMINATE },
		{ SIGPWR, KACS_PROCESS_TERMINATE },
		{ SIGSYS, KACS_PROCESS_TERMINATE },
		{ SIGSTOP, KACS_PROCESS_SUSPEND_RESUME },
		{ SIGTSTP, KACS_PROCESS_SUSPEND_RESUME },
		{ SIGTTIN, KACS_PROCESS_SUSPEND_RESUME },
		{ SIGTTOU, KACS_PROCESS_SUSPEND_RESUME },
		{ SIGCONT, KACS_PROCESS_SUSPEND_RESUME },
		{ SIGCHLD, KACS_PROCESS_SIGNAL },
		{ SIGURG, KACS_PROCESS_SIGNAL },
		{ SIGWINCH, KACS_PROCESS_SIGNAL },
	};
	struct pkm_kacs_kunit_process_signal_check_args args = { };
	const void *subject_token;
	const void *target_token;
	u32 i;
	int sig;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	args.subject_token = subject_token;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		const u8 *process_sd;
		size_t process_sd_len = 0;

		process_sd = kacs_rust_kunit_create_process_sd_with_everyone_mask(
			target_token, cases[i].process_right, &process_sd_len);
		KUNIT_ASSERT_NOT_NULL(test, process_sd);

		args.target_process_sd_ptr = process_sd;
		args.target_process_sd_len = process_sd_len;
		args.sig = cases[i].sig;
		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_check_signal_for_subject(&args),
				0L);

		pkm_kacs_free((void *)process_sd);
	}

	for (sig = SIGRTMIN; sig <= SIGRTMAX; sig++) {
		const u8 *process_sd;
		size_t process_sd_len = 0;

		process_sd = kacs_rust_kunit_create_process_sd_with_everyone_mask(
			target_token, KACS_PROCESS_TERMINATE, &process_sd_len);
		KUNIT_ASSERT_NOT_NULL(test, process_sd);

		args.target_process_sd_ptr = process_sd;
		args.target_process_sd_len = process_sd_len;
		args.sig = sig;
		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_check_signal_for_subject(&args),
				0L);

		pkm_kacs_free((void *)process_sd);
	}

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_signal_probe_query_limited_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.sig = 0;

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_signal_for_subject(&args),
			0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_signal_probe_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_information_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.sig = 0;

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_signal_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_signal_probe_denied_by_pip(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.sig = 0;

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_signal_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_signal_invalid_fails_closed(struct kunit *test)
{
	struct pkm_kacs_kunit_process_signal_check_args args = {
		.sig = SIGRTMAX + 1,
	};

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_signal_for_subject(&args),
			(long)-EINVAL);
}


static void pkm_kunit_ptrace_read_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_ptrace_attach_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_ATTACH;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_ptrace_read_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_ptrace_attach_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_ATTACH;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_ptrace_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_ATTACH;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_ptrace_debug_still_fails_on_pip(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.mode = PTRACE_MODE_ATTACH;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_ptrace_unknown_mode_fails_closed(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = {
		.mode = 0,
	};

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_ptrace_for_subject(&args),
			(long)-EACCES);
}


static void pkm_kunit_ptrace_traceme_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	ret = pkm_kacs_kunit_check_ptrace_traceme_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_ptrace_traceme_denied_by_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	ret = pkm_kacs_kunit_check_ptrace_traceme_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_ptrace_traceme_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	ret = pkm_kacs_kunit_check_ptrace_traceme_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_ptrace_traceme_debug_still_fails_on_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;

	ret = pkm_kacs_kunit_check_ptrace_traceme_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_ptrace_traceme_null_args_fail_closed(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_ptrace_traceme_for_subject(NULL),
			(long)-EINVAL);
}


static void pkm_kunit_pidfd_getfd_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_ATTACH | PTRACE_MODE_GETFD;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_pidfd_getfd_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_ATTACH | PTRACE_MODE_GETFD;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_pidfd_getfd_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_ATTACH | PTRACE_MODE_GETFD;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_pidfd_getfd_debug_still_fails_on_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.mode = PTRACE_MODE_ATTACH | PTRACE_MODE_GETFD;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_pidfd_open_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PIDFD_OPEN;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_pidfd_open_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_information_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PIDFD_OPEN;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_pidfd_open_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_information_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PIDFD_OPEN;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_pidfd_open_debug_still_fails_on_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_information_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PIDFD_OPEN;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_proc_metadata_query_limited_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PROC_QUERY_LIMITED;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_proc_metadata_query_limited_denied_by_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_information_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PROC_QUERY_LIMITED;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_proc_metadata_query_information_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PROC_QUERY_INFORMATION;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, 0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_proc_metadata_query_information_denied_by_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;
	long ret;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.mode = PTRACE_MODE_READ | PTRACE_MODE_PROC_QUERY_INFORMATION;

	ret = pkm_kacs_kunit_check_ptrace_for_subject(&args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_proc_metadata_debug_bypasses_limited_process_sd_only(
	struct kunit *test)
{
	pkm_kunit_expect_proc_metadata_debug_bypass(
		test, PTRACE_MODE_PROC_QUERY_LIMITED);
}


static void pkm_kunit_proc_metadata_debug_bypasses_information_process_sd_only(
	struct kunit *test)
{
	pkm_kunit_expect_proc_metadata_debug_bypass(
		test, PTRACE_MODE_PROC_QUERY_INFORMATION);
}


static void pkm_kunit_proc_metadata_debug_limited_still_fails_on_pip(
	struct kunit *test)
{
	pkm_kunit_expect_proc_metadata_debug_pip_denial(
		test, PTRACE_MODE_PROC_QUERY_LIMITED);
}


static void pkm_kunit_proc_metadata_debug_information_still_fails_on_pip(
	struct kunit *test)
{
	pkm_kunit_expect_proc_metadata_debug_pip_denial(
		test, PTRACE_MODE_PROC_QUERY_INFORMATION);
}


static void pkm_kunit_proc_metadata_query_mode_combo_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_ptrace_check_args args = {
		.mode = PTRACE_MODE_READ | PTRACE_MODE_PROC_QUERY_LIMITED |
			PTRACE_MODE_PROC_QUERY_INFORMATION,
	};

	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_check_ptrace_for_subject(&args),
			(long)-EACCES);
}


static void pkm_kunit_setnice_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_setscheduler_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_setioprio_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_process_setinfo_denied_by_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_process_setinfo_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_process_setinfo_debug_still_fails_on_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_process_setinfo_self_target_bypasses_boundary_gate(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_setinfo_check_args args = {
		.self_target = 1,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_setinfo_for_subject(&args),
			0L);
}


static void pkm_kunit_process_attribute_query_limited_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_access_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.desired_access = KACS_PROCESS_QUERY_LIMITED;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_attribute_for_subject(
				&args),
			0L);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_process_attribute_query_information_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_access_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_information_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.desired_access = KACS_PROCESS_QUERY_INFORMATION;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_attribute_for_subject(
				&args),
			0L);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_process_attribute_query_limited_denied_by_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_access_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_information_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.desired_access = KACS_PROCESS_QUERY_LIMITED;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_attribute_for_subject(
				&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_process_attribute_query_information_denied_by_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_access_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.desired_access = KACS_PROCESS_QUERY_INFORMATION;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_attribute_for_subject(
				&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_process_attribute_restrictive_sd_denies_administrator(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_access_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_local_administrator_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_process_sd_with_everyone_mask(
		target_token, KACS_PROCESS_QUERY_LIMITED, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.desired_access = KACS_PROCESS_QUERY_INFORMATION;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_attribute_for_subject(
				&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_process_attribute_setinfo_denied_by_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_access_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.desired_access = KACS_PROCESS_SET_INFORMATION;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_attribute_for_subject(
				&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_process_attribute_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_access_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.desired_access = KACS_PROCESS_QUERY_INFORMATION;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_attribute_for_subject(
				&args),
			0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_process_attribute_debug_still_fails_on_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_access_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.desired_access = KACS_PROCESS_QUERY_INFORMATION;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_attribute_for_subject(
				&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_process_attribute_self_target_bypasses_boundary_gate(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_access_check_args args = {
		.self_target = 1,
		.desired_access = KACS_PROCESS_SET_INFORMATION,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_attribute_for_subject(
				&args),
			0L);
}


static void pkm_kunit_process_attribute_unknown_access_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_access_check_args args = {
		.self_target = 1,
		.desired_access = KACS_PROCESS_TERMINATE,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_attribute_for_subject(
				&args),
			(long)-EACCES);
}


static void pkm_kunit_affinity_same_process_bypasses_boundary_gate(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_affinity_check_args args = {
		.same_process = 1,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_affinity_for_subject(
				&args),
			0L);
}


static void pkm_kunit_affinity_cross_process_success_with_privilege(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_affinity_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_affinity_for_subject(
				&args),
			0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_affinity_cross_process_denied_without_privilege(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_affinity_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_affinity_for_subject(
				&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_affinity_debug_does_not_bypass_standalone_privilege(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_affinity_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_DEBUG_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_affinity_for_subject(
				&args),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used,
			before.privileges_used);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void
pkm_kunit_affinity_debug_plus_privilege_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_affinity_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_DEBUG_PRIVILEGE |
			PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_affinity_for_subject(
				&args),
			0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_DEBUG_PRIVILEGE |
				PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_affinity_privilege_still_fails_on_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_affinity_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_process_affinity_for_subject(
				&args),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_INCREASE_BASE_PRIORITY_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_prlimit_read_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.flags = PKM_KUNIT_PRLIMIT_READ;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args), 0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_prlimit_write_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.flags = PKM_KUNIT_PRLIMIT_WRITE;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args), 0L);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_prlimit_read_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.flags = PKM_KUNIT_PRLIMIT_READ;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_prlimit_write_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_adjustable_privileges_token();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.flags = PKM_KUNIT_PRLIMIT_WRITE;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_prlimit_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_effective_token_ptr());
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.flags = PKM_KUNIT_PRLIMIT_WRITE;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args), 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_prlimit_debug_still_fails_on_pip(struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;
	args.flags = PKM_KUNIT_PRLIMIT_WRITE;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
}


static void pkm_kunit_prlimit_self_target_bypasses_boundary_gate(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = {
		.self_target = 1,
		.flags = PKM_KUNIT_PRLIMIT_WRITE,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args), 0L);
}


static void pkm_kunit_prlimit_unknown_flags_fail_closed(struct kunit *test)
{
	struct pkm_kacs_kunit_process_prlimit_check_args args = {
		.flags = 0,
	};

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_prlimit_for_subject(&args),
			(long)-EACCES);
}


static void pkm_kunit_perf_event_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_perf_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_perf_event_for_subject(&args),
			0L);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_perf_event_denied_by_process_sd(struct kunit *test)
{
	struct pkm_kacs_kunit_process_perf_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_perf_event_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_perf_event_debug_bypasses_process_sd_only(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_perf_check_args args = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_DEBUG_PRIVILEGE |
			PKM_KUNIT_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_perf_event_for_subject(&args),
			0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used | PKM_KUNIT_SE_DEBUG_PRIVILEGE |
				PKM_KUNIT_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_perf_event_debug_still_fails_on_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_perf_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_DEBUG_PRIVILEGE |
			PKM_KUNIT_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_perf_event_for_subject(&args),
			(long)-EACCES);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_perf_event_requires_profile_privilege(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_perf_check_args args = { };
	const void *subject_token;
	const void *target_token;
	const u8 *process_sd;
	size_t process_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(target_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_perf_event_for_subject(&args),
			(long)-EPERM);

	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_perf_event_self_target_bypasses_boundary_gate(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_perf_check_args args = { };
	const void *subject_token;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_PROFILE_SINGLE_PROCESS_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	args.subject_token = subject_token;
	args.self_target = 1;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_perf_event_for_subject(&args),
			0L);

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_perf_event_null_args_fail_closed(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_perf_event_for_subject(NULL),
			(long)-EINVAL);
}


static void pkm_kunit_set_file_sd_cached_success(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.cached_granted_access = KACS_ACCESS_WRITE_DAC,
		.file_mode = FMODE_READ,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_default_file_sd(subject_token,
							  &target_file_sd_len);
	input_sd = pkm_kunit_create_query_only_file_sd(subject_token,
						      &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_cached_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
}


static void pkm_kunit_set_file_sd_write_failure_preserves_cache(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.cached_granted_access = KACS_ACCESS_WRITE_DAC,
		.file_mode = FMODE_READ,
		.fail_xattr_write = 1,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_default_file_sd(subject_token,
							  &target_file_sd_len);
	input_sd = pkm_kunit_create_query_only_file_sd(subject_token,
						      &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_cached_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EIO);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				target_file_sd, target_file_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
}


static void pkm_kunit_set_file_sd_cached_sacl_uses_cached_access(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
		.file_mode = FMODE_READ,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_file_sd = pkm_kunit_create_default_file_sd(target_token,
							  &target_file_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_cached_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	args.cached_granted_access = KACS_ACCESS_ACCESS_SYSTEM_SECURITY;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_cached_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_unmanaged_mount_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_default_file_sd(subject_token,
							  &target_file_sd_len);
	input_sd = pkm_kunit_create_query_only_file_sd(subject_token,
						      &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_on_mount_for_subject(
				&args, PROC_SUPER_MAGIC),
			(long)-EOPNOTSUPP);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
}


static void pkm_kunit_set_file_sd_dacl_success(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_default_file_sd(subject_token,
							  &target_file_sd_len);
	input_sd = pkm_kunit_create_query_only_file_sd(subject_token,
						      &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
}


static void pkm_kunit_set_path_file_sd_dacl_success(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_default_file_sd(subject_token,
							  &target_file_sd_len);
	input_sd = pkm_kunit_create_query_only_file_sd(subject_token,
						      &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_path_file_sd_on_mount_for_subject(
				&args, TMPFS_MAGIC, 0),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_merge_file_sd(
				subject_token, target_file_sd,
				target_file_sd_len, args.security_info,
				input_sd, input_sd_len, &result_sd,
				&result_sd_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
}


static void pkm_kunit_set_path_file_sd_unmanaged_mount_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.mount_policy_override = KACS_MOUNT_POLICY_UNMANAGED,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_default_file_sd(subject_token,
							  &target_file_sd_len);
	input_sd = pkm_kunit_create_query_only_file_sd(subject_token,
						      &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_path_file_sd_on_mount_for_subject(
				&args, TMPFS_MAGIC, 0),
			(long)-EOPNOTSUPP);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
}


static void pkm_kunit_set_file_sd_dacl_denied_without_write_dac(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_file_sd = pkm_kunit_create_query_only_file_sd(target_token,
							     &target_file_sd_len);
	input_sd = pkm_kunit_create_query_only_file_sd(target_token,
						      &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_dacl_preserves_opaque_ace(
	struct kunit *test)
{
	const void *subject_token;
	const u8 *current_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *source_ace;
	const u8 *actual_ace;
	size_t current_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	u16 source_ace_len;
	u16 actual_ace_len;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	current_sd = pkm_kunit_create_default_file_sd(subject_token,
						      &current_sd_len);
	input_sd = pkm_kunit_create_default_file_sd(subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, current_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	pkm_kunit_make_first_file_ace_opaque(
		(u8 *)input_sd,
		PKM_KUNIT_CONTAINER_INHERIT_ACE | PKM_KUNIT_INHERITED_ACE);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_merge_file_sd(
				subject_token, current_sd, current_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);

	source_ace = pkm_kunit_first_dacl_ace_const(input_sd);
	actual_ace = pkm_kunit_first_dacl_ace_const(result_sd);
	KUNIT_ASSERT_NOT_NULL(test, source_ace);
	KUNIT_ASSERT_NOT_NULL(test, actual_ace);
	source_ace_len = pkm_kunit_read_u16(source_ace, 2);
	actual_ace_len = pkm_kunit_read_u16(actual_ace, 2);
	pkm_kunit_expect_bytes_eq(test, actual_ace, actual_ace_len,
				  source_ace, source_ace_len);

	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)current_sd);
}


static void pkm_kunit_set_file_sd_sacl_denied_without_security(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_file_sd = pkm_kunit_create_default_file_sd(target_token,
							  &target_file_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_sacl_with_security_succeeds(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	target_file_sd = pkm_kunit_create_default_file_sd(target_token,
							  &target_file_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_SECURITY_PRIVILEGE);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_sacl_removal_success(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_labeled_audit_file_sd(
		subject_token, PKM_KUNIT_IL_HIGH, &target_file_sd_len);
	input_sd = pkm_kunit_create_default_file_sd(subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, actual_subset);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(actual_subset, 12), 0U);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
}


static void pkm_kunit_set_file_sd_label_removal_preserves_non_label_sacl(
	struct kunit *test)
{
	static const u8 expected_audit_ace[] = {
		2, 64, 20, 0, 0, 0, 0, 1,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_LABEL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *sacl_subset = NULL;
	const u8 *label_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t sacl_subset_len = 0;
	size_t label_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_RELABEL_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_labeled_audit_file_sd(
		subject_token, PKM_KUNIT_IL_HIGH, &target_file_sd_len);
	input_sd = pkm_kunit_create_default_file_sd(subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&sacl_subset, &sacl_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION,
				&label_subset, &label_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, sacl_subset);
	KUNIT_ASSERT_NOT_NULL(test, label_subset);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(
				  sacl_subset, sacl_subset_len,
				  expected_audit_ace,
				  sizeof(expected_audit_ace)));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(label_subset, 12), 0U);

	pkm_kacs_free((void *)label_subset);
	pkm_kacs_free((void *)sacl_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_sacl_audit_emits_kmes(struct kunit *test)
{
	static const u8 expected_ace[] = {
		2, 64, 20, 0, 0, 0, 0, 1,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.target_file_sd_ptr = pkm_kunit_system_read_audit_sd,
		.target_file_sd_len = sizeof(pkm_kunit_system_read_audit_sd),
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
		.cached_granted_access = KACS_ACCESS_ACCESS_SYSTEM_SECURITY,
		.file_mode = FMODE_READ,
	};
	u8 *buffer;
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	const void *subject_token;
	const u8 *input_sd = NULL;
	const u8 *result_sd = NULL;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t written = 0;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	input_sd = pkm_kunit_system_set_sd_audit_sd;
	input_sd_len = sizeof(pkm_kunit_system_set_sd_audit_sd);
	args.subject_token = subject_token;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4105, PKM_KUNIT_KMES_PROCESS_NAME,
				PKM_KUNIT_KMES_PROCESS_PATH),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_cached_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_expect_access_audit_schema(
				  test, &view,
				  KACS_ACCESS_ACCESS_SYSTEM_SECURITY,
				  KACS_ACCESS_ACCESS_SYSTEM_SECURITY, true,
				  "sacl", expected_ace,
				  sizeof(expected_ace)));

	pkm_kacs_free((void *)result_sd);
}


static void pkm_kunit_set_file_sd_sacl_audit_unmatched_no_event(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.target_file_sd_ptr = pkm_kunit_system_read_audit_sd,
		.target_file_sd_len = sizeof(pkm_kunit_system_read_audit_sd),
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
		.cached_granted_access = KACS_ACCESS_ACCESS_SYSTEM_SECURITY,
		.file_mode = FMODE_READ,
	};
	struct pkm_kmes_kunit_snapshot snapshot = { };
	const void *subject_token;
	const u8 *result_sd = NULL;
	size_t result_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	args.subject_token = subject_token;
	args.input_sd_ptr = pkm_kunit_system_file_read_audit_sd;
	args.input_sd_len = sizeof(pkm_kunit_system_file_read_audit_sd);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_cached_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_EXPECT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			-ENOENT);

	pkm_kacs_free((void *)result_sd);
}


static void pkm_kunit_set_file_sd_missing_restore_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_MISSING,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION |
				 PKM_KUNIT_GROUP_SECURITY_INFORMATION |
				 PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_RESTORE_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	input_sd = pkm_kunit_create_default_file_sd(target_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	pkm_kunit_set_sd_rm_control((u8 *)input_sd, 0x6b);
	args.subject_token = subject_token;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len, args.security_info,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, result_sd_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(result_sd, expected_subset, result_sd_len), 0);
	pkm_kunit_expect_sd_rm_control(test, result_sd, 0x6b);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_RESTORE_PRIVILEGE);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_opath_missing_restore_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_MISSING,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION |
				 PKM_KUNIT_GROUP_SECURITY_INFORMATION |
				 PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.file_mode = FMODE_PATH,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_RESTORE_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	input_sd = pkm_kunit_create_default_file_sd(target_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_cached_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len, args.security_info,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len, args.security_info,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_RESTORE_PRIVILEGE);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_missing_restore_accepts_null_group(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_MISSING,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION |
				 PKM_KUNIT_GROUP_SECURITY_INFORMATION |
				 PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_RESTORE_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	input_sd = pkm_kunit_create_default_file_sd(target_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	pkm_kunit_make_sd_groupless((u8 *)input_sd);

	args.subject_token = subject_token;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(result_sd, 4), 20U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(result_sd, 8), 0U);
	KUNIT_EXPECT_NE(test, pkm_kunit_read_u32(result_sd, 16), 0U);

	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_corrupt_restore_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_CORRUPT,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION |
				 PKM_KUNIT_GROUP_SECURITY_INFORMATION |
				 PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_RESTORE_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	input_sd = pkm_kunit_create_default_file_sd(target_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len, args.security_info,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, result_sd_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(result_sd, expected_subset, result_sd_len), 0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_RESTORE_PRIVILEGE);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_owner_self_success(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_default_file_sd(subject_token,
							  &target_file_sd_len);
	input_sd = pkm_kunit_create_default_file_sd(subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
}


static void pkm_kunit_set_file_sd_owner_group_owner_success(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
	};
	u8 input_sd[64] = { };
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_default_file_sd(subject_token,
							  &target_file_sd_len);
	input_sd_len = pkm_kunit_build_owner_subset_sd(
		input_sd, sizeof(input_sd), pkm_kunit_administrators_sid,
		sizeof(pkm_kunit_administrators_sid));
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_GT(test, (long)input_sd_len, 0L);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)target_file_sd);
}


static void pkm_kunit_set_file_sd_owner_foreign_denied(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *foreign_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	foreign_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, foreign_token);

	target_file_sd = pkm_kunit_create_default_file_sd(subject_token,
							  &target_file_sd_len);
	input_sd = pkm_kunit_create_default_file_sd(foreign_token,
						    &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_owner_take_ownership_self_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 input_sd[64] = { };
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_TAKE_OWNERSHIP_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	target_file_sd = pkm_kunit_create_default_file_sd(target_token,
							  &target_file_sd_len);
	input_sd_len = pkm_kunit_build_owner_subset_sd(
		input_sd, sizeof(input_sd), pkm_kunit_local_service_sid,
		sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_GT(test, (long)input_sd_len, 0L);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_TAKE_OWNERSHIP_PRIVILEGE);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_owner_null_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_default_file_sd(subject_token,
							  &target_file_sd_len);
	input_sd = pkm_kunit_create_default_file_sd(subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	pkm_kunit_make_sd_ownerless((u8 *)input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
}


static void pkm_kunit_set_file_sd_group_null_success(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_GROUP_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_default_file_sd(subject_token,
							  &target_file_sd_len);
	input_sd = pkm_kunit_create_default_file_sd(subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	pkm_kunit_make_sd_groupless((u8 *)input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_GROUP_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, actual_subset);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(actual_subset, 8), 0U);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
}


static void pkm_kunit_set_file_sd_owner_restore_arbitrary_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 input_sd[64] = { };
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_RESTORE_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	target_file_sd = pkm_kunit_create_default_file_sd(target_token,
							  &target_file_sd_len);
	input_sd_len = pkm_kunit_build_owner_subset_sd(
		input_sd, sizeof(input_sd), pkm_kunit_anonymous_sid,
		sizeof(pkm_kunit_anonymous_sid));
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_GT(test, (long)input_sd_len, 0L);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_RESTORE_PRIVILEGE);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_cached_file_sd_restore_owner_no_effect(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
		.cached_granted_access = KACS_ACCESS_WRITE_OWNER,
		.file_mode = FMODE_READ,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 input_sd[64] = { };
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *result_sd = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_RESTORE_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	target_file_sd = pkm_kunit_create_default_file_sd(target_token,
							  &target_file_sd_len);
	input_sd_len = pkm_kunit_build_owner_subset_sd(
		input_sd, sizeof(input_sd), pkm_kunit_anonymous_sid,
		sizeof(pkm_kunit_anonymous_sid));
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_GT(test, (long)input_sd_len, 0L);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_cached_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);

	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_label_requires_relabel(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_LABEL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_file_sd = pkm_kunit_create_default_file_sd(target_token,
							  &target_file_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_sacl_label_requires_relabel(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	/*
	 * KC-13: a full SACL write carrying a SYSTEM_MANDATORY_LABEL_ACE that
	 * raises integrity above the subject's own level must require
	 * SE_RELABEL_PRIVILEGE, just like the dedicated LABEL path. The subject
	 * holds SE_SECURITY_PRIVILEGE (so it is authorized to write the SACL at
	 * all, ACCESS_SYSTEM_SECURITY) but NOT SE_RELABEL_PRIVILEGE, so a HIGH
	 * label smuggled through the SACL must be rejected by the relabel gate.
	 */
	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_file_sd = pkm_kunit_create_default_file_sd(target_token,
							  &target_file_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_sacl_label_with_privilege_succeeds(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	/*
	 * Companion to the requires_relabel test: with SE_SECURITY_PRIVILEGE
	 * (authorizes the SACL write) AND SE_RELABEL_PRIVILEGE (authorizes the
	 * label raise) the same HIGH-label SACL write must succeed, confirming the
	 * gate is the relabel privilege rather than a structural rejection.
	 */
	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE | PKM_KUNIT_SE_RELABEL_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_file_sd = pkm_kunit_create_default_file_sd(target_token,
							  &target_file_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);

	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_label_with_privilege_succeeds(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_LABEL_SECURITY_INFORMATION,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
		PKM_KUNIT_SE_RELABEL_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	target_file_sd = pkm_kunit_create_default_file_sd(target_token,
							  &target_file_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_RELABEL_PRIVILEGE);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_dacl_denied_by_mic(struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_LOW, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_labeled_file_sd(
		subject_token, PKM_KUNIT_IL_HIGH, &target_file_sd_len);
	input_sd = pkm_kunit_create_default_file_sd(subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_dacl_pip_context_enforced(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
		.target_file_sd_ptr = pkm_kunit_system_pip_sd,
		.target_file_sd_len = sizeof(pkm_kunit_system_pip_sd),
	};
	const void *subject_token;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	u32 old_pip_type = 0;
	u32 old_pip_trust = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	input_sd = pkm_kunit_create_default_file_sd(subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_current_pip_context(&old_pip_type,
						     &old_pip_trust),
			0);

	pkm_kacs_kunit_set_current_pip_context(0, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_kunit_set_current_pip_context(PKM_KUNIT_PIP_TYPE_PROTECTED,
					       PKM_KUNIT_PIP_TRUST_TEST);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_EXPECT_NOT_NULL(test, result_sd);
	KUNIT_EXPECT_GT(test, (long)result_sd_len, 0L);

	pkm_kacs_kunit_set_current_pip_context(old_pip_type, old_pip_trust);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
}


static void pkm_kunit_set_file_sd_sacl_label_combo_invalid(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION |
				 PKM_KUNIT_LABEL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_file_sd = pkm_kunit_create_default_file_sd(subject_token,
							  &target_file_sd_len);
	input_sd = pkm_kunit_create_default_file_sd(subject_token,
						    &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EINVAL);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
}


static void pkm_kunit_set_file_sd_mandatory_resource_attr_protected(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_file_sd =
		pkm_kunit_create_file_sd_with_mandatory_resource_attr(
			target_token, &target_file_sd_len);
	input_sd = pkm_kunit_create_default_file_sd(target_token,
						    &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_mandatory_resource_attr_modify_denied(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_file_sd =
		pkm_kunit_create_file_sd_with_mandatory_resource_attr_value(
			target_token, 1, &target_file_sd_len);
	input_sd =
		pkm_kunit_create_file_sd_with_mandatory_resource_attr_value(
			target_token, 2, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_mandatory_resource_attr_tcb_allows(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE |
			PKM_KUNIT_SE_TCB_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	target_file_sd =
		pkm_kunit_create_file_sd_with_mandatory_resource_attr(
			target_token, &target_file_sd_len);
	input_sd = pkm_kunit_create_default_file_sd(target_token,
						    &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used & PKM_KUNIT_SE_TCB_PRIVILEGE,
			PKM_KUNIT_SE_TCB_PRIVILEGE);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_process_sd_resolver_accepts_pidfd_empty_path(
	struct kunit *test)
{
	bool self_target = false;
	int fd;

	fd = pkm_kunit_open_current_pidfd();
	KUNIT_ASSERT_GE(test, fd, 0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_resolve_process_sd_pidfd_target(
				fd, "", AT_EMPTY_PATH, &self_target),
			0L);
	KUNIT_EXPECT_TRUE(test, self_target);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_process_sd_resolver_accepts_pidfd_nofollow(
	struct kunit *test)
{
	bool self_target = false;
	int fd;

	fd = pkm_kunit_open_current_pidfd();
	KUNIT_ASSERT_GE(test, fd, 0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_resolve_process_sd_pidfd_target(
				fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
				&self_target),
			0L);
	KUNIT_EXPECT_TRUE(test, self_target);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_process_sd_resolver_rejects_missing_empty_path(
	struct kunit *test)
{
	bool self_target = true;
	int fd;

	fd = pkm_kunit_open_current_pidfd();
	KUNIT_ASSERT_GE(test, fd, 0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_resolve_process_sd_pidfd_target(
				fd, "", 0, &self_target),
			(long)-EOPNOTSUPP);
	KUNIT_EXPECT_FALSE(test, self_target);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_process_sd_resolver_rejects_nonempty_path(
	struct kunit *test)
{
	bool self_target = true;
	int fd;

	fd = pkm_kunit_open_current_pidfd();
	KUNIT_ASSERT_GE(test, fd, 0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_resolve_process_sd_pidfd_target(
				fd, "x", AT_EMPTY_PATH, &self_target),
			(long)-EOPNOTSUPP);
	KUNIT_EXPECT_FALSE(test, self_target);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_process_sd_resolver_rejects_unknown_flags(
	struct kunit *test)
{
	bool self_target = true;
	int fd;

	fd = pkm_kunit_open_current_pidfd();
	KUNIT_ASSERT_GE(test, fd, 0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_resolve_process_sd_pidfd_target(
				fd, "", AT_EMPTY_PATH | 0x80000000U,
				&self_target),
			(long)-EINVAL);
	KUNIT_EXPECT_FALSE(test, self_target);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_process_sd_resolver_rejects_non_pidfd(
	struct kunit *test)
{
	bool self_target = true;
	int fd;

	fd = anon_inode_getfd("pkm-kunit-not-process",
			      &pkm_kunit_non_process_fops, NULL, O_CLOEXEC);
	KUNIT_ASSERT_GE(test, fd, 0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_resolve_process_sd_pidfd_target(
				fd, "", AT_EMPTY_PATH, &self_target),
			(long)-EOPNOTSUPP);
	KUNIT_EXPECT_FALSE(test, self_target);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_process_state_fork_under_impersonation_uses_primary_sd(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot primary_snapshot = { };
	struct pkm_kacs_boot_snapshot effective_snapshot = { };
	struct pkm_kacs_kunit_process_state_view child_view = { };
	const void *primary_token;
	const void *client_token;
	const void *child_state;
	const u8 *child_sd;
	u32 owner_offset;
	long fd;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(primary_token,
							 &primary_snapshot));

	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_impersonate((int)fd,
							   primary_token),
			0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  pkm_kacs_current_effective_token_ptr(),
				  &effective_snapshot));
	KUNIT_EXPECT_TRUE(test,
			  effective_snapshot.token_ptr !=
				  primary_snapshot.token_ptr);
	KUNIT_EXPECT_EQ(test, effective_snapshot.user_sid_len,
			primary_snapshot.user_sid_len);
	KUNIT_EXPECT_NE(test,
			memcmp(effective_snapshot.user_sid_ptr,
			       primary_snapshot.user_sid_ptr,
			       primary_snapshot.user_sid_len),
			0);

	child_state = pkm_kacs_kunit_inherit_current_process_state(0);
	KUNIT_ASSERT_NOT_NULL(test, child_state);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(child_state,
							      &child_view),
			0);
	child_sd = child_view.process_sd_ptr;
	KUNIT_ASSERT_NOT_NULL(test, child_sd);
	KUNIT_ASSERT_GT(test, (long)child_view.process_sd_len, 20L);
	pkm_kunit_expect_default_process_sd_shape(test, child_sd,
						  child_view.process_sd_len,
						  &primary_snapshot);

	owner_offset = pkm_kunit_read_u32(child_sd, 4);
	KUNIT_ASSERT_LE(test,
			(size_t)owner_offset + effective_snapshot.user_sid_len,
			child_view.process_sd_len);
	KUNIT_EXPECT_NE(test,
			memcmp(child_sd + owner_offset,
			       effective_snapshot.user_sid_ptr,
			       effective_snapshot.user_sid_len),
			0);

	pkm_kacs_kunit_put_process_state(child_state);
	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_set_process_sd_dacl_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_process_sd = kacs_rust_create_default_process_sd(subject_token,
								&target_process_sd_len);
	input_sd = kacs_rust_kunit_create_query_limited_process_sd(
		subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	pkm_kunit_set_sd_rm_control((u8 *)target_process_sd, 0x7c);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	pkm_kunit_set_sd_rm_control((u8 *)expected_subset, 0x7c);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);
	pkm_kunit_expect_sd_rm_control(test, result_sd, 0x7c);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
}


static void pkm_kunit_set_process_sd_dacl_denied_without_write_dac(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &target_process_sd_len);
	input_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_process_sd_sacl_denied_without_security(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_process_sd = kacs_rust_create_default_process_sd(
		target_token, &target_process_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_process_sd_sacl_with_security_succeeds(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	target_process_sd = kacs_rust_create_default_process_sd(
		target_token, &target_process_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_SECURITY_PRIVILEGE);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_file_sd_mandatory_resource_attr_tcb_modifies(
	struct kunit *test)
{
	struct pkm_kacs_kunit_file_sd_set_args args = {
		.target_file_sd_state = PKM_KACS_KUNIT_FILE_SD_VALID,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_file_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_file_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE |
			PKM_KUNIT_SE_TCB_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_file_sd =
		pkm_kunit_create_file_sd_with_mandatory_resource_attr_value(
			target_token, 1, &target_file_sd_len);
	input_sd =
		pkm_kunit_create_file_sd_with_mandatory_resource_attr_value(
			target_token, 2, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_file_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_file_sd_ptr = target_file_sd;
	args.target_file_sd_len = target_file_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_file_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_file_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_file_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_process_sd_owner_self_success(struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_process_sd = kacs_rust_create_default_process_sd(subject_token,
								&target_process_sd_len);
	input_sd = kacs_rust_create_default_process_sd(subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
}


static void pkm_kunit_set_process_sd_owner_group_owner_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
	};
	u8 input_sd[64] = { };
	const void *subject_token;
	const u8 *target_process_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_process_sd = kacs_rust_create_default_process_sd(
		subject_token, &target_process_sd_len);
	input_sd_len = pkm_kunit_build_owner_subset_sd(
		input_sd, sizeof(input_sd), pkm_kunit_administrators_sid,
		sizeof(pkm_kunit_administrators_sid));
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_GT(test, (long)input_sd_len, 0L);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)target_process_sd);
}


static void pkm_kunit_set_process_sd_owner_foreign_denied(struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *foreign_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	foreign_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, foreign_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_process_sd = kacs_rust_create_default_process_sd(target_token,
								&target_process_sd_len);
	input_sd = kacs_rust_create_default_process_sd(foreign_token,
						       &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(foreign_token);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_process_sd_owner_restore_arbitrary_success(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_OWNER_SECURITY_INFORMATION,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 input_sd[64] = { };
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_RESTORE_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	target_process_sd = kacs_rust_create_default_process_sd(
		target_token, &target_process_sd_len);
	input_sd_len = pkm_kunit_build_owner_subset_sd(
		input_sd, sizeof(input_sd), pkm_kunit_anonymous_sid,
		sizeof(pkm_kunit_anonymous_sid));
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_GT(test, (long)input_sd_len, 0L);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_RESTORE_PRIVILEGE);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_process_sd_label_requires_relabel(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_LABEL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0, 0);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_process_sd = kacs_rust_create_default_process_sd(target_token,
								&target_process_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_process_sd_label_with_privilege_succeeds(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_LABEL_SECURITY_INFORMATION,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const u8 *actual_subset = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	size_t actual_subset_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
		PKM_KUNIT_SE_RELABEL_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	target_process_sd = kacs_rust_create_default_process_sd(target_token,
								&target_process_sd_len);
	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				result_sd, result_sd_len,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION,
				&actual_subset, &actual_subset_len),
			0);
	KUNIT_EXPECT_EQ(test, actual_subset_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(actual_subset, expected_subset, actual_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_RELABEL_PRIVILEGE);

	pkm_kacs_free((void *)actual_subset);
	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_process_sd_cross_process_denied_by_pip(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.security_info = PKM_KUNIT_DACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_process_sd = kacs_rust_create_default_process_sd(target_token,
								&target_process_sd_len);
	input_sd = kacs_rust_kunit_create_query_limited_process_sd(
		target_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;
	args.target_pip_type = PKM_KUNIT_PIP_TYPE_PROTECTED;
	args.target_pip_trust = PKM_KUNIT_PIP_TRUST_TEST;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
}


static void pkm_kunit_set_process_sd_sacl_label_combo_invalid(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION |
				 PKM_KUNIT_LABEL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_process_sd = kacs_rust_create_default_process_sd(subject_token,
								&target_process_sd_len);
	input_sd = kacs_rust_create_default_process_sd(subject_token, &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EINVAL);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
}


static void pkm_kunit_set_process_sd_mandatory_resource_attr_protected(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_sd_set_args args = {
		.self_target = 1,
		.security_info = PKM_KUNIT_SACL_SECURITY_INFORMATION,
	};
	const void *subject_token;
	const void *target_token;
	const u8 *target_process_sd;
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	size_t target_process_sd_len = 0;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE);
	target_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	target_process_sd =
		kacs_rust_kunit_create_process_sd_with_mandatory_resource_attr(
			target_token, &target_process_sd_len);
	input_sd = kacs_rust_create_default_process_sd(target_token,
						       &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, target_process_sd);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	args.subject_token = subject_token;
	args.target_process_sd_ptr = target_process_sd;
	args.target_process_sd_len = target_process_sd_len;
	args.input_sd_ptr = input_sd;
	args.input_sd_len = input_sd_len;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_process_sd_for_subject(
				&args, &result_sd, &result_sd_len),
			(long)-EACCES);

	pkm_kacs_free((void *)input_sd);
	pkm_kacs_free((void *)target_process_sd);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_token_sd_dacl_success(struct kunit *test)
{
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const void *subject_token;
	const void *target_token;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	long token_fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	input_sd = kacs_rust_kunit_create_query_only_token_sd(&input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_DACL_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_NOT_NULL(test, expected_subset);
	KUNIT_EXPECT_EQ(test, result_sd_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(result_sd, expected_subset, result_sd_len), 0);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_set_token_sd_dacl_denied_without_write_dac(
	struct kunit *test)
{
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const void *subject_token;
	const void *target_token;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	long token_fd;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		pkm_kacs_current_effective_token_ptr(), target_token,
		KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	input_sd = kacs_rust_kunit_create_query_only_token_sd(&input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_DACL_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_token_sd_sacl_denied_without_security(
	struct kunit *test)
{
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const void *subject_token;
	const void *target_token;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	long token_fd;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		pkm_kacs_current_effective_token_ptr(), target_token,
		KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_SACL_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_token_sd_sacl_with_security_succeeds(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const void *subject_token;
	const void *target_token;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	long token_fd;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_SECURITY_PRIVILEGE);
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		pkm_kacs_current_effective_token_ptr(), target_token,
		KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_SACL_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_SACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_NOT_NULL(test, expected_subset);
	KUNIT_EXPECT_EQ(test, result_sd_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(result_sd, expected_subset, result_sd_len), 0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_SECURITY_PRIVILEGE);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_token_sd_owner_self_success(struct kunit *test)
{
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const void *subject_token;
	const void *target_token;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	long token_fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	input_sd = kacs_rust_create_default_process_sd(subject_token,
						       &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_NOT_NULL(test, expected_subset);
	KUNIT_EXPECT_EQ(test, result_sd_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(result_sd, expected_subset, result_sd_len), 0);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_set_token_sd_owner_group_owner_success(struct kunit *test)
{
	u8 input_sd[64] = { };
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const void *subject_token;
	const void *target_token;
	size_t input_sd_len;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	long token_fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	input_sd_len = pkm_kunit_build_owner_subset_sd(
		input_sd, sizeof(input_sd), pkm_kunit_administrators_sid,
		sizeof(pkm_kunit_administrators_sid));
	KUNIT_ASSERT_GT(test, (long)input_sd_len, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_NOT_NULL(test, expected_subset);
	KUNIT_EXPECT_EQ(test, result_sd_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(result_sd, expected_subset, result_sd_len), 0);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_set_token_sd_owner_foreign_denied(struct kunit *test)
{
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const void *subject_token;
	const void *foreign_token;
	const void *target_token;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	long token_fd;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	foreign_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, foreign_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		pkm_kacs_current_effective_token_ptr(), target_token,
		KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	input_sd = kacs_rust_create_default_process_sd(foreign_token,
						       &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
	kacs_rust_token_drop(foreign_token);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_token_sd_owner_restore_arbitrary_success(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 input_sd[64] = { };
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const void *subject_token;
	const void *target_token;
	size_t input_sd_len;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	long token_fd;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_RESTORE_PRIVILEGE);
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		pkm_kacs_current_effective_token_ptr(), target_token,
		KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	input_sd_len = pkm_kunit_build_owner_subset_sd(
		input_sd, sizeof(input_sd), pkm_kunit_anonymous_sid,
		sizeof(pkm_kunit_anonymous_sid));
	KUNIT_ASSERT_GT(test, (long)input_sd_len, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_OWNER_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_ASSERT_NOT_NULL(test, result_sd);
	KUNIT_ASSERT_NOT_NULL(test, expected_subset);
	KUNIT_EXPECT_EQ(test, result_sd_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(result_sd, expected_subset, result_sd_len), 0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_RESTORE_PRIVILEGE);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_token_sd_label_requires_relabel(
	struct kunit *test)
{
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const void *subject_token;
	const void *target_token;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	long token_fd;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0, 0);
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		pkm_kacs_current_effective_token_ptr(), target_token,
		KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			(long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, result_sd, NULL);
	KUNIT_EXPECT_EQ(test, result_sd_len, (size_t)0);

	pkm_kacs_free((void *)input_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_token_sd_label_with_privilege_succeeds(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const void *subject_token;
	const void *target_token;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	long token_fd;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
		PKM_KUNIT_SE_RELABEL_PRIVILEGE);
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		pkm_kacs_current_effective_token_ptr(), target_token,
		KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	input_sd = kacs_rust_kunit_create_label_sd_subset(PKM_KUNIT_IL_HIGH,
							  &input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_LABEL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, result_sd_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(result_sd, expected_subset, result_sd_len), 0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_RELABEL_PRIVILEGE);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_token_sd_restore_bypasses_access_check(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const u8 *input_sd;
	const u8 *result_sd = NULL;
	const u8 *expected_subset = NULL;
	const void *subject_token;
	const void *target_token;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	size_t expected_subset_len = 0;
	long token_fd;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_RESTORE_PRIVILEGE);
	target_token = kacs_rust_token_deep_copy(
		pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &before));

	token_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		pkm_kacs_current_effective_token_ptr(), target_token,
		KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, token_fd, 0);

	input_sd = kacs_rust_kunit_create_query_only_token_sd(&input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_token_sd_for_subject(
				(int)token_fd, subject_token,
				PKM_KUNIT_DACL_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_query_process_sd_subset(
				input_sd, input_sd_len,
				PKM_KUNIT_DACL_SECURITY_INFORMATION,
				&expected_subset, &expected_subset_len),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token, &after));
	KUNIT_EXPECT_EQ(test, result_sd_len, expected_subset_len);
	KUNIT_EXPECT_EQ(test,
			memcmp(result_sd, expected_subset, result_sd_len), 0);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_RESTORE_PRIVILEGE);

	pkm_kacs_free((void *)expected_subset);
	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(target_token);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_set_caap_public_installs_and_marks_tcb_used(
	struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	struct pkm_kacs_boot_snapshot after = { };
	const void *token;

	token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);

	spec_len = pkm_kunit_build_caap_spec(
		spec, pkm_kunit_caap_system_read_dacl,
		sizeof(pkm_kunit_caap_system_read_dacl));
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_caap_for_token(
				token, pkm_kunit_caap_policy_sid,
				sizeof(pkm_kunit_caap_policy_sid), spec,
				(u32)spec_len),
			0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)1);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used & PKM_KUNIT_SE_TCB_PRIVILEGE,
			PKM_KUNIT_SE_TCB_PRIVILEGE);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}


static void pkm_kunit_set_caap_public_denies_without_tcb(struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	const void *token;

	token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);

	spec_len = pkm_kunit_build_caap_spec(
		spec, pkm_kunit_caap_system_read_dacl,
		sizeof(pkm_kunit_caap_system_read_dacl));
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_caap_for_token(
				token, pkm_kunit_caap_policy_sid,
				sizeof(pkm_kunit_caap_policy_sid), spec,
				(u32)spec_len),
			-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)0);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_set_caap_public_checks_tcb_before_usercopy(
	struct kunit *test)
{
	const void *token;

	token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_caap_user_for_token(
				token, (const void __user *)1,
				sizeof(pkm_kunit_caap_policy_sid),
				(const void __user *)1, 16),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)0);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_set_caap_public_rejects_sid_bounds_before_copy(
	struct kunit *test)
{
	const void *token;

	token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_caap_user_for_token(
				token, (const void __user *)1, 7, NULL, 0),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_caap_user_for_token(
				token, (const void __user *)1, 69,
				NULL, 0),
			(long)-EINVAL);
}


static void pkm_kunit_set_caap_public_malformed_keeps_old_policy(
	struct kunit *test)
{
	u8 spec[64];
	size_t spec_len;
	u32 granted = 0xffffffffU;
	const void *token;
	long ret;

	token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);

	spec_len = pkm_kunit_build_caap_spec(
		spec, pkm_kunit_caap_system_read_dacl,
		sizeof(pkm_kunit_caap_system_read_dacl));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_caap_for_token(
				token, pkm_kunit_caap_policy_sid,
				sizeof(pkm_kunit_caap_policy_sid), spec,
				(u32)spec_len),
			0);

	spec_len = pkm_kunit_build_caap_spec(spec, NULL, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_set_caap_for_token(
				token, pkm_kunit_caap_policy_sid,
				sizeof(pkm_kunit_caap_policy_sid), spec,
				(u32)spec_len),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kacs_caap_cache_len(), (size_t)1);

	ret = pkm_kunit_run_caap_access_check(&granted);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_CAAP_READ_GRANT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_set_caap_internal(pkm_kunit_caap_policy_sid,
						   sizeof(pkm_kunit_caap_policy_sid),
						   NULL, 0),
			0);
}

static struct kunit_case pkm_kunit_process_cases[] = {
	KUNIT_CASE(pkm_kunit_capget_reports_allow_substrate),
	KUNIT_CASE(pkm_kunit_capget_preserves_non_allow_compat_bits),
	KUNIT_CASE(pkm_kunit_capget_cross_process_success),
	KUNIT_CASE(pkm_kunit_capget_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_capget_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_capget_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_capget_self_target_bypasses_boundary_gate),
	KUNIT_CASE(pkm_kunit_capget_null_args_fail_closed),
	KUNIT_CASE(pkm_kunit_proc_status_caps_report_allow_substrate),
	KUNIT_CASE(pkm_kunit_proc_status_caps_preserve_non_allow_and_ambient),
	KUNIT_CASE(pkm_kunit_proc_status_caps_null_args_fail_closed),
	KUNIT_CASE(pkm_kunit_capability_allow_succeeds_without_privilege),
	KUNIT_CASE(pkm_kunit_capability_privilege_success_marks_used),
	KUNIT_CASE(pkm_kunit_remote_shutdown_denies_without_remote_privilege),
	KUNIT_CASE(pkm_kunit_remote_shutdown_denies_without_shutdown_privilege),
	KUNIT_CASE(pkm_kunit_remote_shutdown_success_requires_both_privileges),
	KUNIT_CASE(pkm_kunit_capability_privilege_mapping_matrix),
	KUNIT_CASE(pkm_kunit_capability_switchboard_full_matrix),
	KUNIT_CASE(pkm_kunit_capability_privilege_denied_without_privilege),
	KUNIT_CASE(pkm_kunit_capability_denied_caps_fail_closed),
	KUNIT_CASE(pkm_kunit_capability_deny_caps_matrix),
	KUNIT_CASE(pkm_kunit_capset_preserves_allow_and_rejects_clear),
	KUNIT_CASE(pkm_kunit_capset_rejects_each_allow_clear),
	KUNIT_CASE(pkm_kunit_capset_preserves_non_allow_and_repairs_bset),
	KUNIT_CASE(pkm_kunit_capset_masks_ambient_to_permitted_inheritable),
	KUNIT_CASE(pkm_kunit_capset_null_and_tokenless_fail_closed),
	KUNIT_CASE(pkm_kunit_prctl_capability_guard_rejects_allow_mutations),
	KUNIT_CASE(pkm_kunit_prctl_capability_guard_rejects_each_allow),
	KUNIT_CASE(pkm_kunit_exec_cap_reprojection_suppresses_filecap_grants),
	KUNIT_CASE(pkm_kunit_setuid_fixup_suppresses_unprivileged_change),
	KUNIT_CASE(pkm_kunit_setuid_fixup_privileged_path_fails_closed),
	KUNIT_CASE(pkm_kunit_setuid_fixup_unknown_flags_fail_closed),
	KUNIT_CASE(pkm_kunit_setgid_fixup_suppresses_unprivileged_change),
	KUNIT_CASE(pkm_kunit_setgroups_fixup_suppresses_unprivileged_change),
	KUNIT_CASE(pkm_kunit_peercred_projection_uses_token_ids),
	KUNIT_CASE(pkm_kunit_exec_setid_uid_compat_rewrites_visible_uid_only),
	KUNIT_CASE(pkm_kunit_exec_setid_gid_compat_rewrites_visible_gid_only),
	KUNIT_CASE(pkm_kunit_exec_setid_compat_rewrites_visible_uid_and_gid_only),
	KUNIT_CASE(pkm_kunit_exec_setid_without_token_fails_closed),
	KUNIT_CASE(pkm_kunit_exec_setid_privileged_path_fails_closed),
	KUNIT_CASE(pkm_kunit_exec_new_process_min_lowers_to_file_label),
	KUNIT_CASE(pkm_kunit_exec_new_process_min_unlabeled_defaults_medium),
	KUNIT_CASE(pkm_kunit_exec_new_process_min_equal_label_noops),
	KUNIT_CASE(pkm_kunit_exec_new_process_min_corrupt_sd_fails_closed),
	KUNIT_CASE(pkm_kunit_process_state_clone_thread_shares_live_object),
	KUNIT_CASE(pkm_kunit_process_state_fork_gets_fresh_sd_and_rate_bucket),
	KUNIT_CASE(pkm_kunit_process_state_fork_inherits_no_child),
	KUNIT_CASE(pkm_kunit_process_state_impersonation_preserves_psb),
	KUNIT_CASE(pkm_kunit_clone_process_impersonation_uses_primary_copy),
	KUNIT_CASE(pkm_kunit_clone_thread_impersonation_starts_on_primary),
	KUNIT_CASE(pkm_kunit_clone_thread_shared_token_mutation_visible),
	KUNIT_CASE(pkm_kunit_clone_process_deep_copy_mutation_isolated),
	KUNIT_CASE(pkm_kunit_exec_committing_reverts_impersonation),
	KUNIT_CASE(pkm_kunit_set_psb_self_supported_bits_success),
	KUNIT_CASE(pkm_kunit_set_psb_cross_process_success),
	KUNIT_CASE(pkm_kunit_set_psb_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_set_psb_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_set_psb_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_process_pip_dominance_matrix),
	KUNIT_CASE(pkm_kunit_set_psb_cfi_alias_expands),
	KUNIT_CASE(pkm_kunit_set_psb_cfi_requires_cpu_support),
	KUNIT_CASE(pkm_kunit_set_psb_tlp_lsv_supported),
	KUNIT_CASE(pkm_kunit_set_psb_activation_failure_preserves_bits),
	KUNIT_CASE(pkm_kunit_set_psb_cfif_real_activation_fails_closed),
	KUNIT_CASE(pkm_kunit_set_psb_unknown_bits_fail_closed),
	KUNIT_CASE(pkm_kunit_no_child_blocks_process_fork_only),
	KUNIT_CASE(pkm_kunit_wxp_rejects_wx_map_and_transition),
	KUNIT_CASE(pkm_kunit_tlp_cache_validation),
	KUNIT_CASE(pkm_kunit_tlp_executable_mapping_enforcement),
	KUNIT_CASE(pkm_kunit_tlp_mprotect_checks_new_exec_only),
	KUNIT_CASE(pkm_kunit_exec_pip_signed_material_sets_tcb_trust),
	KUNIT_CASE(pkm_kunit_exec_pip_bad_signature_resets_none),
	KUNIT_CASE(pkm_kunit_exec_pip_pending_is_transactional),
	KUNIT_CASE(pkm_kunit_exec_pip_unsigned_commit_clears_existing_pip),
	KUNIT_CASE(pkm_kunit_exec_commit_preserves_mitigations_and_no_child),
	KUNIT_CASE(pkm_kunit_exec_dumpable_decision_tracks_pip),
	KUNIT_CASE(pkm_kunit_exec_dumpable_signed_material_clears_if_mm),
	KUNIT_CASE(pkm_kunit_lsv_signed_tcb_allows_none_and_tcb_pip),
	KUNIT_CASE(pkm_kunit_lsv_unsigned_and_bad_signature_deny),
	KUNIT_CASE(pkm_kunit_lsv_insufficient_trust_denies),
	KUNIT_CASE(pkm_kunit_lsv_bypasses_non_exec_and_anonymous),
	KUNIT_CASE(pkm_kunit_pie_rejects_et_exec),
	KUNIT_CASE(pkm_kunit_bprm_file_execute_live_success),
	KUNIT_CASE(pkm_kunit_bprm_file_execute_live_denied_by_sd),
	KUNIT_CASE(pkm_kunit_bprm_file_execute_missing_or_corrupt_fails_closed),
	KUNIT_CASE(pkm_kunit_bprm_file_execute_unmanaged_skips_facs),
	KUNIT_CASE(pkm_kunit_task_prctl_sml_and_cfib_block_disable_paths),
	KUNIT_CASE(pkm_kunit_task_prctl_pip_blocks_dumpable_reenable),
	KUNIT_CASE(pkm_kunit_process_boundary_under_impersonation_uses_psb_pip),
	KUNIT_CASE(pkm_kunit_proc_token_inspection_query_only_success),
	KUNIT_CASE(pkm_kunit_proc_token_inspection_statistics_auth_id),
	KUNIT_CASE(pkm_kunit_proc_token_inspection_self_bypasses_process_sd),
	KUNIT_CASE(pkm_kunit_proc_token_inspection_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_proc_token_inspection_denied_by_pip),
	KUNIT_CASE(pkm_kunit_signal_terminate_success),
	KUNIT_CASE(pkm_kunit_signal_info_success),
	KUNIT_CASE(pkm_kunit_process_sd_access_uses_caller_psb_pip),
	KUNIT_CASE(pkm_kunit_signal_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_signal_suspend_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_signal_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_signal_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_signal_kernel_originated_bypasses_checks),
	KUNIT_CASE(pkm_kunit_signal_origin_classification),
	KUNIT_CASE(pkm_kunit_signal_table_exact_rights),
	KUNIT_CASE(pkm_kunit_signal_probe_query_limited_success),
	KUNIT_CASE(pkm_kunit_signal_probe_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_signal_probe_denied_by_pip),
	KUNIT_CASE(pkm_kunit_signal_invalid_fails_closed),
	KUNIT_CASE(pkm_kunit_ptrace_read_success),
	KUNIT_CASE(pkm_kunit_ptrace_attach_success),
	KUNIT_CASE(pkm_kunit_ptrace_read_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_ptrace_attach_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_ptrace_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_ptrace_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_ptrace_unknown_mode_fails_closed),
	KUNIT_CASE(pkm_kunit_ptrace_traceme_success),
	KUNIT_CASE(pkm_kunit_ptrace_traceme_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_ptrace_traceme_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_ptrace_traceme_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_ptrace_traceme_null_args_fail_closed),
	KUNIT_CASE(pkm_kunit_pidfd_getfd_success),
	KUNIT_CASE(pkm_kunit_pidfd_getfd_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_pidfd_getfd_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_pidfd_getfd_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_pidfd_open_success),
	KUNIT_CASE(pkm_kunit_pidfd_open_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_pidfd_open_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_pidfd_open_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_proc_metadata_query_limited_success),
	KUNIT_CASE(pkm_kunit_proc_metadata_query_limited_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_proc_metadata_query_information_success),
	KUNIT_CASE(pkm_kunit_proc_metadata_query_information_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_proc_metadata_debug_bypasses_limited_process_sd_only),
	KUNIT_CASE(pkm_kunit_proc_metadata_debug_bypasses_information_process_sd_only),
	KUNIT_CASE(pkm_kunit_proc_metadata_debug_limited_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_proc_metadata_debug_information_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_proc_metadata_query_mode_combo_fails_closed),
	KUNIT_CASE(pkm_kunit_setnice_success),
	KUNIT_CASE(pkm_kunit_setscheduler_success),
	KUNIT_CASE(pkm_kunit_setioprio_success),
	KUNIT_CASE(pkm_kunit_process_setinfo_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_process_setinfo_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_process_setinfo_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_process_setinfo_self_target_bypasses_boundary_gate),
	KUNIT_CASE(pkm_kunit_process_attribute_query_limited_success),
	KUNIT_CASE(pkm_kunit_process_attribute_query_information_success),
	KUNIT_CASE(pkm_kunit_process_attribute_query_limited_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_process_attribute_query_information_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_process_attribute_restrictive_sd_denies_administrator),
	KUNIT_CASE(pkm_kunit_process_attribute_setinfo_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_process_attribute_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_process_attribute_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_process_attribute_self_target_bypasses_boundary_gate),
	KUNIT_CASE(pkm_kunit_process_attribute_unknown_access_fails_closed),
	KUNIT_CASE(pkm_kunit_affinity_same_process_bypasses_boundary_gate),
	KUNIT_CASE(pkm_kunit_affinity_cross_process_success_with_privilege),
	KUNIT_CASE(pkm_kunit_affinity_cross_process_denied_without_privilege),
	KUNIT_CASE(pkm_kunit_affinity_debug_does_not_bypass_standalone_privilege),
	KUNIT_CASE(pkm_kunit_affinity_debug_plus_privilege_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_affinity_privilege_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_prlimit_read_success),
	KUNIT_CASE(pkm_kunit_prlimit_write_success),
	KUNIT_CASE(pkm_kunit_prlimit_read_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_prlimit_write_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_prlimit_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_prlimit_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_prlimit_self_target_bypasses_boundary_gate),
	KUNIT_CASE(pkm_kunit_prlimit_unknown_flags_fail_closed),
	KUNIT_CASE(pkm_kunit_perf_event_success),
	KUNIT_CASE(pkm_kunit_perf_event_denied_by_process_sd),
	KUNIT_CASE(pkm_kunit_perf_event_debug_bypasses_process_sd_only),
	KUNIT_CASE(pkm_kunit_perf_event_debug_still_fails_on_pip),
	KUNIT_CASE(pkm_kunit_perf_event_requires_profile_privilege),
	KUNIT_CASE(pkm_kunit_perf_event_self_target_bypasses_boundary_gate),
	KUNIT_CASE(pkm_kunit_perf_event_null_args_fail_closed),
	KUNIT_CASE(pkm_kunit_set_file_sd_cached_success),
	KUNIT_CASE(pkm_kunit_set_file_sd_write_failure_preserves_cache),
	KUNIT_CASE(pkm_kunit_set_file_sd_cached_sacl_uses_cached_access),
	KUNIT_CASE(pkm_kunit_set_file_sd_unmanaged_mount_fails_closed),
	KUNIT_CASE(pkm_kunit_set_file_sd_dacl_success),
	KUNIT_CASE(pkm_kunit_set_path_file_sd_dacl_success),
	KUNIT_CASE(pkm_kunit_set_path_file_sd_unmanaged_mount_fails_closed),
	KUNIT_CASE(pkm_kunit_set_file_sd_dacl_denied_without_write_dac),
	KUNIT_CASE(pkm_kunit_set_file_sd_dacl_preserves_opaque_ace),
	KUNIT_CASE(pkm_kunit_set_file_sd_sacl_denied_without_security),
	KUNIT_CASE(pkm_kunit_set_file_sd_sacl_with_security_succeeds),
	KUNIT_CASE(pkm_kunit_set_file_sd_sacl_removal_success),
	KUNIT_CASE(pkm_kunit_set_file_sd_label_removal_preserves_non_label_sacl),
	KUNIT_CASE(pkm_kunit_set_file_sd_sacl_audit_emits_kmes),
	KUNIT_CASE(pkm_kunit_set_file_sd_sacl_audit_unmatched_no_event),
	KUNIT_CASE(pkm_kunit_set_file_sd_missing_restore_success),
	KUNIT_CASE(pkm_kunit_set_file_sd_opath_missing_restore_success),
	KUNIT_CASE(pkm_kunit_set_file_sd_missing_restore_accepts_null_group),
	KUNIT_CASE(pkm_kunit_set_file_sd_corrupt_restore_success),
	KUNIT_CASE(pkm_kunit_set_file_sd_owner_self_success),
	KUNIT_CASE(pkm_kunit_set_file_sd_owner_group_owner_success),
	KUNIT_CASE(pkm_kunit_set_file_sd_owner_foreign_denied),
	KUNIT_CASE(pkm_kunit_set_file_sd_owner_take_ownership_self_success),
	KUNIT_CASE(pkm_kunit_set_file_sd_owner_null_fails_closed),
	KUNIT_CASE(pkm_kunit_set_file_sd_group_null_success),
	KUNIT_CASE(pkm_kunit_set_file_sd_owner_restore_arbitrary_success),
	KUNIT_CASE(pkm_kunit_set_cached_file_sd_restore_owner_no_effect),
	KUNIT_CASE(pkm_kunit_set_file_sd_label_requires_relabel),
	KUNIT_CASE(pkm_kunit_set_file_sd_sacl_label_requires_relabel),
	KUNIT_CASE(pkm_kunit_set_file_sd_sacl_label_with_privilege_succeeds),
	KUNIT_CASE(pkm_kunit_set_file_sd_label_with_privilege_succeeds),
	KUNIT_CASE(pkm_kunit_set_file_sd_dacl_denied_by_mic),
	KUNIT_CASE(pkm_kunit_set_file_sd_dacl_pip_context_enforced),
	KUNIT_CASE(pkm_kunit_set_file_sd_sacl_label_combo_invalid),
	KUNIT_CASE(pkm_kunit_set_file_sd_mandatory_resource_attr_protected),
	KUNIT_CASE(pkm_kunit_set_file_sd_mandatory_resource_attr_modify_denied),
	KUNIT_CASE(pkm_kunit_set_file_sd_mandatory_resource_attr_tcb_allows),
	KUNIT_CASE(pkm_kunit_process_sd_resolver_accepts_pidfd_empty_path),
	KUNIT_CASE(pkm_kunit_process_sd_resolver_accepts_pidfd_nofollow),
	KUNIT_CASE(pkm_kunit_process_sd_resolver_rejects_missing_empty_path),
	KUNIT_CASE(pkm_kunit_process_sd_resolver_rejects_nonempty_path),
	KUNIT_CASE(pkm_kunit_process_sd_resolver_rejects_unknown_flags),
	KUNIT_CASE(pkm_kunit_process_sd_resolver_rejects_non_pidfd),
	KUNIT_CASE(pkm_kunit_process_state_fork_under_impersonation_uses_primary_sd),
	KUNIT_CASE(pkm_kunit_set_process_sd_dacl_success),
	KUNIT_CASE(pkm_kunit_set_process_sd_dacl_denied_without_write_dac),
	KUNIT_CASE(pkm_kunit_set_process_sd_sacl_denied_without_security),
	KUNIT_CASE(pkm_kunit_set_process_sd_sacl_with_security_succeeds),
	KUNIT_CASE(pkm_kunit_set_file_sd_mandatory_resource_attr_tcb_modifies),
	KUNIT_CASE(pkm_kunit_set_process_sd_owner_self_success),
	KUNIT_CASE(pkm_kunit_set_process_sd_owner_group_owner_success),
	KUNIT_CASE(pkm_kunit_set_process_sd_owner_foreign_denied),
	KUNIT_CASE(pkm_kunit_set_process_sd_owner_restore_arbitrary_success),
	KUNIT_CASE(pkm_kunit_set_process_sd_label_requires_relabel),
	KUNIT_CASE(pkm_kunit_set_process_sd_label_with_privilege_succeeds),
	KUNIT_CASE(pkm_kunit_set_process_sd_cross_process_denied_by_pip),
	KUNIT_CASE(pkm_kunit_set_process_sd_sacl_label_combo_invalid),
	KUNIT_CASE(pkm_kunit_set_process_sd_mandatory_resource_attr_protected),
	KUNIT_CASE(pkm_kunit_set_token_sd_dacl_success),
	KUNIT_CASE(pkm_kunit_set_token_sd_dacl_denied_without_write_dac),
	KUNIT_CASE(pkm_kunit_set_token_sd_sacl_denied_without_security),
	KUNIT_CASE(pkm_kunit_set_token_sd_sacl_with_security_succeeds),
	KUNIT_CASE(pkm_kunit_set_token_sd_owner_self_success),
	KUNIT_CASE(pkm_kunit_set_token_sd_owner_group_owner_success),
	KUNIT_CASE(pkm_kunit_set_token_sd_owner_foreign_denied),
	KUNIT_CASE(pkm_kunit_set_token_sd_owner_restore_arbitrary_success),
	KUNIT_CASE(pkm_kunit_set_token_sd_label_requires_relabel),
	KUNIT_CASE(pkm_kunit_set_token_sd_label_with_privilege_succeeds),
	KUNIT_CASE(pkm_kunit_set_token_sd_restore_bypasses_access_check),
	KUNIT_CASE(pkm_kunit_set_caap_public_installs_and_marks_tcb_used),
	KUNIT_CASE(pkm_kunit_set_caap_public_denies_without_tcb),
	KUNIT_CASE(pkm_kunit_set_caap_public_checks_tcb_before_usercopy),
	KUNIT_CASE(pkm_kunit_set_caap_public_rejects_sid_bounds_before_copy),
	KUNIT_CASE(pkm_kunit_set_caap_public_malformed_keeps_old_policy),
	{}
};

static struct kunit_suite pkm_kunit_process_suite = {
	.name = "pkm_kunit_process",
	.test_cases = pkm_kunit_process_cases,
};

kunit_test_suite(pkm_kunit_process_suite);
