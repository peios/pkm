// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_kunit_validate_sd_rejects_oversized_descriptor(
	struct kunit *test)
{
	u8 *sd;

	sd = kunit_kzalloc(test, PKM_KUNIT_MAX_SECURITY_DESCRIPTOR_BYTES + 1,
			   GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, sd);

	sd[0] = 1;
	pkm_kunit_write_u16(sd, 2, PKM_KUNIT_SE_SELF_RELATIVE);

	KUNIT_EXPECT_EQ(test,
			kacs_rust_validate_sd_bytes(
				sd, PKM_KUNIT_MAX_SECURITY_DESCRIPTOR_BYTES + 1),
			-ERANGE);
}


static void pkm_kunit_token_eval_context_requires_subjective_cred(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_eval_context_allowed(1, 1, 1, 1),
			1);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_eval_context_allowed(0, 1, 1, 1),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_eval_context_allowed(1, 0, 0, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_eval_context_allowed(1, 1, 0, 0),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_eval_context_allowed(1, 1, 1, 0),
			0);
	KUNIT_EXPECT_TRUE(test, pkm_kacs_current_token_eval_context_allowed());
	KUNIT_EXPECT_NOT_NULL(test, pkm_kacs_current_effective_token_ptr());
}


static void pkm_kunit_create_session_success(struct kunit *test)
{
	static const u8 local_service_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0,
	};
	static const char auth_pkg[] = "Kerberos";
	u8 spec[64] = { };
	u8 expected_logon_sid[20] = { };
	struct pkm_kacs_session_snapshot snapshot = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t spec_len;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	spec_len = pkm_kunit_build_session_spec(spec, 2, auth_pkg,
						local_service_sid,
						sizeof(local_service_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, spec, spec_len, &session_id),
			0L);
	KUNIT_EXPECT_GE(test, session_id, 1000ULL);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_kunit_session_snapshot(session_id, &snapshot),
			0);
	KUNIT_ASSERT_NOT_NULL(test, snapshot.session_ptr);
	KUNIT_EXPECT_EQ(test, snapshot.session_id, session_id);
	KUNIT_EXPECT_EQ(test, snapshot.logon_type, 2U);
	pkm_kunit_expect_bytes_eq(test, snapshot.auth_pkg_ptr, snapshot.auth_pkg_len,
				  (const u8 *)auth_pkg, sizeof(auth_pkg) - 1);
	pkm_kunit_expect_bytes_eq(test, snapshot.user_sid_ptr, snapshot.user_sid_len,
				  local_service_sid,
				  sizeof(local_service_sid));
	pkm_kunit_build_logon_sid(session_id, expected_logon_sid);
	pkm_kunit_expect_bytes_eq(test, snapshot.logon_sid_ptr,
				  snapshot.logon_sid_len,
				  expected_logon_sid,
				  sizeof(expected_logon_sid));
	KUNIT_ASSERT_NOT_NULL(test, snapshot.own_sd_ptr);
	KUNIT_ASSERT_GT(test, (long)snapshot.own_sd_len, 20L);
	pkm_kunit_expect_sd_sid_component(test, snapshot.own_sd_ptr,
					  snapshot.own_sd_len, 4,
					  local_service_sid,
					  sizeof(local_service_sid));
	pkm_kunit_expect_sd_sid_component(test, snapshot.own_sd_ptr,
					  snapshot.own_sd_len, 8,
					  pkm_kunit_administrators_sid,
					  sizeof(pkm_kunit_administrators_sid));
	pkm_kunit_expect_allow_ace(test, snapshot.own_sd_ptr,
				   snapshot.own_sd_len, 0,
				   KACS_ACCESS_GENERIC_ALL, local_service_sid,
				   sizeof(local_service_sid));
	pkm_kunit_expect_allow_ace(test, snapshot.own_sd_ptr,
				   snapshot.own_sd_len, 1,
				   KACS_ACCESS_GENERIC_ALL,
				   pkm_kunit_administrators_sid,
				   sizeof(pkm_kunit_administrators_sid));
	pkm_kunit_expect_allow_ace(test, snapshot.own_sd_ptr,
				   snapshot.own_sd_len, 2,
				   KACS_ACCESS_GENERIC_ALL, pkm_kunit_system_sid,
				   sizeof(pkm_kunit_system_sid));
}


static void pkm_kunit_create_session_wire_format_edge_vectors(
	struct kunit *test)
{
	static const u8 local_service_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0,
	};
	static const u8 min_user_sid[] = {
		1, 0, 0, 0, 0, 0, 0, 5,
	};
	static const u8 expected_boundary_logon_sid[] = {
		1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0,
		0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55,
	};
	static const u32 logon_types[] = {
		PKM_KUNIT_LOGON_TYPE_INTERACTIVE,
		PKM_KUNIT_LOGON_TYPE_NETWORK,
		PKM_KUNIT_LOGON_TYPE_BATCH,
		PKM_KUNIT_LOGON_TYPE_SERVICE,
		PKM_KUNIT_LOGON_TYPE_NETWORK_CLEARTEXT,
		PKM_KUNIT_LOGON_TYPE_NEW_CREDENTIALS,
	};
	const void *subject_token;
	struct pkm_kacs_session_snapshot snapshot = { };
	u8 spec[64] = { };
	u8 logon_sid[20] = { };
	u8 *max_spec;
	u64 session_id = 0;
	size_t spec_len;
	size_t max_spec_len = 4096U;
	size_t max_auth_len = max_spec_len - 7U - sizeof(local_service_sid);
	u32 i;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	for (i = 0; i < ARRAY_SIZE(logon_types); i++) {
		memset(spec, 0, sizeof(spec));
		session_id = 0;
		spec_len = pkm_kunit_build_session_spec(
			spec, logon_types[i], "Pkg", local_service_sid,
			sizeof(local_service_sid));
		KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
		KUNIT_ASSERT_EQ(test,
				pkm_kacs_kunit_create_session_for_subject(
					subject_token, spec, spec_len,
					&session_id),
				0L);
		KUNIT_ASSERT_EQ(test,
				kacs_rust_kunit_session_snapshot(session_id,
								 &snapshot),
				0);
		KUNIT_EXPECT_EQ(test, snapshot.logon_type, logon_types[i]);
	}

	memset(spec, 0, sizeof(spec));
	spec[0] = PKM_KUNIT_LOGON_TYPE_INTERACTIVE;
	pkm_kunit_write_u16(spec, 1, 0);
	pkm_kunit_write_u32(spec, 3, sizeof(min_user_sid));
	memcpy(spec + 7, min_user_sid, sizeof(min_user_sid));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, spec, 15U, &session_id),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_kunit_session_snapshot(session_id,
							 &snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.auth_pkg_len, (size_t)0);
	pkm_kunit_expect_bytes_eq(test, snapshot.user_sid_ptr,
				  snapshot.user_sid_len, min_user_sid,
				  sizeof(min_user_sid));

	memset(spec, 0, sizeof(spec));
	spec_len = pkm_kunit_build_session_spec(
		spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Pkg", local_service_sid,
		sizeof(local_service_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_LT(test, spec_len + 1, sizeof(spec));
	spec[spec_len] = 0xa5;
	session_id = 0;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, spec, spec_len + 1, &session_id),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, session_id, 0ULL);

	max_spec = kunit_kzalloc(test, max_spec_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, max_spec);
	max_spec[0] = PKM_KUNIT_LOGON_TYPE_NEW_CREDENTIALS;
	pkm_kunit_write_u16(max_spec, 1, (u16)max_auth_len);
	memset(max_spec + 3, 'A', max_auth_len);
	pkm_kunit_write_u32(max_spec, 3 + max_auth_len,
			    sizeof(local_service_sid));
	memcpy(max_spec + 7 + max_auth_len, local_service_sid,
	       sizeof(local_service_sid));
	session_id = 0;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, max_spec, max_spec_len,
				&session_id),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_kunit_session_snapshot(session_id,
							 &snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.logon_type,
			PKM_KUNIT_LOGON_TYPE_NEW_CREDENTIALS);
	KUNIT_EXPECT_EQ(test, snapshot.auth_pkg_len, max_auth_len);
	KUNIT_ASSERT_NOT_NULL(test, snapshot.auth_pkg_ptr);
	KUNIT_EXPECT_EQ(test, snapshot.auth_pkg_ptr[0], (u8)'A');
	KUNIT_EXPECT_EQ(test, snapshot.auth_pkg_ptr[max_auth_len - 1],
			(u8)'A');

	KUNIT_ASSERT_EQ(test,
			kacs_rust_kunit_build_logon_sid(
				0x1122334455667788ULL, logon_sid),
			0);
	pkm_kunit_expect_bytes_eq(test, logon_sid, sizeof(logon_sid),
				  expected_boundary_logon_sid,
				  sizeof(expected_boundary_logon_sid));
}


static void pkm_kunit_create_session_non_utf8_auth_package_fails_closed(
	struct kunit *test)
{
	static const u8 local_service_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0,
	};
	const void *subject_token;
	u64 session_id = 0;
	u8 spec[64] = { };
	size_t auth_pkg_len = 2;
	size_t user_sid_len_offset = 3 + auth_pkg_len;
	size_t user_sid_offset = user_sid_len_offset + 4;
	size_t spec_len = user_sid_offset + sizeof(local_service_sid);

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_LE(test, spec_len, sizeof(spec));

	spec[0] = PKM_KUNIT_LOGON_TYPE_NETWORK;
	pkm_kunit_write_u16(spec, 1, (u16)auth_pkg_len);
	spec[3] = (u8)'K';
	spec[4] = 0xff;
	pkm_kunit_write_u32(spec, user_sid_len_offset,
			    sizeof(local_service_sid));
	memcpy(spec + user_sid_offset, local_service_sid,
	       sizeof(local_service_sid));

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, spec, spec_len, &session_id),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, session_id, 0ULL);
}


static void pkm_kunit_create_session_requires_tcb(struct kunit *test)
{
	static const u8 system_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	static const char auth_pkg[] = "Negotiate";
	u8 spec[64] = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t spec_len;

	subject_token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	spec_len = pkm_kunit_build_session_spec(spec, 5, auth_pkg, system_sid,
						sizeof(system_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, spec, spec_len, &session_id),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test, session_id, 0ULL);

	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_create_session_invalid_spec_fails_closed(
	struct kunit *test)
{
	static const u8 system_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	static const char auth_pkg[] = "Negotiate";
	u8 spec[64] = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t spec_len;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	spec_len = pkm_kunit_build_session_spec(spec, 5, auth_pkg, system_sid,
						sizeof(system_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);

	spec[0] = 7;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, spec, spec_len, &session_id),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, session_id, 0ULL);

	spec_len = pkm_kunit_build_session_spec(spec, 5, auth_pkg, system_sid,
						sizeof(system_sid));
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, spec, spec_len - 1,
				&session_id),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, session_id, 0ULL);
}


static void pkm_kunit_create_token_success(struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
		{
			.sid = pkm_kunit_authenticated_users_sid,
			.sid_len = sizeof(pkm_kunit_authenticated_users_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	static const struct pkm_kunit_sid_attr_spec device_groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = 0U,
		},
	};
	static const struct pkm_kunit_sid_attr_spec confinement_caps[] = {
		{
			.sid = pkm_kunit_all_restricted_application_packages_sid,
			.sid_len =
				sizeof(pkm_kunit_all_restricted_application_packages_sid),
			.attributes = 0U,
		},
	};
	static const u32 supplementary_gids[] = {
		77U, 88U,
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot snapshot = { };
	struct pkm_kacs_boot_snapshot caller_after = { };
	struct kacs_query_args args = { };
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.privileges_present = PKM_KUNIT_SE_DEBUG_PRIVILEGE,
		.privileges_enabled = PKM_KUNIT_SE_DEBUG_PRIVILEGE,
		.projected_uid = 1234U,
		.projected_gid = 2345U,
		.audit_policy = 0x00000005U,
		.expiration = 0x1122334455667788ULL,
		.owner_sid_index = 1U,
		.primary_group_index = 2U,
		.source_name = source_name,
		.source_id = 0x0102030405060708ULL,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
		.default_dacl = pkm_kunit_replacement_default_dacl,
		.default_dacl_len = sizeof(pkm_kunit_replacement_default_dacl),
		.device_groups = device_groups,
		.device_group_count = ARRAY_SIZE(device_groups),
		.confinement_sid = pkm_kunit_sample_confinement_sid,
		.confinement_sid_len = sizeof(pkm_kunit_sample_confinement_sid),
		.confinement_caps = confinement_caps,
		.confinement_cap_count = ARRAY_SIZE(confinement_caps),
		.projected_supplementary_gids = supplementary_gids,
		.projected_supplementary_gid_count =
			ARRAY_SIZE(supplementary_gids),
		.origin = 0x8877665544332211ULL,
		.interactive_session_id = 9U,
	};
	u8 spec[512] = { };
	u8 buf[128] = { };
	u8 expected_logon_sid[20] = { };
	const void *subject_token;
	u64 session_id = 0;
	u32 logon_attributes = 0;
	size_t spec_len;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	spec_len = pkm_kunit_build_session_spec(spec,
						PKM_KUNIT_LOGON_TYPE_NETWORK,
						"Kerberos",
						pkm_kunit_local_service_sid,
						sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, spec, spec_len, &session_id),
			0L);
	KUNIT_ASSERT_GE(test, session_id, 1000ULL);

	memset(spec, 0, sizeof(spec));
	spec_args.session_id = session_id;
	spec_len = pkm_kunit_build_token_spec(spec, sizeof(spec), &spec_args);
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, spec, spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test, pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_ALL_ACCESS);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(view.token,
							       &snapshot));

	KUNIT_EXPECT_EQ(test, snapshot.session_id, session_id);
	KUNIT_EXPECT_EQ(test, snapshot.auth_id, session_id);
	KUNIT_EXPECT_EQ(test, snapshot.logon_type,
			PKM_KUNIT_LOGON_TYPE_NETWORK);
	pkm_kunit_expect_bytes_eq(test, snapshot.user_sid_ptr,
				  snapshot.user_sid_len,
				  pkm_kunit_local_service_sid,
				  sizeof(pkm_kunit_local_service_sid));
	KUNIT_EXPECT_EQ(test, snapshot.group_count, 3U);
	KUNIT_EXPECT_EQ(test, snapshot.owner_sid_index, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.primary_group_index, 2U);
	KUNIT_EXPECT_EQ(test, snapshot.projected_uid, 1234U);
	KUNIT_EXPECT_EQ(test, snapshot.projected_gid, 2345U);
	KUNIT_EXPECT_EQ(test, snapshot.audit_policy, 0x00000005U);
	KUNIT_EXPECT_EQ(test, snapshot.integrity_level, PKM_KUNIT_IL_MEDIUM);
	KUNIT_EXPECT_EQ(test, snapshot.token_type, KACS_TOKEN_TYPE_PRIMARY);
	KUNIT_EXPECT_EQ(test, snapshot.impersonation_level,
			KACS_IMLEVEL_ANONYMOUS);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_present,
			PKM_KUNIT_SE_DEBUG_PRIVILEGE);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_enabled,
			PKM_KUNIT_SE_DEBUG_PRIVILEGE);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_enabled_by_default,
			PKM_KUNIT_SE_DEBUG_PRIVILEGE);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_used, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.modified_id, snapshot.token_id);
	KUNIT_EXPECT_GE(test, snapshot.token_id, 1000ULL);
	KUNIT_EXPECT_GT(test, snapshot.created_at, 0ULL);
	pkm_kunit_expect_allow_ace(test, snapshot.own_sd_ptr,
				   snapshot.own_sd_len, 0,
				   PKM_KUNIT_DEFAULT_TOKEN_SELF_ACCESS,
				   pkm_kunit_local_service_sid,
				   sizeof(pkm_kunit_local_service_sid));
	pkm_kunit_build_logon_sid(session_id, expected_logon_sid);
	KUNIT_ASSERT_TRUE(test, pkm_kunit_snapshot_has_group(
				 &snapshot, expected_logon_sid,
				 sizeof(expected_logon_sid),
				 &logon_attributes));
	KUNIT_EXPECT_EQ(test, logon_attributes,
			PKM_KUNIT_SE_GROUP_MANDATORY |
				PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				PKM_KUNIT_SE_GROUP_ENABLED |
				PKM_KUNIT_SE_GROUP_LOGON_ID);

	args.token_class = KACS_TOKEN_CLASS_OWNER;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  pkm_kunit_everyone_sid,
				  sizeof(pkm_kunit_everyone_sid));

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_PRIMARY_GROUP;
	args.buf_len = sizeof(buf);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  pkm_kunit_authenticated_users_sid,
				  sizeof(pkm_kunit_authenticated_users_sid));

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_SOURCE;
	args.buf_len = 16U;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 16U);
	pkm_kunit_expect_bytes_eq(test, buf, 8U, source_name, sizeof(source_name));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 8),
			0x0102030405060708ULL);

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_ORIGIN;
	args.buf_len = 8U;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 0),
			0x8877665544332211ULL);

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_STATISTICS;
	args.buf_len = 40U;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 0), snapshot.token_id);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 8), session_id);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 16), snapshot.modified_id);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 32),
			0x1122334455667788ULL);

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_LOGON_TYPE;
	args.buf_len = 4U;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0),
			PKM_KUNIT_LOGON_TYPE_NETWORK);

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_LOGON_SID;
	args.buf_len = sizeof(buf);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len, expected_logon_sid,
				  sizeof(expected_logon_sid));

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_DEVICE_GROUPS;
	args.buf_len = sizeof(buf);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0), 1U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 4),
			(u32)sizeof(pkm_kunit_everyone_sid));
	pkm_kunit_expect_bytes_eq(test, &buf[8],
				  sizeof(pkm_kunit_everyone_sid),
				  pkm_kunit_everyone_sid,
				  sizeof(pkm_kunit_everyone_sid));
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_read_u32(
				buf, 8U + sizeof(pkm_kunit_everyone_sid)),
			0U);

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_APPCONTAINER_SID;
	args.buf_len = sizeof(buf);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  pkm_kunit_sample_confinement_sid,
				  sizeof(pkm_kunit_sample_confinement_sid));

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_CAPABILITIES;
	args.buf_len = sizeof(buf);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0), 1U);
	KUNIT_EXPECT_EQ(
		test, pkm_kunit_read_u32(buf, 4),
		(u32)sizeof(pkm_kunit_all_restricted_application_packages_sid));
	pkm_kunit_expect_bytes_eq(
		test, &buf[8],
		sizeof(pkm_kunit_all_restricted_application_packages_sid),
		pkm_kunit_all_restricted_application_packages_sid,
		sizeof(pkm_kunit_all_restricted_application_packages_sid));

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &caller_after));
	KUNIT_EXPECT_EQ(test,
			caller_after.privileges_used &
				PKM_KUNIT_SE_CREATE_TOKEN_PRIVILEGE,
			PKM_KUNIT_SE_CREATE_TOKEN_PRIVILEGE);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_create_token_rejects_uid0_non_system_projection(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'U', 'i', 'd', '0', 'G', 'u', 'a', 'r',
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0U,
		.projected_uid = 0U,
		.projected_gid = 2345U,
		.allow_zero_projected_uid = 1U,
		.owner_sid_index = 1U,
		.primary_group_index = 1U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	u8 session_spec[96] = { };
	u8 token_spec[512] = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t spec_len;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Negotiate",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	spec_len = pkm_kunit_build_token_spec(token_spec, sizeof(token_spec),
					      &spec_args);
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, spec_len),
			(long)-EINVAL);

	memset(session_spec, 0, sizeof(session_spec));
	memset(token_spec, 0, sizeof(token_spec));
	spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_SERVICE, "Negotiate",
		pkm_kunit_system_sid, sizeof(pkm_kunit_system_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	spec_args.user_sid = pkm_kunit_system_sid;
	spec_args.user_sid_len = sizeof(pkm_kunit_system_sid);
	spec_args.projected_gid = 0U;
	spec_len = pkm_kunit_build_token_spec(token_spec, sizeof(token_spec),
					      &spec_args);
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						    spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_create_token_administrators_group_adds_no_privileges(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_administrators_sid,
			.sid_len = sizeof(pkm_kunit_administrators_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.projected_uid = 1234U,
		.projected_gid = 2345U,
		.owner_sid_index = 0U,
		.primary_group_index = 1U,
		.source_name = source_name,
		.source_id = 0x0102030405060708ULL,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
		.default_dacl = pkm_kunit_replacement_default_dacl,
		.default_dacl_len = sizeof(pkm_kunit_replacement_default_dacl),
	};
	struct kacs_query_args query = {
		.token_class = KACS_TOKEN_CLASS_PRIVILEGES,
		.buf_len = 32U,
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot snapshot = { };
	u8 spec[512] = { };
	u8 buf[32] = { };
	const void *subject_token;
	u64 session_id = 0;
	u32 admin_attributes = 0;
	size_t spec_len;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	spec_len = pkm_kunit_build_session_spec(spec,
						PKM_KUNIT_LOGON_TYPE_NETWORK,
						"Kerberos",
						pkm_kunit_local_service_sid,
						sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, spec, spec_len, &session_id),
			0L);

	memset(spec, 0, sizeof(spec));
	spec_args.session_id = session_id;
	spec_len = pkm_kunit_build_token_spec(spec, sizeof(spec), &spec_args);
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, spec,
						     spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test, pkm_kacs_kunit_token_fd_snapshot((int)fd, &view),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token,
							 &snapshot));
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_snapshot_has_group(
				  &snapshot, pkm_kunit_administrators_sid,
				  sizeof(pkm_kunit_administrators_sid),
				  &admin_attributes));
	KUNIT_EXPECT_NE(test, admin_attributes & PKM_KUNIT_SE_GROUP_ENABLED, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_present, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_enabled, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_enabled_by_default, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_used, 0ULL);

	query.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &query, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, query.buf_len, 32U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 0), 0ULL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 8), 0ULL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 16), 0ULL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 24), 0ULL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_create_token_default_enabled_derives_live_groups(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
		{
			.sid = pkm_kunit_authenticated_users_sid,
			.sid_len = sizeof(pkm_kunit_authenticated_users_sid),
			.attributes = PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.owner_sid_index = 1U,
		.primary_group_index = 2U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
		.default_dacl = pkm_kunit_replacement_default_dacl,
		.default_dacl_len = sizeof(pkm_kunit_replacement_default_dacl),
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot snapshot = { };
	u8 spec[512] = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t spec_len;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	spec_len = pkm_kunit_build_session_spec(spec,
						PKM_KUNIT_LOGON_TYPE_NETWORK,
						"Kerberos",
						pkm_kunit_local_service_sid,
						sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, spec, spec_len, &session_id),
			0L);
	KUNIT_ASSERT_GE(test, session_id, 1000ULL);

	memset(spec, 0, sizeof(spec));
	spec_args.session_id = session_id;
	spec_len = pkm_kunit_build_token_spec(spec, sizeof(spec), &spec_args);
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, spec, spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test, pkm_kacs_kunit_token_fd_snapshot((int)fd,
							       &view), 0);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(view.token,
							       &snapshot));
	KUNIT_EXPECT_EQ(test, snapshot.group_count, 3U);
	KUNIT_EXPECT_EQ(test, snapshot.groups_ptr[0].attributes,
			PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				PKM_KUNIT_SE_GROUP_ENABLED |
				PKM_KUNIT_SE_GROUP_OWNER);
	KUNIT_EXPECT_EQ(test, snapshot.groups_ptr[1].attributes, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_create_token_preserves_resource_group_metadata(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_OWNER |
				      PKM_KUNIT_SE_GROUP_RESOURCE,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.owner_sid_index = 1U,
		.primary_group_index = 1U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
		.default_dacl = pkm_kunit_replacement_default_dacl,
		.default_dacl_len = sizeof(pkm_kunit_replacement_default_dacl),
	};
	struct kacs_query_args group_query = {
		.token_class = KACS_TOKEN_CLASS_GROUPS,
		.buf_len = 128,
	};
	u8 group_buf[128] = { 0 };
	u8 spec[512] = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t spec_len;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	spec_len = pkm_kunit_build_session_spec(spec,
						PKM_KUNIT_LOGON_TYPE_NETWORK,
						"Kerberos",
						pkm_kunit_local_service_sid,
						sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, spec, spec_len, &session_id),
			0L);
	KUNIT_ASSERT_GE(test, session_id, 1000ULL);

	memset(spec, 0, sizeof(spec));
	spec_args.session_id = session_id;
	spec_len = pkm_kunit_build_token_spec(spec, sizeof(spec), &spec_args);
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, spec, spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);

	group_query.buf_ptr = (u64)(unsigned long)group_buf;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &group_query,
						      group_buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(group_buf, 0), 2U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_groups_query_attr(group_buf, 0),
			PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				PKM_KUNIT_SE_GROUP_ENABLED |
				PKM_KUNIT_SE_GROUP_OWNER |
				PKM_KUNIT_SE_GROUP_RESOURCE);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_create_token_requires_privilege(struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.session_id = 0,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	const void *subject_token;
	const void *caller_without_privilege;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	caller_without_privilege = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, caller_without_privilege);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				caller_without_privilege, token_spec,
				token_spec_len),
			(long)-EPERM);

	kacs_rust_token_drop(caller_without_privilege);
}


static void pkm_kunit_create_token_invalid_session_fails_closed(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.session_id = 0x8877665544332211ULL,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	u8 token_spec[256] = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &before));

	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
}


static void pkm_kunit_create_token_write_restricted_requires_user_deny_only(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.write_restricted = 1,
		.user_deny_only = 0,
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &before));
	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
}


static void pkm_kunit_create_token_malformed_claims_fail_closed(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	static const u8 malformed_claims[] = {
		4, 0, 0, 0, 1, 2, 3, 4,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.user_claims = malformed_claims,
		.user_claims_len = sizeof(malformed_claims),
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);

	memset(token_spec, 0, sizeof(token_spec));
	spec_args.user_claims = NULL;
	spec_args.user_claims_len = 0;
	spec_args.device_claims = malformed_claims;
	spec_args.device_claims_len = sizeof(malformed_claims);
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
}


static void pkm_kunit_create_token_primary_non_anonymous_denies(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_IDENTIFICATION,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
}


static void pkm_kunit_create_token_impersonation_levels_query(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	static const u32 levels[] = {
		KACS_IMLEVEL_ANONYMOUS,
		KACS_IMLEVEL_IDENTIFICATION,
		KACS_IMLEVEL_IMPERSONATION,
		KACS_IMLEVEL_DELEGATION,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_IMPERSONATION,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;
	size_t i;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	for (i = 0; i < ARRAY_SIZE(levels); i++) {
		long fd;

		memset(token_spec, 0, sizeof(token_spec));
		spec_args.impersonation_level = (u8)levels[i];
		spec_args.source_id = i;
		token_spec_len = pkm_kunit_build_token_spec(token_spec,
							    sizeof(token_spec),
							    &spec_args);
		KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);

		fd = pkm_kacs_kunit_create_token_for_subject(
			subject_token, token_spec, token_spec_len);
		KUNIT_ASSERT_GE(test, fd, 0L);
		KUNIT_EXPECT_EQ(test,
				pkm_kunit_query_token_u32(test, (int)fd,
							  KACS_TOKEN_CLASS_TYPE),
				KACS_TOKEN_TYPE_IMPERSONATION);
		KUNIT_EXPECT_EQ(test,
				pkm_kunit_query_token_u32(
					test, (int)fd,
					KACS_TOKEN_CLASS_IMPERSONATION_LEVEL),
				levels[i]);
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	}
}


static void pkm_kunit_create_token_invalid_mandatory_policy_fails_closed(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000004U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &before));
	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
}


static void pkm_kunit_create_token_invalid_audit_policy_fails_closed(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.audit_policy = 0x00000010U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &before));
	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
}


static void pkm_kunit_create_token_invalid_default_dacl_fails_closed(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.default_dacl = pkm_kunit_invalid_default_dacl,
		.default_dacl_len = sizeof(pkm_kunit_invalid_default_dacl),
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &before));
	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
}


static void pkm_kunit_create_token_enabled_privilege_subset_fails_closed(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.privileges_present = PKM_KUNIT_SE_DEBUG_PRIVILEGE,
		.privileges_enabled = PKM_KUNIT_SE_DEBUG_PRIVILEGE |
				      PKM_KUNIT_SE_TCB_PRIVILEGE,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &before));
	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
}


static void pkm_kunit_create_token_isolation_requires_confinement(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.isolation_boundary = 1U,
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &before));
	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(subject_token,
							 &after));
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
}


static void pkm_kunit_create_token_invalid_owner_index_denies(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
		{
			.sid = pkm_kunit_authenticated_users_sid,
			.sid_len = sizeof(pkm_kunit_authenticated_users_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.owner_sid_index = 3U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
}


static void pkm_kunit_create_token_owner_group_requires_owner_attr(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.owner_sid_index = 1U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
}


static void pkm_kunit_create_token_primary_group_excludes_injected_logon(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.owner_sid_index = 1U,
		.primary_group_index = 2U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
}


static void pkm_kunit_create_token_reserved_elevation_denies(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	pkm_kunit_write_u32(token_spec, 32, 1U);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
}


static void pkm_kunit_create_token_wire_format_edge_vectors(struct kunit *test)
{
	enum pkm_kunit_bad_token_spec_case {
		PKM_KUNIT_BAD_RESERVED0_BYTE0,
		PKM_KUNIT_BAD_RESERVED0_BYTE1,
		PKM_KUNIT_BAD_RESERVED1,
		PKM_KUNIT_BAD_RESERVED3,
		PKM_KUNIT_BAD_USER_OFFSET_ABSENT,
		PKM_KUNIT_BAD_DUPLICATE_SECTION_OFFSET,
		PKM_KUNIT_BAD_SECTION_OFFSET_IN_HEADER,
		PKM_KUNIT_BAD_SECTION_OFFSET_AT_END,
		PKM_KUNIT_BAD_FIXED_OFFSET_WITH_ZERO_LEN,
		PKM_KUNIT_BAD_FIXED_LEN_WITH_ZERO_OFFSET,
		PKM_KUNIT_BAD_FIXED_SECTION_OVERRUN,
		PKM_KUNIT_BAD_COUNT_OFFSET_WITH_ZERO_COUNT,
		PKM_KUNIT_BAD_COUNT_WITH_ZERO_OFFSET,
		PKM_KUNIT_BAD_COUNT_SECTION_TOO_SHORT,
		PKM_KUNIT_BAD_SUPP_GIDS_TOO_SHORT,
	};
	static const enum pkm_kunit_bad_token_spec_case bad_cases[] = {
		PKM_KUNIT_BAD_RESERVED0_BYTE0,
		PKM_KUNIT_BAD_RESERVED0_BYTE1,
		PKM_KUNIT_BAD_RESERVED1,
		PKM_KUNIT_BAD_RESERVED3,
		PKM_KUNIT_BAD_USER_OFFSET_ABSENT,
		PKM_KUNIT_BAD_DUPLICATE_SECTION_OFFSET,
		PKM_KUNIT_BAD_SECTION_OFFSET_IN_HEADER,
		PKM_KUNIT_BAD_SECTION_OFFSET_AT_END,
		PKM_KUNIT_BAD_FIXED_OFFSET_WITH_ZERO_LEN,
		PKM_KUNIT_BAD_FIXED_LEN_WITH_ZERO_OFFSET,
		PKM_KUNIT_BAD_FIXED_SECTION_OVERRUN,
		PKM_KUNIT_BAD_COUNT_OFFSET_WITH_ZERO_COUNT,
		PKM_KUNIT_BAD_COUNT_WITH_ZERO_OFFSET,
		PKM_KUNIT_BAD_COUNT_SECTION_TOO_SHORT,
		PKM_KUNIT_BAD_SUPP_GIDS_TOO_SHORT,
	};
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	const void *subject_token;
	u8 *session_spec;
	u8 *base_spec;
	u8 *mutated_spec;
	u8 *ordered_spec;
	u64 session_id = 0;
	size_t base_len;
	size_t group_len;
	size_t groups_offset;
	size_t i;
	size_t ordered_len;
	size_t session_spec_len;
	size_t user_len;
	size_t user_offset;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	session_spec = kunit_kzalloc(test, 96U, GFP_KERNEL);
	base_spec = kunit_kzalloc(test, 512U, GFP_KERNEL);
	mutated_spec = kunit_kzalloc(test, 512U, GFP_KERNEL);
	ordered_spec = kunit_kzalloc(test, 512U, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, session_spec);
	KUNIT_ASSERT_NOT_NULL(test, base_spec);
	KUNIT_ASSERT_NOT_NULL(test, mutated_spec);
	KUNIT_ASSERT_NOT_NULL(test, ordered_spec);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	base_len = pkm_kunit_build_token_spec(base_spec, 512U, &spec_args);
	KUNIT_ASSERT_GT(test, (long)base_len,
			(long)PKM_KUNIT_TOKEN_SPEC_HEADER_LEN);
	KUNIT_ASSERT_LE(test, base_len, (size_t)512U);

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, base_spec,
						     base_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	user_offset = pkm_kunit_read_u32(base_spec, 88);
	groups_offset = pkm_kunit_read_u32(base_spec, 92);
	KUNIT_ASSERT_EQ(test, user_offset,
			(size_t)PKM_KUNIT_TOKEN_SPEC_HEADER_LEN);
	KUNIT_ASSERT_GT(test, groups_offset, user_offset);
	KUNIT_ASSERT_GT(test, base_len, groups_offset);
	user_len = groups_offset - user_offset;
	group_len = base_len - groups_offset;

	memset(ordered_spec, 0, 512U);
	memcpy(ordered_spec, base_spec, PKM_KUNIT_TOKEN_SPEC_HEADER_LEN);
	memcpy(ordered_spec + PKM_KUNIT_TOKEN_SPEC_HEADER_LEN,
	       base_spec + groups_offset, group_len);
	memcpy(ordered_spec + PKM_KUNIT_TOKEN_SPEC_HEADER_LEN + group_len,
	       base_spec + user_offset, user_len);
	pkm_kunit_write_u32(ordered_spec, 88,
			    PKM_KUNIT_TOKEN_SPEC_HEADER_LEN + group_len);
	pkm_kunit_write_u32(ordered_spec, 92,
			    PKM_KUNIT_TOKEN_SPEC_HEADER_LEN);
	ordered_len = PKM_KUNIT_TOKEN_SPEC_HEADER_LEN + group_len + user_len;
	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, ordered_spec,
						     ordered_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);

	for (i = 0; i < ARRAY_SIZE(bad_cases); i++) {
		memcpy(mutated_spec, base_spec, base_len);

		switch (bad_cases[i]) {
		case PKM_KUNIT_BAD_RESERVED0_BYTE0:
			mutated_spec[6] = 1U;
			break;
		case PKM_KUNIT_BAD_RESERVED0_BYTE1:
			mutated_spec[7] = 1U;
			break;
		case PKM_KUNIT_BAD_RESERVED1:
			pkm_kunit_write_u32(mutated_spec, 32, 1U);
			break;
		case PKM_KUNIT_BAD_RESERVED3:
			pkm_kunit_write_u32(mutated_spec, 188, 1U);
			break;
		case PKM_KUNIT_BAD_USER_OFFSET_ABSENT:
			pkm_kunit_write_u32(mutated_spec, 88, 0U);
			break;
		case PKM_KUNIT_BAD_DUPLICATE_SECTION_OFFSET:
			pkm_kunit_write_u32(mutated_spec, 100,
					    (u32)groups_offset);
			pkm_kunit_write_u32(mutated_spec, 104, 4U);
			break;
		case PKM_KUNIT_BAD_SECTION_OFFSET_IN_HEADER:
			pkm_kunit_write_u32(
				mutated_spec, 92,
				PKM_KUNIT_TOKEN_SPEC_HEADER_LEN - 1U);
			break;
		case PKM_KUNIT_BAD_SECTION_OFFSET_AT_END:
			pkm_kunit_write_u32(mutated_spec, 100, (u32)base_len);
			pkm_kunit_write_u32(mutated_spec, 104, 4U);
			break;
		case PKM_KUNIT_BAD_FIXED_OFFSET_WITH_ZERO_LEN:
			pkm_kunit_write_u32(mutated_spec, 100,
					    (u32)(base_len - 1U));
			pkm_kunit_write_u32(mutated_spec, 104, 0U);
			break;
		case PKM_KUNIT_BAD_FIXED_LEN_WITH_ZERO_OFFSET:
			pkm_kunit_write_u32(mutated_spec, 100, 0U);
			pkm_kunit_write_u32(mutated_spec, 104, 4U);
			break;
		case PKM_KUNIT_BAD_FIXED_SECTION_OVERRUN:
			pkm_kunit_write_u32(mutated_spec, 100,
					    (u32)(groups_offset + 4U));
			pkm_kunit_write_u32(mutated_spec, 104,
					    (u32)(base_len - groups_offset));
			break;
		case PKM_KUNIT_BAD_COUNT_OFFSET_WITH_ZERO_COUNT:
			pkm_kunit_write_u32(mutated_spec, 124,
					    (u32)(base_len - 1U));
			pkm_kunit_write_u32(mutated_spec, 128, 0U);
			break;
		case PKM_KUNIT_BAD_COUNT_WITH_ZERO_OFFSET:
			pkm_kunit_write_u32(mutated_spec, 124, 0U);
			pkm_kunit_write_u32(mutated_spec, 128, 1U);
			break;
		case PKM_KUNIT_BAD_COUNT_SECTION_TOO_SHORT:
			pkm_kunit_write_u32(mutated_spec, 96, 2U);
			break;
		case PKM_KUNIT_BAD_SUPP_GIDS_TOO_SHORT:
			pkm_kunit_write_u32(mutated_spec, 160,
					    (u32)(base_len - 1U));
			pkm_kunit_write_u32(mutated_spec, 164, 1U);
			break;
		}

		pkm_kunit_expect_create_token_spec_einval(test, subject_token,
							  mutated_spec,
							  base_len);
	}
}


static void pkm_kunit_create_token_malformed_sid_sections_fail_closed(
	struct kunit *test)
{
	enum pkm_kunit_malformed_sid_section {
		PKM_KUNIT_BAD_USER_SID,
		PKM_KUNIT_BAD_GROUP_SID,
		PKM_KUNIT_BAD_DEVICE_GROUP_SID,
		PKM_KUNIT_BAD_RESTRICTED_SID,
		PKM_KUNIT_BAD_CONFINEMENT_SID,
		PKM_KUNIT_BAD_CONFINEMENT_CAPABILITY,
		PKM_KUNIT_BAD_RESTRICTED_DEVICE_GROUP,
	};
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	static const u8 malformed_sid[] = {
		2, 1, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0,
	};
	static const enum pkm_kunit_malformed_sid_section cases[] = {
		PKM_KUNIT_BAD_USER_SID,
		PKM_KUNIT_BAD_GROUP_SID,
		PKM_KUNIT_BAD_DEVICE_GROUP_SID,
		PKM_KUNIT_BAD_RESTRICTED_SID,
		PKM_KUNIT_BAD_CONFINEMENT_SID,
		PKM_KUNIT_BAD_CONFINEMENT_CAPABILITY,
		PKM_KUNIT_BAD_RESTRICTED_DEVICE_GROUP,
	};
	struct pkm_kunit_sid_attr_spec malformed_entry = {
		.sid = malformed_sid,
		.sid_len = sizeof(malformed_sid),
		.attributes = PKM_KUNIT_SE_GROUP_ENABLED,
	};
	u8 session_spec[64] = { };
	u8 token_spec[512] = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;
	size_t i;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct pkm_kunit_token_spec_args spec_args = {
			.token_type = KACS_TOKEN_TYPE_PRIMARY,
			.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
			.integrity_level = PKM_KUNIT_IL_MEDIUM,
			.mandatory_policy = 0x00000003U,
			.session_id = session_id,
			.source_name = source_name,
			.user_sid = pkm_kunit_local_service_sid,
			.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		};

		switch (cases[i]) {
		case PKM_KUNIT_BAD_USER_SID:
			spec_args.user_sid = malformed_sid;
			spec_args.user_sid_len = sizeof(malformed_sid);
			break;
		case PKM_KUNIT_BAD_GROUP_SID:
			spec_args.groups = &malformed_entry;
			spec_args.group_count = 1U;
			break;
		case PKM_KUNIT_BAD_DEVICE_GROUP_SID:
			spec_args.device_groups = &malformed_entry;
			spec_args.device_group_count = 1U;
			break;
		case PKM_KUNIT_BAD_RESTRICTED_SID:
			spec_args.restricted_sids = &malformed_entry;
			spec_args.restricted_sid_count = 1U;
			break;
		case PKM_KUNIT_BAD_CONFINEMENT_SID:
			spec_args.confinement_sid = malformed_sid;
			spec_args.confinement_sid_len = sizeof(malformed_sid);
			break;
		case PKM_KUNIT_BAD_CONFINEMENT_CAPABILITY:
			spec_args.confinement_caps = &malformed_entry;
			spec_args.confinement_cap_count = 1U;
			break;
		case PKM_KUNIT_BAD_RESTRICTED_DEVICE_GROUP:
			spec_args.restricted_device_groups = &malformed_entry;
			spec_args.restricted_device_group_count = 1U;
			break;
		}

		token_spec_len = pkm_kunit_build_token_spec(
			token_spec, sizeof(token_spec), &spec_args);
		KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_create_token_for_subject(
					subject_token, token_spec,
					token_spec_len),
				(long)-EINVAL);
	}
}


static void pkm_kunit_create_token_caller_logon_sid_denies(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_sid_attr_spec groups[1] = { };
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	u8 logon_sid[20] = { };
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	pkm_kunit_build_logon_sid(session_id, logon_sid);
	groups[0].sid = logon_sid;
	groups[0].sid_len = sizeof(logon_sid);
	groups[0].attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
			       PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
			       PKM_KUNIT_SE_GROUP_ENABLED |
			       PKM_KUNIT_SE_GROUP_LOGON_ID;
	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
}


static void pkm_kunit_create_token_max_groups_succeeds(struct kunit *test)
{
	static const u8 source_name[8] = {
		'G', 'r', 'p', 'M', 'a', 'x', 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.owner_sid_index = 0,
		.primary_group_index = 0,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.group_count = PKM_KUNIT_MAX_CALLER_GROUPS,
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot snapshot = { };
	struct pkm_kunit_sid_attr_spec *groups;
	u8 session_spec[64] = { };
	u8 *token_spec;
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	groups = kunit_kcalloc(test, PKM_KUNIT_MAX_CALLER_GROUPS,
			       sizeof(*groups), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, groups);
	token_spec = kunit_kzalloc(test,
				   PKM_KUNIT_GROUP_LIMIT_TOKEN_SPEC_BYTES,
				   GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, token_spec);

	pkm_kunit_fill_group_limit_specs(groups, PKM_KUNIT_MAX_CALLER_GROUPS);
	spec_args.groups = groups;

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(
		token_spec, PKM_KUNIT_GROUP_LIMIT_TOKEN_SPEC_BYTES, &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(view.token,
							       &snapshot));
	KUNIT_EXPECT_EQ(test, snapshot.group_count,
			PKM_KUNIT_MAX_TOKEN_GROUPS);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
}


static void pkm_kunit_create_token_over_max_groups_fails_closed(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'G', 'r', 'p', 'O', 'v', 'r', 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.owner_sid_index = 0,
		.primary_group_index = 0,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.group_count = PKM_KUNIT_MAX_TOKEN_GROUPS,
	};
	struct pkm_kunit_sid_attr_spec *groups;
	u8 session_spec[64] = { };
	u8 *token_spec;
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	groups = kunit_kcalloc(test, PKM_KUNIT_MAX_TOKEN_GROUPS,
			       sizeof(*groups), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, groups);
	token_spec = kunit_kzalloc(test,
				   PKM_KUNIT_GROUP_LIMIT_TOKEN_SPEC_BYTES,
				   GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, token_spec);

	pkm_kunit_fill_group_limit_specs(groups, PKM_KUNIT_MAX_TOKEN_GROUPS);
	spec_args.groups = groups;

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(
		token_spec, PKM_KUNIT_GROUP_LIMIT_TOKEN_SPEC_BYTES, &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_create_token_for_subject(
				subject_token, token_spec, token_spec_len),
			(long)-EINVAL);
}


static void pkm_kunit_session_destroy_last_token_emits_kmes(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kacs_session_snapshot snapshot = { };
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	u8 *buffer;
	const void *subject_token;
	const void *token_ptr = NULL;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;
	size_t written = 0;
	long fd;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);
	KUNIT_ASSERT_EQ(test, kacs_rust_kunit_session_snapshot(session_id, &snapshot),
			0);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_token_fd_clone_token((int)fd, &token_ptr,
						      NULL),
			0);
	KUNIT_ASSERT_NOT_NULL(test, token_ptr);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	kacs_rust_token_drop(token_ptr);

	KUNIT_EXPECT_EQ(test, kacs_rust_kunit_session_snapshot(session_id, &snapshot),
			-EACCES);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&kmes_snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, kmes_snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, kmes_snapshot.dropped_events, 0ULL);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)"logon-session-destroyed",
				  sizeof("logon-session-destroyed") - 1);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"session_id",
						 sizeof("session_id") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"user_sid",
						 sizeof("user_sid") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"logon_type",
						 sizeof("logon_type") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"auth_package",
						 sizeof("auth_package") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"created_at",
						 sizeof("created_at") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"Kerberos",
						 sizeof("Kerberos") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
							 pkm_kunit_local_service_sid,
							 sizeof(pkm_kunit_local_service_sid)));
}


static void pkm_kunit_logon_session_destroyed_msgpack_schema(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kacs_session_snapshot session_snapshot = { };
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	u8 *buffer;
	const void *subject_token;
	const void *token_ptr = NULL;
	u64 session_id = 0;
	u64 created_at;
	size_t session_spec_len;
	size_t token_spec_len;
	size_t written = 0;
	long fd;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_kunit_session_snapshot(session_id,
							 &session_snapshot),
			0);
	created_at = session_snapshot.created_at;

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_token_fd_clone_token((int)fd, &token_ptr,
						      NULL),
			0);
	KUNIT_ASSERT_NOT_NULL(test, token_ptr);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	kacs_rust_token_drop(token_ptr);

	KUNIT_EXPECT_EQ(test,
			kacs_rust_kunit_session_snapshot(session_id,
							 &session_snapshot),
			-EACCES);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&kmes_snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_expect_logon_destroyed_schema(
				  test, &view, session_id,
				  PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
				  created_at));
}


static void pkm_kunit_destroy_empty_session_success_emits_kmes(
	struct kunit *test)
{
	u8 session_spec[64] = { };
	struct pkm_kacs_session_snapshot snapshot = { };
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	u8 *buffer;
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t written = 0;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_SERVICE, "Negotiate",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);
	KUNIT_ASSERT_EQ(test, kacs_rust_kunit_session_snapshot(session_id, &snapshot),
			0);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_destroy_empty_session_for_subject(
				subject_token, session_id),
			0L);
	KUNIT_EXPECT_EQ(test, kacs_rust_kunit_session_snapshot(session_id, &snapshot),
			-EACCES);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&kmes_snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, kmes_snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, kmes_snapshot.dropped_events, 0ULL);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)"logon-session-destroyed",
				  sizeof("logon-session-destroyed") - 1);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"Negotiate",
						 sizeof("Negotiate") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 pkm_kunit_local_service_sid,
						 sizeof(pkm_kunit_local_service_sid)));
}


static void pkm_kunit_destroy_empty_session_requires_tcb(struct kunit *test)
{
	u8 session_spec[64] = { };
	struct pkm_kacs_session_snapshot snapshot = { };
	const void *subject_token;
	const void *unprivileged_token;
	u64 session_id = 0;
	size_t session_spec_len;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	unprivileged_token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, unprivileged_token);
	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_SERVICE, "Negotiate",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_destroy_empty_session_for_subject(
				unprivileged_token, session_id),
			(long)-EPERM);
	KUNIT_EXPECT_EQ(test, kacs_rust_kunit_session_snapshot(session_id, &snapshot),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_destroy_empty_session_for_subject(
				subject_token, session_id),
			0L);

	kacs_rust_token_drop(unprivileged_token);
}


static void pkm_kunit_destroy_empty_session_busy_with_live_token(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'u', 't', 'h', 'd', 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	struct pkm_kacs_session_snapshot snapshot = { };
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_reset_kmes();
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_destroy_empty_session_for_subject(
				subject_token, session_id),
			(long)-EBUSY);
	KUNIT_EXPECT_EQ(test, kacs_rust_kunit_session_snapshot(session_id, &snapshot),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_snapshot_single_active(&kmes_snapshot),
			-ENOENT);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
	KUNIT_EXPECT_EQ(test, kacs_rust_kunit_session_snapshot(session_id, &snapshot),
			-EACCES);
}


static void pkm_kunit_destroy_empty_session_missing_returns_enoent(
	struct kunit *test)
{
	const void *subject_token;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_destroy_empty_session_for_subject(
				subject_token, ~0ULL),
			(long)-ENOENT);
}


static void pkm_kunit_current_token_resolution(struct kunit *test)
{
	struct pkm_kacs_resolved_ctx effective = { };
	struct pkm_kacs_resolved_ctx primary = { };
	const void *effective_token;
	const void *primary_token;
	long ret;

	effective_token = pkm_kacs_current_effective_token_ptr();
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, effective_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	ret = pkm_kacs_resolve_current_effective_ctx(&effective);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, effective.kind, PKM_KACS_RESOLVED_CTX_TOKEN);
	KUNIT_EXPECT_EQ(test, effective._reserved, 0U);
	KUNIT_EXPECT_PTR_EQ(test, effective.token, effective_token);
	KUNIT_EXPECT_PTR_EQ(test, effective.caap_cache, NULL);
	KUNIT_EXPECT_EQ(test, effective.default_pip_type, 0U);
	KUNIT_EXPECT_EQ(test, effective.default_pip_trust, 0U);

	ret = pkm_kacs_resolve_current_primary_ctx(&primary);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, primary.kind, PKM_KACS_RESOLVED_CTX_TOKEN);
	KUNIT_EXPECT_EQ(test, primary._reserved, 0U);
	KUNIT_EXPECT_PTR_EQ(test, primary.token, primary_token);
	KUNIT_EXPECT_PTR_EQ(test, primary.caap_cache, NULL);
	KUNIT_EXPECT_EQ(test, primary.default_pip_type, 0U);
	KUNIT_EXPECT_EQ(test, primary.default_pip_trust, 0U);
}


static void pkm_kunit_projected_fsids_follow_effective_token(
	struct kunit *test)
{
	const void *token = NULL;
	u32 fsuid = 0;
	u32 fsgid = 0;

	KUNIT_ASSERT_EQ(test,
			kacs_rust_create_anonymous_impersonation_token(
				&token),
			0);
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_projected_fsids_for_subject(
				token, 1234U, 1235U, &fsuid, &fsgid),
			0);
	KUNIT_EXPECT_EQ(test, fsuid, 65534U);
	KUNIT_EXPECT_EQ(test, fsgid, 65534U);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_projected_fsids_fallback_to_raw_without_token(
	struct kunit *test)
{
	u32 fsuid = 0;
	u32 fsgid = 0;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_projected_fsids_for_subject(
				NULL, 1234U, 1235U, &fsuid, &fsgid),
			0);
	KUNIT_EXPECT_EQ(test, fsuid, 1234U);
	KUNIT_EXPECT_EQ(test, fsgid, 1235U);
}


static void pkm_kunit_token_projection_sets_linux_cred_fields(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'P', 'r', 'o', 'j', 'C', 'r', 'e', 'd',
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
	};
	static const u32 supplementary_gids[] = {
		7002U, 7001U,
	};
	struct pkm_kacs_kunit_cred_projection_view projection = { };
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0U,
		.projected_uid = 4321U,
		.projected_gid = 5432U,
		.owner_sid_index = 1U,
		.primary_group_index = 1U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
		.projected_supplementary_gids = supplementary_gids,
		.projected_supplementary_gid_count =
			ARRAY_SIZE(supplementary_gids),
	};
	u8 session_spec[96] = { };
	u8 token_spec[512] = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t spec_len;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Negotiate",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	spec_len = pkm_kunit_build_token_spec(token_spec, sizeof(token_spec),
					      &spec_args);
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						    spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test, pkm_kacs_kunit_token_fd_snapshot((int)fd, &view),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_prepare_projected_cred_for_subject(
				view.token, &projection),
			0);
	KUNIT_EXPECT_EQ(test, projection.uid, 4321U);
	KUNIT_EXPECT_EQ(test, projection.euid, 4321U);
	KUNIT_EXPECT_EQ(test, projection.suid, 4321U);
	KUNIT_EXPECT_EQ(test, projection.fsuid, 4321U);
	KUNIT_EXPECT_EQ(test, projection.gid, 5432U);
	KUNIT_EXPECT_EQ(test, projection.egid, 5432U);
	KUNIT_EXPECT_EQ(test, projection.sgid, 5432U);
	KUNIT_EXPECT_EQ(test, projection.fsgid, 5432U);
	KUNIT_EXPECT_EQ(test, projection.projected_fsuid, 4321U);
	KUNIT_EXPECT_EQ(test, projection.projected_fsgid, 5432U);
	KUNIT_EXPECT_EQ(test, projection.group_count, 2U);
	KUNIT_EXPECT_EQ(test, projection.groups[0], 7001U);
	KUNIT_EXPECT_EQ(test, projection.groups[1], 7002U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_token_install_projection_preserves_impersonation_split(
	struct kunit *test)
{
	const void *old_primary_token;
	const void *new_primary_token = NULL;
	const void *client_token = NULL;
	long old_fd = -1;
	long install_fd = -1;
	long impersonation_fd = -1;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	old_primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, old_primary_token);

	old_fd = pkm_kacs_open_self_token_internal(KACS_TOKEN_OPEN_REAL,
						   KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, old_fd, 0L);

	new_primary_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, new_primary_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	install_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, new_primary_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, install_fd, 0L);
	impersonation_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, impersonation_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)impersonation_fd,
						 old_primary_token);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	pkm_kunit_expect_linux_cred_projection(test, current_cred(), 0U, 0U);
	pkm_kunit_expect_linux_cred_projection(test, current_real_cred(), 0U,
					       0U);

	ret = pkm_kacs_kunit_token_fd_install((int)install_fd,
						 old_primary_token);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    new_primary_token);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  new_primary_token);
	pkm_kunit_expect_linux_cred_projection(test, current_real_cred(),
					       65534U, 65534U);
	pkm_kunit_expect_linux_cred_projection(test, current_cred(), 0U, 0U);

	ret = pkm_kacs_revert_impersonation();
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    new_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    new_primary_token);
	pkm_kunit_expect_linux_cred_projection(test, current_cred(), 65534U,
					       65534U);
	pkm_kunit_expect_linux_cred_projection(test, current_real_cred(),
					       65534U, 65534U);

	ret = pkm_kacs_kunit_token_fd_install(
		(int)old_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    old_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    old_primary_token);
	pkm_kunit_expect_linux_cred_projection(test, current_cred(), 0U, 0U);
	pkm_kunit_expect_linux_cred_projection(test, current_real_cred(), 0U,
					       0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)impersonation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)install_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)old_fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(new_primary_token);
}


static void pkm_kunit_token_deep_copy_independent(struct kunit *test)
{
	struct pkm_kacs_boot_snapshot original = { };
	struct pkm_kacs_boot_snapshot copied = { };
	const void *copy;

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_boot_snapshot(&original));

	copy = kacs_rust_token_deep_copy(original.token_ptr);
	KUNIT_ASSERT_NOT_NULL(test, copy);
	KUNIT_EXPECT_TRUE(test, copy != original.token_ptr);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(copy, &copied));

	KUNIT_EXPECT_NE(test, copied.token_id, original.token_id);
	pkm_kunit_expect_guid_v4(test, copied.token_guid);
	pkm_kunit_expect_guid_ne(test, copied.token_guid,
				 original.token_guid);
	KUNIT_EXPECT_EQ(test, copied.modified_id, copied.token_id);
	pkm_kunit_expect_boot_snapshot_eq_except_identity(test, &original,
							  &copied);
	kacs_rust_token_drop(copy);
}


static void pkm_kunit_token_lowered_impersonation_clone_gets_fresh_identity(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot source = { };
	struct pkm_kacs_boot_snapshot expected = { };
	struct pkm_kacs_boot_snapshot lowered_snapshot = { };
	const void *lowered = NULL;
	const void *token;

	token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &source));

	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_clone_with_impersonation_level(
				token, KACS_IMLEVEL_IDENTIFICATION, &lowered),
			0);
	KUNIT_ASSERT_NOT_NULL(test, lowered);
	KUNIT_EXPECT_TRUE(test, lowered != token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(lowered,
							 &lowered_snapshot));

	expected = source;
	expected.impersonation_level = KACS_IMLEVEL_IDENTIFICATION;
	KUNIT_EXPECT_NE(test, lowered_snapshot.token_id, source.token_id);
	pkm_kunit_expect_guid_v4(test, lowered_snapshot.token_guid);
	pkm_kunit_expect_guid_ne(test, lowered_snapshot.token_guid,
				 source.token_guid);
	KUNIT_EXPECT_EQ(test, lowered_snapshot.modified_id,
			lowered_snapshot.token_id);
	pkm_kunit_expect_boot_snapshot_eq_except_identity(
		test, &expected, &lowered_snapshot);

	kacs_rust_token_drop(lowered);
	kacs_rust_token_drop(token);
}


static void pkm_kunit_token_created_at_preserved_by_derivations(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot source_snapshot = { };
	struct pkm_kacs_boot_snapshot duplicate_snapshot = { };
	struct pkm_kacs_boot_snapshot restricted_snapshot = { };
	struct pkm_kacs_boot_snapshot lowered_snapshot = { };
	const void *duplicate = NULL;
	const void *restricted = NULL;
	const void *lowered = NULL;
	const void *source;
	u8 payload[64] = { };
	size_t payload_len;

	source = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, source);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(source,
							 &source_snapshot));

	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_duplicate(
				source, source, KACS_TOKEN_TYPE_IMPERSONATION,
				KACS_IMLEVEL_IDENTIFICATION, &duplicate),
			0);
	KUNIT_ASSERT_NOT_NULL(test, duplicate);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(duplicate,
							 &duplicate_snapshot));
	KUNIT_EXPECT_NE(test, duplicate_snapshot.token_id,
			source_snapshot.token_id);
	pkm_kunit_expect_guid_v4(test, duplicate_snapshot.token_guid);
	pkm_kunit_expect_guid_ne(test, duplicate_snapshot.token_guid,
				 source_snapshot.token_guid);
	KUNIT_EXPECT_EQ(test, duplicate_snapshot.created_at,
			source_snapshot.created_at);

	payload_len = pkm_kunit_build_restrict_payload(
		payload, (u32[]){ 0U }, 1, source_snapshot.groups_ptr, 1);
	KUNIT_ASSERT_GT(test, (long)payload_len, 0L);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_restrict(source, source, 0ULL, 0U,
						 payload, payload_len, 1U, 1U,
						 &restricted),
			0);
	KUNIT_ASSERT_NOT_NULL(test, restricted);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(restricted,
							 &restricted_snapshot));
	KUNIT_EXPECT_NE(test, restricted_snapshot.token_id,
			source_snapshot.token_id);
	pkm_kunit_expect_guid_v4(test, restricted_snapshot.token_guid);
	pkm_kunit_expect_guid_ne(test, restricted_snapshot.token_guid,
				 source_snapshot.token_guid);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.created_at,
			source_snapshot.created_at);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_new_process_min_exec(
				source, PKM_KUNIT_IL_LOW, &lowered),
			0);
	KUNIT_ASSERT_NOT_NULL(test, lowered);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(lowered,
							 &lowered_snapshot));
	KUNIT_EXPECT_NE(test, lowered_snapshot.token_id,
			source_snapshot.token_id);
	pkm_kunit_expect_guid_v4(test, lowered_snapshot.token_guid);
	pkm_kunit_expect_guid_ne(test, lowered_snapshot.token_guid,
				 source_snapshot.token_guid);
	KUNIT_EXPECT_EQ(test, lowered_snapshot.created_at,
			source_snapshot.created_at);

	kacs_rust_token_drop(lowered);
	kacs_rust_token_drop(restricted);
	kacs_rust_token_drop(duplicate);
	kacs_rust_token_drop(source);
}


static void pkm_kunit_token_expiration_not_enforced_by_access_check(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'E', 'x', 'p', 'i', 'r', 'e', 'd', 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
		{
			.sid = pkm_kunit_authenticated_users_sid,
			.sid_len = sizeof(pkm_kunit_authenticated_users_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	struct pkm_kacs_token_fd_view view = { };
	struct kacs_query_args query = {
		.token_class = KACS_TOKEN_CLASS_STATISTICS,
		.buf_len = 40U,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_SYSTEM,
		.mandatory_policy = 0x00000003U,
		.expiration = 1ULL,
		.owner_sid_index = 1U,
		.primary_group_index = 1U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	u8 stats[40] = { };
	const void *subject_token;
	const u8 *file_sd;
	u64 session_id = 0;
	u32 granted = 0;
	size_t file_sd_len = 0;
	size_t spec_len;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_SERVICE, "Negotiate",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	spec_len = pkm_kunit_build_token_spec(token_spec, sizeof(token_spec),
					      &spec_args);
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view),
			0);

	query.buf_ptr = (u64)(unsigned long)stats;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &query, stats),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(stats, 32), 1ULL);

	file_sd = kacs_rust_kunit_create_file_sd(
		view.token, PKM_KUNIT_FILE_READ_DATA, 0U, 0U, 0U,
		&file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_check_file_sd_with_intent(
				view.token, file_sd, file_sd_len,
				PKM_KUNIT_FILE_READ_DATA, 0U, 0U, 0U, &granted),
			0);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_FILE_READ_DATA);

	pkm_kacs_free((void *)file_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_session_metadata_not_enforced_by_access_check(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'S', 'e', 's', 's', 'M', 'e', 't', 'a',
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
	};
	struct kacs_query_args stats_query = {
		.token_class = KACS_TOKEN_CLASS_STATISTICS,
		.buf_len = 40U,
	};
	struct kacs_query_args interactive_query = {
		.token_class = KACS_TOKEN_CLASS_SESSION_ID,
		.buf_len = 4U,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_SYSTEM,
		.mandatory_policy = 0x00000003U,
		.expiration = 0x0102030405060708ULL,
		.owner_sid_index = 1U,
		.primary_group_index = 1U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
		.interactive_session_id = 77U,
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	u8 stats[40] = { };
	u8 interactive_id[4] = { };
	const void *subject_token;
	u64 session_id = 0;
	u32 granted = 0;
	size_t spec_len;
	long fd;
	long ret;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_SERVICE, "Negotiate",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	spec_len = pkm_kunit_build_token_spec(token_spec, sizeof(token_spec),
					      &spec_args);
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);

	stats_query.buf_ptr = (u64)(unsigned long)stats;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &stats_query,
						      stats),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(stats, 8), session_id);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(stats, 32),
			0x0102030405060708ULL);

	interactive_query.buf_ptr = (u64)(unsigned long)interactive_id;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd,
						      &interactive_query,
						      interactive_id),
			0L);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(interactive_id, 0), 77U);

	ret = pkm_kunit_run_read_control_with_token_fd(
		(int)fd, pkm_kunit_everyone_read_sd,
		sizeof(pkm_kunit_everyone_read_sd), &granted);
	KUNIT_EXPECT_EQ(test, ret, (long)KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, granted, KACS_ACCESS_READ_CONTROL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_create_token_same_sid_creator_keeps_self_limited(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'S', 'a', 'm', 'e', 'S', 'i', 'd', 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_SYSTEM,
		.mandatory_policy = 0x00000003U,
		.owner_sid_index = 0U,
		.primary_group_index = 1U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot snapshot = { };
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	const void *creator_token;
	u64 session_id = 0;
	size_t spec_len;
	long fd;
	long query_fd;

	creator_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U,
		PKM_KUNIT_SE_TCB_PRIVILEGE |
			PKM_KUNIT_SE_CREATE_TOKEN_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, creator_token);

	spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_SERVICE, "Negotiate",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				creator_token, session_spec, spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	spec_len = pkm_kunit_build_token_spec(token_spec, sizeof(token_spec),
					      &spec_args);
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	fd = pkm_kacs_kunit_create_token_for_subject(creator_token, token_spec,
						     spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token,
							 &snapshot));

	pkm_kunit_expect_owner_rights_read_control_ace(
		test, snapshot.own_sd_ptr, snapshot.own_sd_len, 0);
	pkm_kunit_expect_allow_ace(test, snapshot.own_sd_ptr,
				   snapshot.own_sd_len, 1,
				   PKM_KUNIT_DEFAULT_TOKEN_SELF_ACCESS,
				   pkm_kunit_local_service_sid,
				   sizeof(pkm_kunit_local_service_sid));
	pkm_kunit_expect_allow_ace(test, snapshot.own_sd_ptr,
				   snapshot.own_sd_len, 2, KACS_TOKEN_ALL_ACCESS,
				   pkm_kunit_system_sid,
				   sizeof(pkm_kunit_system_sid));
	KUNIT_EXPECT_PTR_EQ(test,
			    pkm_kunit_dacl_ace_const(snapshot.own_sd_ptr,
						     snapshot.own_sd_len, 3),
			    NULL);

	query_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		creator_token, view.token, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, query_fd, 0L);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)query_fd), 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_token_fd_for_subject(
				creator_token, view.token, KACS_TOKEN_DUPLICATE),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_token_fd_for_subject(
				creator_token, view.token,
				KACS_TOKEN_IMPERSONATE),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_token_fd_for_subject(
				creator_token, view.token,
				KACS_ACCESS_WRITE_DAC),
			(long)-EACCES);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(creator_token);
}


static void pkm_kunit_create_token_distinct_sid_default_sd_template(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'D', 'e', 'f', 'S', 'd', '0', '1', 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_SYSTEM,
		.mandatory_policy = 0x00000003U,
		.owner_sid_index = 0U,
		.primary_group_index = 1U,
		.source_name = source_name,
		.user_sid = pkm_kunit_system_sid,
		.user_sid_len = sizeof(pkm_kunit_system_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot snapshot = { };
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	const void *creator_token;
	u64 session_id = 0;
	size_t spec_len;
	long fd;

	creator_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0U,
		PKM_KUNIT_SE_TCB_PRIVILEGE |
			PKM_KUNIT_SE_CREATE_TOKEN_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, creator_token);

	spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_SERVICE, "Negotiate",
		pkm_kunit_system_sid, sizeof(pkm_kunit_system_sid));
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				creator_token, session_spec, spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	spec_len = pkm_kunit_build_token_spec(token_spec, sizeof(token_spec),
					      &spec_args);
	KUNIT_ASSERT_GT(test, (long)spec_len, 0L);
	fd = pkm_kacs_kunit_create_token_for_subject(creator_token, token_spec,
						     spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token,
							 &snapshot));

	pkm_kunit_expect_sd_sid_component(test, snapshot.own_sd_ptr,
					  snapshot.own_sd_len, 4,
					  pkm_kunit_local_service_sid,
					  sizeof(pkm_kunit_local_service_sid));
	pkm_kunit_expect_sd_sid_component(test, snapshot.own_sd_ptr,
					  snapshot.own_sd_len, 8,
					  pkm_kunit_local_service_sid,
					  sizeof(pkm_kunit_local_service_sid));
	pkm_kunit_expect_allow_ace(test, snapshot.own_sd_ptr,
				   snapshot.own_sd_len, 0,
				   PKM_KUNIT_DEFAULT_TOKEN_SELF_ACCESS,
				   pkm_kunit_system_sid,
				   sizeof(pkm_kunit_system_sid));
	pkm_kunit_expect_allow_ace(test, snapshot.own_sd_ptr,
				   snapshot.own_sd_len, 1, KACS_TOKEN_ALL_ACCESS,
				   pkm_kunit_local_service_sid,
				   sizeof(pkm_kunit_local_service_sid));
	pkm_kunit_expect_allow_ace(test, snapshot.own_sd_ptr,
				   snapshot.own_sd_len, 2, KACS_TOKEN_ALL_ACCESS,
				   pkm_kunit_system_sid,
				   sizeof(pkm_kunit_system_sid));
	KUNIT_EXPECT_PTR_EQ(test,
			    pkm_kunit_dacl_ace_const(snapshot.own_sd_ptr,
						     snapshot.own_sd_len, 3),
			    NULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(creator_token);
}


static void pkm_kunit_token_query_source_only_denied(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_USER,
	};
	struct pkm_kacs_token_fd_view view = { };
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY_SOURCE);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY_SOURCE);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_token_fd_shared_file_preserves_cached_mask(
	struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_USER,
	};
	struct pkm_kacs_token_fd_view original = { };
	struct pkm_kacs_token_fd_view duplicate = { };
	long fd;
	int duplicate_fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY_SOURCE);
	KUNIT_ASSERT_GE(test, fd, 0L);
	duplicate_fd = pkm_kunit_dup_fd_same_file((int)fd);
	KUNIT_ASSERT_GE(test, duplicate_fd, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &original),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(duplicate_fd,
							 &duplicate),
			0);
	KUNIT_EXPECT_PTR_EQ(test, duplicate.token, original.token);
	KUNIT_EXPECT_EQ(test, duplicate.access_mask, KACS_TOKEN_QUERY_SOURCE);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query(duplicate_fd, &args, NULL),
			(long)-EACCES);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)duplicate_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_token_fd_holds_ref_after_source_drop(struct kunit *test)
{
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot expected = { };
	struct pkm_kacs_boot_snapshot held = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token,
							 &expected));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	kacs_rust_token_drop(target_token);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(view.token, &held));
	pkm_kunit_expect_boot_snapshot_eq(test, &expected, &held);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_identity_guid_accessors(struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view process_view = { };
	struct pkm_kacs_boot_snapshot primary_snapshot = { };
	struct pkm_kacs_boot_snapshot client_snapshot = { };
	kacs_uuid_t effective_guid;
	kacs_uuid_t primary_guid;
	kacs_uuid_t process_guid;
	const void *primary_token;
	const void *client_token;
	const void *state;
	long fd;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	state = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);
	KUNIT_ASSERT_NOT_NULL(test, state);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(primary_token,
							 &primary_snapshot));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state,
							      &process_view),
			0);

	effective_guid = kacs_effective_token_guid();
	primary_guid = kacs_primary_token_guid();
	process_guid = kacs_process_guid();
	pkm_kunit_expect_guid_v4(test, primary_snapshot.token_guid);
	pkm_kunit_expect_guid_eq(test, effective_guid.bytes,
				 primary_snapshot.token_guid);
	pkm_kunit_expect_guid_eq(test, primary_guid.bytes,
				 primary_snapshot.token_guid);
	pkm_kunit_expect_guid_eq(test, process_guid.bytes,
				 process_view.process_guid);

	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(client_token,
							 &client_snapshot));
	pkm_kunit_expect_guid_v4(test, client_snapshot.token_guid);
	pkm_kunit_expect_guid_ne(test, client_snapshot.token_guid,
				 primary_snapshot.token_guid);
	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_impersonate((int)fd,
							   primary_token),
			0L);

	effective_guid = kacs_effective_token_guid();
	primary_guid = kacs_primary_token_guid();
	process_guid = kacs_process_guid();
	pkm_kunit_expect_guid_eq(test, effective_guid.bytes,
				 client_snapshot.token_guid);
	pkm_kunit_expect_guid_eq(test, primary_guid.bytes,
				 primary_snapshot.token_guid);
	pkm_kunit_expect_guid_eq(test, process_guid.bytes,
				 process_view.process_guid);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_shared_token_adjustment_mutations_visible(
	struct kunit *test)
{
	{
		struct pkm_kacs_priv_adjust_entry entry = {
			.luid = PKM_KUNIT_PRIV_LUID_DISABLE,
			.attributes = 0,
		};
		struct pkm_kacs_boot_snapshot before = { };
		struct pkm_kacs_boot_snapshot shared_before = { };
		struct pkm_kacs_boot_snapshot shared_after = { };
		const void *source;
		const void *shared;
		u64 previous_enabled = 0;

		source = kacs_rust_kunit_create_adjustable_privileges_token();
		KUNIT_ASSERT_NOT_NULL(test, source);
		shared = kacs_rust_token_clone(source);
		KUNIT_ASSERT_NOT_NULL(test, shared);
		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(source,
								 &before));
		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(
					  shared, &shared_before));
		pkm_kunit_expect_boot_snapshot_scalars_eq(test, &before,
							  &shared_before);

		KUNIT_ASSERT_EQ(test,
				kacs_rust_token_adjust_privs(source, &entry, 1,
							     &previous_enabled),
				0);
		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(
					  shared, &shared_after));
		KUNIT_EXPECT_EQ(test, shared_after.modified_id,
				before.modified_id + 1);
		KUNIT_EXPECT_EQ(test, shared_after.privileges_enabled,
				before.privileges_enabled &
					~(1ULL << PKM_KUNIT_PRIV_LUID_DISABLE));

		kacs_rust_token_drop(shared);
		kacs_rust_token_drop(source);
	}

	{
		struct pkm_kacs_group_adjust_entry entry = {
			.index = 0,
			.enable = 0,
		};
		struct pkm_kacs_boot_snapshot before = { };
		struct pkm_kacs_boot_snapshot shared_before = { };
		struct pkm_kacs_boot_snapshot shared_after = { };
		const void *source;
		const void *shared;
		u64 previous_state[KACS_TOKEN_GROUP_MASK_WORDS] = {0};

		source = kacs_rust_kunit_create_adjustable_groups_token();
		KUNIT_ASSERT_NOT_NULL(test, source);
		shared = kacs_rust_token_clone(source);
		KUNIT_ASSERT_NOT_NULL(test, shared);
		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(source,
								 &before));
		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(
					  shared, &shared_before));
		pkm_kunit_expect_boot_snapshot_scalars_eq(test, &before,
							  &shared_before);

		KUNIT_ASSERT_EQ(test,
				kacs_rust_token_adjust_groups(source, &entry, 1,
							      previous_state),
				0);
		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(
					  shared, &shared_after));
		KUNIT_EXPECT_EQ(test, shared_after.modified_id,
				before.modified_id + 1);
		KUNIT_EXPECT_EQ(test, shared_after.groups_ptr[0].attributes,
				before.groups_ptr[0].attributes &
					~PKM_KUNIT_SE_GROUP_ENABLED);

		kacs_rust_token_drop(shared);
		kacs_rust_token_drop(source);
	}

	{
		struct pkm_kacs_boot_snapshot before = { };
		struct pkm_kacs_boot_snapshot shared_before = { };
		struct pkm_kacs_boot_snapshot shared_after = { };
		const void *source;
		const void *shared;

		source = kacs_rust_kunit_create_query_only_token();
		KUNIT_ASSERT_NOT_NULL(test, source);
		shared = kacs_rust_token_clone(source);
		KUNIT_ASSERT_NOT_NULL(test, shared);
		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(source,
								 &before));
		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(
					  shared, &shared_before));
		pkm_kunit_expect_boot_snapshot_scalars_eq(test, &before,
							  &shared_before);

		KUNIT_ASSERT_EQ(test,
				kacs_rust_token_adjust_default(
					source,
					PKM_KUNIT_TOKEN_INDEX_NO_CHANGE,
					PKM_KUNIT_TOKEN_INDEX_NO_CHANGE,
					pkm_kunit_replacement_default_dacl,
					sizeof(pkm_kunit_replacement_default_dacl),
					1U),
				0);
		KUNIT_ASSERT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(
					  shared, &shared_after));
		KUNIT_EXPECT_EQ(test, shared_after.modified_id,
				before.modified_id + 1);
		pkm_kunit_expect_bytes_eq(
			test, shared_after.default_dacl_ptr,
			shared_after.default_dacl_len,
			pkm_kunit_replacement_default_dacl,
			sizeof(pkm_kunit_replacement_default_dacl));

		kacs_rust_token_drop(shared);
		kacs_rust_token_drop(source);
	}
}


static void pkm_kunit_thread_token_inspection_returns_impersonation_token(
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
	target_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
		KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_MEDIUM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_create_default_process_sd(subject_token,
							 &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;

	fd = pkm_kacs_kunit_open_thread_token_inspection_for_subject(&args);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_PTR_EQ(test, view.token, target_token);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)fd,
						  KACS_TOKEN_CLASS_TYPE),
			KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)fd,
						  KACS_TOKEN_CLASS_IMPERSONATION_LEVEL),
			KACS_IMLEVEL_IMPERSONATION);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_thread_token_inspection_self_bypasses_process_sd(
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
	target_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
		KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_MEDIUM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	process_sd = kacs_rust_kunit_create_query_limited_process_sd(
		subject_token, &process_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, process_sd);
	args.subject_token = subject_token;
	args.target_token = target_token;
	args.target_process_sd_ptr = process_sd;
	args.target_process_sd_len = process_sd_len;
	args.self_target = 1;

	fd = pkm_kacs_kunit_open_thread_token_inspection_for_subject(&args);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_PTR_EQ(test, view.token, target_token);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)fd,
						  KACS_TOKEN_CLASS_TYPE),
			KACS_TOKEN_TYPE_IMPERSONATION);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	pkm_kacs_free((void *)process_sd);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_duplicate_primary_to_impersonation(
	struct kunit *test)
{
	struct kacs_duplicate_args args = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_IMPERSONATION,
		.impersonation_level = KACS_IMLEVEL_DELEGATION,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot original = { };
	struct pkm_kacs_boot_snapshot duplicate = { };
	struct pkm_kacs_token_fd_view view = { };
	const void *subject_token;
	const void *creator_token;
	long source_fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	creator_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, creator_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(creator_token,
							 &original));

	source_fd = pkm_kacs_open_self_token_internal(KACS_TOKEN_OPEN_REAL,
						      KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, source_fd, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_duplicate(
				(int)source_fd, subject_token,
				creator_token, &args),
			0);
	KUNIT_ASSERT_GE(test, (long)args.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(args.result_fd, &view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token,
							 &duplicate));
	KUNIT_EXPECT_TRUE(test, view.token != creator_token);
	KUNIT_EXPECT_PTR_EQ(test, duplicate.session_ptr, original.session_ptr);
	KUNIT_EXPECT_EQ(test, duplicate.session_id, original.session_id);
	KUNIT_EXPECT_TRUE(test, duplicate.token_id != original.token_id);
	KUNIT_EXPECT_EQ(test, duplicate.modified_id, duplicate.token_id);
	KUNIT_EXPECT_EQ(test, duplicate.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, duplicate.impersonation_level,
			(u32)KACS_IMLEVEL_DELEGATION);
	pkm_kunit_expect_bytes_eq(test, duplicate.user_sid_ptr,
				  duplicate.user_sid_len,
				  original.user_sid_ptr,
				  original.user_sid_len);
	KUNIT_EXPECT_EQ(test, duplicate.privileges_present,
			original.privileges_present);
	KUNIT_EXPECT_EQ(test, duplicate.privileges_enabled,
			original.privileges_enabled);
	KUNIT_EXPECT_EQ(test, duplicate.privileges_enabled_by_default,
			original.privileges_enabled_by_default);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
}


static void pkm_kunit_token_duplicate_impersonation_level_escalation_fails_closed(
	struct kunit *test)
{
	struct kacs_duplicate_args args = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_IMPERSONATION,
		.impersonation_level = KACS_IMLEVEL_IMPERSONATION,
		.result_fd = -1,
	};
	const void *source_token;
	const void *subject_token;
	const void *creator_token;
	long source_fd;
	long ret;

	source_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IDENTIFICATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	subject_token = pkm_kacs_current_effective_token_ptr();
	creator_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, source_token);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, creator_token);

	source_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, source_token, KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, source_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_duplicate((int)source_fd, subject_token,
						 creator_token, &args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, args.result_fd, -1);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
	kacs_rust_token_drop(source_token);
}


static void pkm_kunit_token_duplicate_impersonation_lowers_level(
	struct kunit *test)
{
	struct kacs_duplicate_args args = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_IMPERSONATION,
		.impersonation_level = KACS_IMLEVEL_IDENTIFICATION,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot source = { };
	struct pkm_kacs_boot_snapshot expected = { };
	struct pkm_kacs_boot_snapshot duplicate = { };
	struct pkm_kacs_token_fd_view view = { };
	const void *source_token;
	const void *subject_token;
	const void *creator_token;
	long source_fd;

	source_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	subject_token = pkm_kacs_current_effective_token_ptr();
	creator_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, source_token);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, creator_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(source_token, &source));

	source_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, source_token, KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, source_fd, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_duplicate(
				(int)source_fd, subject_token,
				creator_token, &args),
			0);
	KUNIT_ASSERT_GE(test, (long)args.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(args.result_fd, &view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token,
							 &duplicate));
	KUNIT_EXPECT_EQ(test, duplicate.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, duplicate.impersonation_level,
			(u32)KACS_IMLEVEL_IDENTIFICATION);
	KUNIT_EXPECT_TRUE(test, duplicate.token_id != source.token_id);
	KUNIT_EXPECT_EQ(test, duplicate.modified_id, duplicate.token_id);
	expected = source;
	expected.impersonation_level = KACS_IMLEVEL_IDENTIFICATION;
	pkm_kunit_expect_boot_snapshot_eq_except_identity(test, &expected,
							  &duplicate);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
	kacs_rust_token_drop(source_token);
}


static void pkm_kunit_token_duplicate_new_handle_checks_new_token_sd_against_subject(
	struct kunit *test)
{
	struct kacs_duplicate_args args = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_DELEGATION,
		.result_fd = -1,
	};
	const void *subject_token;
	const void *creator_token;
	long source_fd;
	long ret;

	subject_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	creator_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, creator_token);

	source_fd = pkm_kacs_open_self_token_internal(KACS_TOKEN_OPEN_REAL,
						      KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, source_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_duplicate((int)source_fd, subject_token,
						 creator_token, &args);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, args.result_fd, -1);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
	kacs_rust_token_drop(subject_token);
}


static void pkm_kunit_token_duplicate_primary_to_impersonation_all_levels(
	struct kunit *test)
{
	static const u32 levels[] = {
		KACS_IMLEVEL_ANONYMOUS,
		KACS_IMLEVEL_IDENTIFICATION,
		KACS_IMLEVEL_IMPERSONATION,
		KACS_IMLEVEL_DELEGATION,
	};
	struct kacs_duplicate_args args = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_IMPERSONATION,
		.result_fd = -1,
	};
	const void *subject_token;
	const void *creator_token;
	long source_fd;
	u32 i;

	subject_token = pkm_kacs_current_effective_token_ptr();
	creator_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, creator_token);

	source_fd = pkm_kacs_open_self_token_internal(KACS_TOKEN_OPEN_REAL,
						      KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, source_fd, 0L);

	for (i = 0; i < ARRAY_SIZE(levels); i++) {
		args.impersonation_level = levels[i];
		args.result_fd = -1;
		KUNIT_ASSERT_EQ(test,
				pkm_kacs_kunit_token_fd_duplicate(
					(int)source_fd, subject_token,
					creator_token, &args),
				0);
		KUNIT_ASSERT_GE(test, (long)args.result_fd, 0L);
		KUNIT_EXPECT_EQ(test,
				pkm_kunit_query_token_u32(
					test, args.result_fd,
					KACS_TOKEN_CLASS_TYPE),
				KACS_TOKEN_TYPE_IMPERSONATION);
		KUNIT_EXPECT_EQ(test,
				pkm_kunit_query_token_u32(
					test, args.result_fd,
					KACS_TOKEN_CLASS_IMPERSONATION_LEVEL),
				levels[i]);
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)args.result_fd),
				0);
	}

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
}


static void pkm_kunit_token_duplicate_impersonation_to_primary_forces_anonymous(
	struct kunit *test)
{
	struct kacs_duplicate_args args = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_DELEGATION,
		.result_fd = -1,
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot duplicate = { };
	struct pkm_kacs_boot_snapshot source_before = { };
	struct pkm_kacs_boot_snapshot source_after = { };
	const void *source_token;
	const void *subject_token;
	const void *creator_token;
	long source_fd;

	source_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_DELEGATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	subject_token = pkm_kacs_current_effective_token_ptr();
	creator_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, source_token);
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	KUNIT_ASSERT_NOT_NULL(test, creator_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(source_token,
							 &source_before));

	source_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, source_token, KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, source_fd, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_duplicate(
				(int)source_fd, subject_token,
				creator_token, &args),
			0);
	KUNIT_ASSERT_GE(test, (long)args.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(args.result_fd, &view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token,
							 &duplicate));
	KUNIT_EXPECT_EQ(test, duplicate.token_type,
			(u32)KACS_TOKEN_TYPE_PRIMARY);
	KUNIT_EXPECT_EQ(test, duplicate.impersonation_level,
			(u32)KACS_IMLEVEL_ANONYMOUS);
	KUNIT_EXPECT_TRUE(test, duplicate.token_id != source_before.token_id);
	KUNIT_EXPECT_EQ(test, duplicate.modified_id, duplicate.token_id);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(source_token,
							 &source_after));
	pkm_kunit_expect_boot_snapshot_eq(test, &source_before, &source_after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
	kacs_rust_token_drop(source_token);
}


static void pkm_kunit_token_duplicate_linked_elevation_resets_default(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_duplicate_args args = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.result_fd = -1,
	};
	const void *caller_token;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_linked_pair(test, caller_token, &pair),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)pair.elevated_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_FULL);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)pair.filtered_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_LIMITED);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_duplicate(
				(int)pair.elevated_fd, caller_token,
				caller_token, &args),
			0);
	KUNIT_ASSERT_GE(test, (long)args.result_fd, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, args.result_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_DEFAULT);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)args.result_fd), 0);

	args.result_fd = -1;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_duplicate(
				(int)pair.filtered_fd, caller_token,
				caller_token, &args),
			0);
	KUNIT_ASSERT_GE(test, (long)args.result_fd, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, args.result_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_DEFAULT);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)args.result_fd), 0);

	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_duplicate_copies_field_matrix(struct kunit *test)
{
	static const u8 source_name[8] = {
		'D', 'u', 'p', 'M', 'a', 't', 'r', 'x',
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
		{
			.sid = pkm_kunit_authenticated_users_sid,
			.sid_len = sizeof(pkm_kunit_authenticated_users_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	static const struct pkm_kunit_sid_attr_spec restricted_sids[] = {
		{
			.sid = pkm_kunit_authenticated_users_sid,
			.sid_len = sizeof(pkm_kunit_authenticated_users_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	static const struct pkm_kunit_sid_attr_spec device_groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	static const struct pkm_kunit_sid_attr_spec restricted_device_groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = 0U,
		},
	};
	static const struct pkm_kunit_sid_attr_spec confinement_caps[] = {
		{
			.sid = pkm_kunit_all_restricted_application_packages_sid,
			.sid_len =
				sizeof(pkm_kunit_all_restricted_application_packages_sid),
			.attributes = 0U,
		},
	};
	static const u32 supplementary_gids[] = {
		7001U, 7002U,
	};
	static const u32 query_classes[] = {
		KACS_TOKEN_CLASS_USER,
		KACS_TOKEN_CLASS_GROUPS,
		KACS_TOKEN_CLASS_PRIVILEGES,
		KACS_TOKEN_CLASS_TYPE,
		KACS_TOKEN_CLASS_INTEGRITY_LEVEL,
		KACS_TOKEN_CLASS_OWNER,
		KACS_TOKEN_CLASS_PRIMARY_GROUP,
		KACS_TOKEN_CLASS_SESSION_ID,
		KACS_TOKEN_CLASS_RESTRICTED_SIDS,
		KACS_TOKEN_CLASS_SOURCE,
		KACS_TOKEN_CLASS_ORIGIN,
		KACS_TOKEN_CLASS_ELEVATION_TYPE,
		KACS_TOKEN_CLASS_DEVICE_GROUPS,
		KACS_TOKEN_CLASS_APPCONTAINER_SID,
		KACS_TOKEN_CLASS_CAPABILITIES,
		KACS_TOKEN_CLASS_MANDATORY_POLICY,
		KACS_TOKEN_CLASS_LOGON_TYPE,
		KACS_TOKEN_CLASS_LOGON_SID,
		KACS_TOKEN_CLASS_DEFAULT_DACL,
		KACS_TOKEN_CLASS_IMPERSONATION_LEVEL,
		KACS_TOKEN_CLASS_USER_CLAIMS,
		KACS_TOKEN_CLASS_DEVICE_CLAIMS,
		KACS_TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.privileges_present = PKM_KUNIT_SE_DEBUG_PRIVILEGE,
		.privileges_enabled = PKM_KUNIT_SE_DEBUG_PRIVILEGE,
		.projected_uid = 4321U,
		.projected_gid = 5432U,
		.audit_policy = PKM_KUNIT_AUDIT_POLICY_OBJECT_ACCESS_SUCCESS,
		.expiration = 0x1020304050607080ULL,
		.owner_sid_index = 1U,
		.primary_group_index = 2U,
		.source_name = source_name,
		.source_id = 0x8877665544332211ULL,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
		.default_dacl = pkm_kunit_replacement_default_dacl,
		.default_dacl_len = sizeof(pkm_kunit_replacement_default_dacl),
		.device_groups = device_groups,
		.device_group_count = ARRAY_SIZE(device_groups),
		.restricted_sids = restricted_sids,
		.restricted_sid_count = ARRAY_SIZE(restricted_sids),
		.confinement_sid = pkm_kunit_sample_confinement_sid,
		.confinement_sid_len = sizeof(pkm_kunit_sample_confinement_sid),
		.confinement_caps = confinement_caps,
		.confinement_cap_count = ARRAY_SIZE(confinement_caps),
		.confinement_exempt = 1U,
		.write_restricted = 1U,
		.user_deny_only = 1U,
		.isolation_boundary = 1U,
		.projected_supplementary_gids = supplementary_gids,
		.projected_supplementary_gid_count =
			ARRAY_SIZE(supplementary_gids),
		.restricted_device_groups = restricted_device_groups,
		.restricted_device_group_count =
			ARRAY_SIZE(restricted_device_groups),
		.origin = 0x0102030405060708ULL,
		.interactive_session_id = 12U,
	};
	struct kacs_duplicate_args duplicate = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_DELEGATION,
		.result_fd = -1,
	};
	struct kacs_query_args source_stats = {
		.token_class = KACS_TOKEN_CLASS_STATISTICS,
		.buf_len = 40U,
	};
	struct kacs_query_args duplicate_stats = {
		.token_class = KACS_TOKEN_CLASS_STATISTICS,
		.buf_len = 40U,
	};
	struct pkm_kacs_token_fd_view source_view = { };
	struct pkm_kacs_token_fd_view duplicate_view = { };
	struct pkm_kacs_boot_snapshot source_snapshot = { };
	struct pkm_kacs_boot_snapshot duplicate_snapshot = { };
	u8 session_spec[96] = { };
	u8 user_claim_entry[96] = { };
	u8 device_claim_entry[96] = { };
	u8 user_claims[128] = { };
	u8 device_claims[128] = { };
	u8 source_stats_buf[40] = { };
	u8 duplicate_stats_buf[40] = { };
	u8 *token_spec;
	const void *subject_token;
	size_t user_claims_len = 0;
	size_t device_claims_len = 0;
	size_t entry_len;
	size_t token_spec_len;
	u64 session_id = 0;
	long source_fd;
	u32 i;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	token_spec = kunit_kzalloc(test, 1536U, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, token_spec);

	entry_len = pkm_kunit_build_claim_entry_scalar(
		user_claim_entry, sizeof(user_claim_entry), "DupUser",
		PKM_KUNIT_CLAIM_TYPE_INT64, 0U, 123U);
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(
				user_claims, sizeof(user_claims),
				&user_claims_len, user_claim_entry, entry_len),
			0);
	entry_len = pkm_kunit_build_claim_entry_string(
		device_claim_entry, sizeof(device_claim_entry), "DupDevice",
		0U, "dev");
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(
				device_claims, sizeof(device_claims),
				&device_claims_len, device_claim_entry,
				entry_len),
			0);
	spec_args.user_claims = user_claims;
	spec_args.user_claims_len = user_claims_len;
	spec_args.device_claims = device_claims;
	spec_args.device_claims_len = device_claims_len;

	entry_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, entry_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec, 1536U,
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	source_fd = pkm_kacs_kunit_create_token_for_subject(
		subject_token, token_spec, token_spec_len);
	KUNIT_ASSERT_GE(test, source_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)source_fd,
							 &source_view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, source_view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_token_mark_privileges_used(
				  source_view.token,
				  PKM_KUNIT_SE_DEBUG_PRIVILEGE));
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(source_view.token,
							 &source_snapshot));

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_duplicate(
				(int)source_fd, subject_token,
				subject_token, &duplicate),
			0);
	KUNIT_ASSERT_GE(test, (long)duplicate.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(duplicate.result_fd,
							 &duplicate_view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, duplicate_view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  duplicate_view.token, &duplicate_snapshot));

	KUNIT_EXPECT_TRUE(test,
			  duplicate_snapshot.token_id !=
				  source_snapshot.token_id);
	KUNIT_EXPECT_EQ(test, duplicate_snapshot.modified_id,
			duplicate_snapshot.token_id);
	pkm_kunit_expect_boot_snapshot_eq_except_identity(
		test, &source_snapshot, &duplicate_snapshot);
	KUNIT_EXPECT_EQ(test, source_snapshot.elevation_type,
			KACS_ELEVATION_DEFAULT);
	KUNIT_EXPECT_EQ(test, duplicate_snapshot.elevation_type,
			KACS_ELEVATION_DEFAULT);
	KUNIT_EXPECT_EQ(test, duplicate_snapshot.restricted,
			source_snapshot.restricted);
	KUNIT_EXPECT_EQ(test, duplicate_snapshot.user_deny_only,
			source_snapshot.user_deny_only);
	KUNIT_EXPECT_EQ(test, duplicate_snapshot.write_restricted,
			source_snapshot.write_restricted);
	KUNIT_EXPECT_EQ(test, duplicate_snapshot.confinement_exempt,
			source_snapshot.confinement_exempt);
	KUNIT_EXPECT_EQ(test, duplicate_snapshot.isolation_boundary,
			source_snapshot.isolation_boundary);
	KUNIT_EXPECT_EQ(test, source_snapshot.restricted, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.user_deny_only, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.write_restricted, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.confinement_exempt, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.isolation_boundary, 1U);

	for (i = 0; i < ARRAY_SIZE(query_classes); i++)
		pkm_kunit_expect_token_query_payload_eq(
			test, (int)source_fd, duplicate.result_fd,
			query_classes[i]);

	source_stats.buf_ptr = (u64)(unsigned long)source_stats_buf;
	duplicate_stats.buf_ptr = (u64)(unsigned long)duplicate_stats_buf;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)source_fd,
						      &source_stats,
						      source_stats_buf),
			(long)0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query(duplicate.result_fd,
						      &duplicate_stats,
						      duplicate_stats_buf),
			(long)0);
	KUNIT_EXPECT_NE(test, pkm_kunit_read_u64(source_stats_buf, 0),
			pkm_kunit_read_u64(duplicate_stats_buf, 0));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(duplicate_stats_buf, 16),
			pkm_kunit_read_u64(duplicate_stats_buf, 0));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(source_stats_buf, 8),
			pkm_kunit_read_u64(duplicate_stats_buf, 8));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(source_stats_buf, 24),
			pkm_kunit_read_u32(duplicate_stats_buf, 24));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(source_stats_buf, 28),
			pkm_kunit_read_u32(duplicate_stats_buf, 28));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(source_stats_buf, 32),
			pkm_kunit_read_u64(duplicate_stats_buf, 32));

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)duplicate.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
	flush_delayed_fput();
}


static void pkm_kunit_token_duplicate_mutations_are_independent(
	struct kunit *test)
{
	struct kacs_duplicate_args duplicate = {
		.access_mask = KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_PRIVS,
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.result_fd = -1,
	};
	struct kacs_adjust_privs_args source_adjust = {
		.count = 2,
	};
	struct kacs_priv_entry source_entries[2] = {
		{ .luid = PKM_KUNIT_PRIV_LUID_DISABLE, .attributes = 0 },
		{ .luid = PKM_KUNIT_PRIV_LUID_ENABLE,
		  .attributes = PKM_KUNIT_SE_PRIVILEGE_ENABLED },
	};
	struct kacs_adjust_privs_args duplicate_adjust = {
		.count = 1,
	};
	struct kacs_priv_entry duplicate_entry = {
		.luid = PKM_KUNIT_PRIV_LUID_ENABLE,
		.attributes = PKM_KUNIT_SE_PRIVILEGE_ENABLED,
	};
	struct pkm_kacs_token_fd_view duplicate_view = { };
	struct pkm_kacs_boot_snapshot source_before = { };
	struct pkm_kacs_boot_snapshot duplicate_before = { };
	struct pkm_kacs_boot_snapshot source_after_source = { };
	struct pkm_kacs_boot_snapshot duplicate_after_source = { };
	struct pkm_kacs_boot_snapshot source_after_duplicate = { };
	struct pkm_kacs_boot_snapshot duplicate_after_duplicate = { };
	const void *subject_token;
	const void *source_token;
	long source_fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	source_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, source_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(source_token,
							 &source_before));

	source_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, source_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE |
			KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, source_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_duplicate(
				(int)source_fd, subject_token,
				subject_token, &duplicate),
			0);
	KUNIT_ASSERT_GE(test, (long)duplicate.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(duplicate.result_fd,
							 &duplicate_view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, duplicate_view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  duplicate_view.token, &duplicate_before));

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs(
				(int)source_fd, &source_adjust,
				source_entries),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  source_token, &source_after_source));
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  duplicate_view.token, &duplicate_after_source));
	KUNIT_EXPECT_EQ(test, source_after_source.privileges_enabled,
			PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_ENABLE_DISABLE);
	KUNIT_EXPECT_EQ(test, duplicate_after_source.privileges_enabled,
			duplicate_before.privileges_enabled);
	KUNIT_EXPECT_EQ(test, source_after_source.modified_id,
			source_before.modified_id + 1);
	KUNIT_EXPECT_EQ(test, duplicate_after_source.modified_id,
			duplicate_before.modified_id);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs(
				duplicate.result_fd, &duplicate_adjust,
				&duplicate_entry),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  source_token, &source_after_duplicate));
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  duplicate_view.token,
				  &duplicate_after_duplicate));
	KUNIT_EXPECT_EQ(test, source_after_duplicate.privileges_enabled,
			source_after_source.privileges_enabled);
	KUNIT_EXPECT_EQ(test, source_after_duplicate.modified_id,
			source_after_source.modified_id);
	KUNIT_EXPECT_NE(test, duplicate_after_duplicate.privileges_enabled,
			duplicate_after_source.privileges_enabled);
	KUNIT_EXPECT_EQ(test, duplicate_after_duplicate.modified_id,
			duplicate_after_source.modified_id + 1);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)duplicate.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
	kacs_rust_token_drop(source_token);
}


static void pkm_kunit_token_impersonate_caps_identification_without_privilege(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *server_token;
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_DELEGATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, server_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(
		test,
		kacs_rust_kunit_token_snapshot(
			pkm_kacs_current_effective_token_ptr(), &effective));
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  primary_token);
	KUNIT_EXPECT_EQ(test, effective.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_IMLEVEL_IDENTIFICATION);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}


static void pkm_kunit_token_impersonate_integrity_ceiling_caps_identification(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *server_token;
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
		PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_DELEGATION, PKM_KUNIT_IL_HIGH, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, server_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(
		test,
		kacs_rust_kunit_token_snapshot(
			pkm_kacs_current_effective_token_ptr(), &effective));
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_IMLEVEL_IDENTIFICATION);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}


static void pkm_kunit_token_impersonate_integrity_cap_preserves_label(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *server_token;
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;
	bool snapshot_ok;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
		PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_DELEGATION, PKM_KUNIT_IL_HIGH, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, server_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (!ret) {
		snapshot_ok = kacs_rust_kunit_token_snapshot(
			pkm_kacs_current_effective_token_ptr(), &effective);
		KUNIT_EXPECT_TRUE(test, snapshot_ok);
		if (snapshot_ok) {
			KUNIT_EXPECT_EQ(test, effective.token_type,
					(u32)KACS_TOKEN_TYPE_IMPERSONATION);
			KUNIT_EXPECT_EQ(test, effective.impersonation_level,
					(u32)KACS_IMLEVEL_IDENTIFICATION);
			KUNIT_EXPECT_EQ(test, effective.integrity_level,
					(u32)PKM_KUNIT_IL_HIGH);
		}
	}

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}


static void pkm_kunit_token_impersonation_gate_composition_matrix(
	struct kunit *test)
{
	static const struct pkm_kunit_impersonation_gate_case cases[] = {
		{
			.server_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.client_user_kind = PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
			.server_integrity = PKM_KUNIT_IL_MEDIUM,
			.client_integrity = PKM_KUNIT_IL_MEDIUM,
			.requested_level = KACS_IMLEVEL_ANONYMOUS,
			.expected_level = KACS_IMLEVEL_ANONYMOUS,
			.expected_used_impersonate = 0,
		},
		{
			.server_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.client_user_kind = PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
			.server_integrity = PKM_KUNIT_IL_MEDIUM,
			.client_integrity = PKM_KUNIT_IL_MEDIUM,
			.requested_level = KACS_IMLEVEL_IDENTIFICATION,
			.expected_level = KACS_IMLEVEL_IDENTIFICATION,
			.expected_used_impersonate = 0,
		},
		{
			.server_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.client_user_kind = PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
			.server_integrity = PKM_KUNIT_IL_MEDIUM,
			.client_integrity = PKM_KUNIT_IL_MEDIUM,
			.requested_level = KACS_IMLEVEL_IMPERSONATION,
			.expected_level = KACS_IMLEVEL_IDENTIFICATION,
			.expected_used_impersonate = 0,
		},
		{
			.server_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.client_user_kind = PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
			.server_integrity = PKM_KUNIT_IL_MEDIUM,
			.client_integrity = PKM_KUNIT_IL_MEDIUM,
			.requested_level = KACS_IMLEVEL_DELEGATION,
			.expected_level = KACS_IMLEVEL_IDENTIFICATION,
			.expected_used_impersonate = 0,
		},
		{
			.server_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.client_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.server_integrity = PKM_KUNIT_IL_MEDIUM,
			.client_integrity = PKM_KUNIT_IL_MEDIUM,
			.requested_level = KACS_IMLEVEL_DELEGATION,
			.expected_level = KACS_IMLEVEL_DELEGATION,
			.expected_used_impersonate = 0,
		},
		{
			.server_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.client_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.server_integrity = PKM_KUNIT_IL_MEDIUM,
			.client_integrity = PKM_KUNIT_IL_LOW,
			.requested_level = KACS_IMLEVEL_DELEGATION,
			.expected_level = KACS_IMLEVEL_DELEGATION,
			.expected_used_impersonate = 0,
		},
		{
			.server_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.client_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.server_integrity = PKM_KUNIT_IL_MEDIUM,
			.client_integrity = PKM_KUNIT_IL_MEDIUM,
			.client_restricted = 1,
			.requested_level = KACS_IMLEVEL_DELEGATION,
			.expected_level = KACS_IMLEVEL_IDENTIFICATION,
			.expected_used_impersonate = 0,
		},
		{
			.server_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.client_user_kind = PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
			.server_integrity = PKM_KUNIT_IL_MEDIUM,
			.client_integrity = PKM_KUNIT_IL_MEDIUM,
			.server_privileges_present =
				PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE,
			.server_privileges_enabled =
				PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE,
			.server_privileges_enabled_by_default =
				PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE,
			.requested_level = KACS_IMLEVEL_DELEGATION,
			.expected_level = KACS_IMLEVEL_DELEGATION,
			.expected_used_impersonate = 1,
		},
		{
			.server_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.client_user_kind = PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
			.server_integrity = PKM_KUNIT_IL_MEDIUM,
			.client_integrity = PKM_KUNIT_IL_HIGH,
			.server_privileges_present =
				PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE,
			.server_privileges_enabled =
				PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE,
			.server_privileges_enabled_by_default =
				PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE,
			.requested_level = KACS_IMLEVEL_DELEGATION,
			.expected_level = KACS_IMLEVEL_IDENTIFICATION,
			.expected_used_impersonate = 1,
		},
		{
			.server_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.client_user_kind = PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
			.server_integrity = PKM_KUNIT_IL_MEDIUM,
			.client_integrity = PKM_KUNIT_IL_HIGH,
			.requested_level = KACS_IMLEVEL_DELEGATION,
			.expected_level = KACS_IMLEVEL_IDENTIFICATION,
			.expected_used_impersonate = 0,
		},
		{
			.server_user_kind = PKM_KUNIT_USER_KIND_SYSTEM,
			.client_user_kind = PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
			.server_integrity = PKM_KUNIT_IL_MEDIUM,
			.client_integrity = PKM_KUNIT_IL_MEDIUM,
			.server_privileges_present =
				PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE,
			.requested_level = KACS_IMLEVEL_DELEGATION,
			.expected_level = KACS_IMLEVEL_IDENTIFICATION,
			.expected_used_impersonate = 0,
		},
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cases); i++)
		pkm_kunit_expect_impersonation_gate(test, &cases[i]);
}


static void pkm_kunit_token_impersonation_gate_uses_primary_token(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *old_primary_token;
	const void *new_primary_token = NULL;
	const void *privileged_effective_token = NULL;
	const void *target_client_token = NULL;
	long old_fd = -1;
	long install_fd = -1;
	long first_fd = -1;
	long second_fd = -1;
	long ret;
	bool snapshot_ok = false;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	old_primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, old_primary_token);

	old_fd = pkm_kacs_open_self_token_internal(KACS_TOKEN_OPEN_REAL,
						   KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, old_fd, 0L);

	new_primary_token =
		kacs_rust_kunit_create_impersonation_variant_token_with_privileges(
			PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
			KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
			PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE,
			PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE,
			PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, new_primary_token);

	install_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, new_primary_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, install_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)install_fd,
						 old_primary_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_close;
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    new_primary_token);

	privileged_effective_token =
		kacs_rust_kunit_create_impersonation_variant_token(
			PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
			KACS_IMLEVEL_DELEGATION, PKM_KUNIT_IL_SYSTEM, 0,
			PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE);
	target_client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_DELEGATION, PKM_KUNIT_IL_HIGH, 0, 0);
	KUNIT_EXPECT_NOT_NULL(test, privileged_effective_token);
	KUNIT_EXPECT_NOT_NULL(test, target_client_token);
	if (!privileged_effective_token || !target_client_token)
		goto out_restore_primary;

	first_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		new_primary_token, privileged_effective_token,
		KACS_TOKEN_IMPERSONATE);
	KUNIT_EXPECT_GE(test, first_fd, 0L);
	if (first_fd < 0)
		goto out_restore_primary;
	second_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		new_primary_token, target_client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_EXPECT_GE(test, second_fd, 0L);
	if (second_fd < 0)
		goto out_restore_primary;

	ret = pkm_kacs_kunit_token_fd_impersonate((int)first_fd,
						 new_primary_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_restore_primary;
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  new_primary_token);

	ret = pkm_kacs_kunit_token_fd_impersonate(
		(int)second_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (!ret) {
		snapshot_ok = kacs_rust_kunit_token_snapshot(
			pkm_kacs_current_effective_token_ptr(), &effective);
		KUNIT_EXPECT_TRUE(test, snapshot_ok);
	}
	if (!ret && snapshot_ok) {
		KUNIT_EXPECT_EQ(test, effective.impersonation_level,
				(u32)KACS_IMLEVEL_IDENTIFICATION);
	}

out_restore_primary:
	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	ret = pkm_kacs_kunit_token_fd_install(
		(int)old_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    old_primary_token);

out_close:
	if (second_fd >= 0)
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)second_fd), 0);
	if (first_fd >= 0)
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)first_fd), 0);
	if (install_fd >= 0)
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)install_fd), 0);
	if (old_fd >= 0)
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)old_fd), 0);
	if (target_client_token)
		kacs_rust_token_drop(target_client_token);
	if (privileged_effective_token)
		kacs_rust_token_drop(privileged_effective_token);
	if (new_primary_token)
		kacs_rust_token_drop(new_primary_token);
}


static void pkm_kunit_double_impersonation_replaces_effective_token(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot first = { };
	struct pkm_kacs_boot_snapshot second_source = { };
	struct pkm_kacs_boot_snapshot final = { };
	const void *old_primary_token;
	const void *new_primary_token = NULL;
	const void *first_client_token = NULL;
	const void *second_client_token = NULL;
	long old_fd = -1;
	long install_fd = -1;
	long first_fd = -1;
	long second_fd = -1;
	long ret;
	bool first_ok = false;
	bool second_ok = false;
	bool final_ok = false;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	old_primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, old_primary_token);

	old_fd = pkm_kacs_open_self_token_internal(KACS_TOKEN_OPEN_REAL,
						   KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, old_fd, 0L);

	new_primary_token =
		kacs_rust_kunit_create_impersonation_variant_token_with_privileges(
			PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
			KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_MEDIUM, 0,
			PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE,
			PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE,
			PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, new_primary_token);

	install_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, new_primary_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, install_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)install_fd,
						 old_primary_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_close;
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    new_primary_token);

	first_client_token =
		kacs_rust_kunit_create_impersonation_variant_token(
			PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
			KACS_IMLEVEL_DELEGATION, PKM_KUNIT_IL_SYSTEM, 0,
			PKM_KUNIT_SE_IMPERSONATE_PRIVILEGE);
	second_client_token =
		kacs_rust_kunit_create_impersonation_variant_token(
			PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
			KACS_TOKEN_TYPE_IMPERSONATION, KACS_IMLEVEL_DELEGATION,
			PKM_KUNIT_IL_HIGH, 0, 0);
	KUNIT_EXPECT_NOT_NULL(test, first_client_token);
	KUNIT_EXPECT_NOT_NULL(test, second_client_token);
	if (!first_client_token || !second_client_token)
		goto out_restore_primary;

	second_ok = kacs_rust_kunit_token_snapshot(second_client_token,
						  &second_source);
	KUNIT_EXPECT_TRUE(test, second_ok);
	if (!second_ok)
		goto out_restore_primary;

	first_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		new_primary_token, first_client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_EXPECT_GE(test, first_fd, 0L);
	if (first_fd < 0)
		goto out_restore_primary;
	second_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		new_primary_token, second_client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_EXPECT_GE(test, second_fd, 0L);
	if (second_fd < 0)
		goto out_restore_primary;

	ret = pkm_kacs_kunit_token_fd_impersonate((int)first_fd,
						 new_primary_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_restore_primary;
	first_ok = kacs_rust_kunit_token_snapshot(
		pkm_kacs_current_effective_token_ptr(), &first);
	KUNIT_EXPECT_TRUE(test, first_ok);
	if (!first_ok)
		goto out_restore_primary;
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  new_primary_token);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)second_fd,
						 new_primary_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (!ret) {
		final_ok = kacs_rust_kunit_token_snapshot(
			pkm_kacs_current_effective_token_ptr(), &final);
		KUNIT_EXPECT_TRUE(test, final_ok);
	}
	if (!ret && final_ok) {
		KUNIT_EXPECT_EQ(test, final.token_type,
				(u32)KACS_TOKEN_TYPE_IMPERSONATION);
		KUNIT_EXPECT_EQ(test, final.impersonation_level,
				(u32)KACS_IMLEVEL_IDENTIFICATION);
		pkm_kunit_expect_bytes_eq(test, final.user_sid_ptr,
					  final.user_sid_len,
					  second_source.user_sid_ptr,
					  second_source.user_sid_len);
		KUNIT_EXPECT_EQ(test, final.user_sid_len, first.user_sid_len);
		if (final.user_sid_len == first.user_sid_len)
			KUNIT_EXPECT_NE(test,
					memcmp(final.user_sid_ptr,
					       first.user_sid_ptr,
					       final.user_sid_len),
					0);
	}

out_restore_primary:
	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	ret = pkm_kacs_kunit_token_fd_install(
		(int)old_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    old_primary_token);

out_close:
	if (second_fd >= 0)
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)second_fd), 0);
	if (first_fd >= 0)
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)first_fd), 0);
	if (install_fd >= 0)
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)install_fd), 0);
	if (old_fd >= 0)
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)old_fd), 0);
	if (second_client_token)
		kacs_rust_token_drop(second_client_token);
	if (first_client_token)
		kacs_rust_token_drop(first_client_token);
	if (new_primary_token)
		kacs_rust_token_drop(new_primary_token);
}


static void pkm_kunit_token_impersonate_same_user_restriction_mismatch_denies(
	struct kunit *test)
{
	const void *server_token;
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 1, 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_DELEGATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, server_token);
	KUNIT_EXPECT_EQ(test, ret, (long)-EPERM);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}


static void pkm_kunit_token_impersonate_anonymous_bypasses_gates(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *server_token;
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_LOW, 1, 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_HIGH, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, server_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(
		test,
		kacs_rust_kunit_token_snapshot(
			pkm_kacs_current_effective_token_ptr(), &effective));
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_IMLEVEL_ANONYMOUS);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}


static void pkm_kunit_anonymous_impersonation_access_check_matrix(
	struct kunit *test)
{
	const void *anonymous_token = NULL;
	const void *primary_token;
	long ret;
	u32 granted = 0;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_create_anonymous_impersonation_token(
				&anonymous_token),
			0);
	KUNIT_ASSERT_NOT_NULL(test, anonymous_token);

	ret = pkm_kacs_kunit_impersonate_peer_for_socket(1, anonymous_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_drop;

	ret = pkm_kunit_run_read_control_with_token_fd(
		-1, pkm_kunit_anonymous_read_sd,
		sizeof(pkm_kunit_anonymous_read_sd), &granted);
	KUNIT_EXPECT_EQ(test, ret, (long)KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, granted, KACS_ACCESS_READ_CONTROL);

	granted = 0;
	ret = pkm_kunit_run_read_control_with_token_fd(
		-1, pkm_kunit_everyone_read_sd,
		sizeof(pkm_kunit_everyone_read_sd), &granted);
	KUNIT_EXPECT_EQ(test, ret, (long)KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, granted, KACS_ACCESS_READ_CONTROL);

	granted = 0;
	ret = pkm_kunit_run_read_control_with_token_fd(
		-1, pkm_kunit_system_read_sd,
		sizeof(pkm_kunit_system_read_sd), &granted);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	granted = 0;
	ret = pkm_kunit_run_read_control_with_token_fd(
		-1, pkm_kunit_authenticated_users_read_sd,
		sizeof(pkm_kunit_authenticated_users_read_sd), &granted);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);

out_drop:
	kacs_rust_token_drop(anonymous_token);
}


static void pkm_kunit_token_install_requires_assign_primary_handle(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view before = { };
	struct pkm_kacs_kunit_process_state_view after = { };
	const void *target_token;
	const void *primary_token;
	const void *state_ptr;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	state_ptr = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);
	KUNIT_ASSERT_NOT_NULL(test, state_ptr);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &before),
			0);

	target_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(primary_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)fd, primary_token);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &after),
			0);
	KUNIT_EXPECT_PTR_EQ(test, after.state_ptr, before.state_ptr);
	KUNIT_EXPECT_PTR_EQ(test, after.process_sd_ptr, before.process_sd_ptr);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_install_requires_assign_primary_privilege(
	struct kunit *test)
{
	const void *target_token;
	const void *caller_without_privilege;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	target_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	caller_without_privilege =
		kacs_rust_kunit_create_impersonation_variant_token(
			PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
			KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_NOT_NULL(test, caller_without_privilege);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, target_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)fd,
						 caller_without_privilege);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(caller_without_privilege);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_install_rejects_impersonation_token(
	struct kunit *test)
{
	const void *target_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	target_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, target_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)fd, primary_token);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_install_same_user_preserves_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view before = { };
	struct pkm_kacs_kunit_process_state_view after_install = { };
	struct pkm_kacs_kunit_process_state_view after_restore = { };
	const void *old_primary_token;
	const void *new_primary_token;
	const void *state_ptr;
	long old_fd;
	long install_fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	old_primary_token = pkm_kacs_current_primary_token_ptr();
	state_ptr = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, old_primary_token);
	KUNIT_ASSERT_NOT_NULL(test, state_ptr);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &before),
			0);

	old_fd = pkm_kacs_open_self_token_internal(KACS_TOKEN_OPEN_REAL,
						   KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, old_fd, 0L);

	new_primary_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, new_primary_token);

	install_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, new_primary_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, install_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)install_fd,
						 old_primary_token);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    new_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    new_primary_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				pkm_kacs_kunit_current_process_state_ptr(),
				&after_install),
			0);
	KUNIT_EXPECT_PTR_EQ(test, after_install.state_ptr, before.state_ptr);
	KUNIT_EXPECT_PTR_EQ(test, after_install.process_sd_ptr,
			    before.process_sd_ptr);
	KUNIT_EXPECT_EQ(test, after_install.process_sd_len,
			before.process_sd_len);

	ret = pkm_kacs_kunit_token_fd_install(
		(int)old_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    old_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    old_primary_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				pkm_kacs_kunit_current_process_state_ptr(),
				&after_restore),
			0);
	KUNIT_EXPECT_PTR_EQ(test, after_restore.state_ptr, before.state_ptr);
	KUNIT_EXPECT_PTR_EQ(test, after_restore.process_sd_ptr,
			    before.process_sd_ptr);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)install_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)old_fd), 0);
	kacs_rust_token_drop(new_primary_token);
}


static void pkm_kunit_token_install_different_user_regenerates_process_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_process_state_view before = { };
	struct pkm_kacs_kunit_process_state_view after_install = { };
	struct pkm_kacs_kunit_process_state_view after_restore = { };
	const void *old_primary_token;
	const void *new_primary_token;
	const void *state_ptr;
	long old_fd;
	long install_fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	old_primary_token = pkm_kacs_current_primary_token_ptr();
	state_ptr = pkm_kacs_kunit_current_process_state_ptr();
	KUNIT_ASSERT_NOT_NULL(test, old_primary_token);
	KUNIT_ASSERT_NOT_NULL(test, state_ptr);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(state_ptr, &before),
			0);

	old_fd = pkm_kacs_open_self_token_internal(KACS_TOKEN_OPEN_REAL,
						   KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, old_fd, 0L);

	new_primary_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	KUNIT_ASSERT_NOT_NULL(test, new_primary_token);

	install_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, new_primary_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, install_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_install((int)install_fd,
						 old_primary_token);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    new_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    new_primary_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				pkm_kacs_kunit_current_process_state_ptr(),
				&after_install),
			0);
	KUNIT_EXPECT_PTR_EQ(test, after_install.state_ptr, before.state_ptr);
	KUNIT_EXPECT_TRUE(test,
			  after_install.process_sd_ptr !=
				  before.process_sd_ptr);
	KUNIT_EXPECT_GT(test, after_install.process_sd_len, (size_t)0);

	ret = pkm_kacs_kunit_token_fd_install(
		(int)old_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    old_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    old_primary_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_process_state_snapshot(
				pkm_kacs_kunit_current_process_state_ptr(),
				&after_restore),
			0);
	KUNIT_EXPECT_PTR_EQ(test, after_restore.state_ptr, before.state_ptr);
	KUNIT_EXPECT_TRUE(test,
			  after_restore.process_sd_ptr !=
				  after_install.process_sd_ptr);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)install_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)old_fd), 0);
	kacs_rust_token_drop(new_primary_token);
}


static void pkm_kunit_token_install_under_impersonation_revert_lands_on_new_primary(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *old_primary_token;
	const void *new_primary_token;
	const void *client_token;
	long old_fd;
	long install_fd;
	long impersonation_fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	old_primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, old_primary_token);

	old_fd = pkm_kacs_open_self_token_internal(KACS_TOKEN_OPEN_REAL,
						   KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, old_fd, 0L);

	new_primary_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0,
		PKM_KUNIT_SE_ASSIGN_PRIMARY_PRIVILEGE);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IMPERSONATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, new_primary_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	install_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, new_primary_token, KACS_TOKEN_ASSIGN_PRIMARY);
	KUNIT_ASSERT_GE(test, install_fd, 0L);
	impersonation_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		old_primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, impersonation_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)impersonation_fd,
						 old_primary_token);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    old_primary_token);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  old_primary_token);

	ret = pkm_kacs_kunit_token_fd_install(
		(int)install_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    new_primary_token);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  new_primary_token);
	KUNIT_ASSERT_TRUE(
		test,
		kacs_rust_kunit_token_snapshot(
			pkm_kacs_current_effective_token_ptr(), &effective));
	KUNIT_EXPECT_EQ(test, effective.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_IMLEVEL_IMPERSONATION);

	ret = pkm_kacs_revert_impersonation();
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    new_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    new_primary_token);

	ret = pkm_kacs_kunit_token_fd_install(
		(int)old_fd, pkm_kacs_current_primary_token_ptr());
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    old_primary_token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    old_primary_token);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)impersonation_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)install_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)old_fd), 0);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(new_primary_token);
}


static void pkm_kunit_peer_socket_abstract_bind_stamps_once(struct kunit *test)
{
	struct pkm_kacs_kunit_socket_view first = { };
	struct pkm_kacs_kunit_socket_view second = { };
	long ret;

	ret = pkm_kacs_kunit_bind_abstract_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), &first, &second);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, first.socket_sd_ptr);
	KUNIT_EXPECT_EQ(test, first.socket_sd_len, second.socket_sd_len);
	KUNIT_EXPECT_PTR_EQ(test, first.socket_sd_ptr, second.socket_sd_ptr);
	KUNIT_EXPECT_EQ(test, first.max_impersonation,
			(u32)KACS_IMLEVEL_IMPERSONATION);
}


static void pkm_kunit_peer_socket_abstract_default_sd_shape(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot snapshot = { };
	const u8 *socket_sd = NULL;
	const struct pkm_kacs_boot_group_view *primary_group;
	size_t socket_sd_len = 0;
	long ret;

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  pkm_kacs_current_effective_token_ptr(),
				  &snapshot));
	KUNIT_ASSERT_NE(test, snapshot.primary_group_index, 0U);
	KUNIT_ASSERT_LT(test, snapshot.primary_group_index,
			snapshot.group_count + 1);
	primary_group = &snapshot.groups_ptr[snapshot.primary_group_index - 1];

	ret = pkm_kacs_kunit_bind_abstract_socket_sd_for_subject(
		pkm_kacs_current_effective_token_ptr(), &socket_sd,
		&socket_sd_len);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, socket_sd);
	KUNIT_ASSERT_GT(test, (long)socket_sd_len, 20L);

	pkm_kunit_expect_sd_sid_component(test, socket_sd, socket_sd_len, 4,
					  snapshot.user_sid_ptr,
					  snapshot.user_sid_len);
	pkm_kunit_expect_sd_sid_component(test, socket_sd, socket_sd_len, 8,
					  primary_group->sid_ptr,
					  primary_group->sid_len);
	pkm_kunit_expect_allow_ace(test, socket_sd, socket_sd_len, 0,
				   KACS_ACCESS_GENERIC_ALL,
				   snapshot.user_sid_ptr,
				   snapshot.user_sid_len);
	pkm_kunit_expect_allow_ace(test, socket_sd, socket_sd_len, 1,
				   KACS_ACCESS_GENERIC_ALL,
				   pkm_kunit_administrators_sid,
				   sizeof(pkm_kunit_administrators_sid));
	pkm_kunit_expect_allow_ace(test, socket_sd, socket_sd_len, 2,
				   KACS_ACCESS_GENERIC_ALL, pkm_kunit_system_sid,
				   sizeof(pkm_kunit_system_sid));
	kfree(socket_sd);
}


static void pkm_kunit_peer_socket_set_level_updates_unconnected(
	struct kunit *test)
{
	struct pkm_kacs_kunit_socket_view view = { };
	long ret;

	ret = pkm_kacs_kunit_set_socket_impersonation_level(
		SOCK_STREAM, 0, KACS_IMLEVEL_IDENTIFICATION, &view);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_EQ(test, view.max_impersonation,
			(u32)KACS_IMLEVEL_IDENTIFICATION);
}


static void pkm_kunit_peer_socket_set_level_invalid_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_socket_view view = { };
	long ret;

	ret = pkm_kacs_kunit_set_socket_impersonation_level(
		SOCK_STREAM, 0, 99U, &view);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_EQ(test, view.max_impersonation,
			(u32)KACS_IMLEVEL_IMPERSONATION);
}


static void pkm_kunit_peer_socket_set_level_connected_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_socket_view view = { };
	long ret;

	ret = pkm_kacs_kunit_set_socket_impersonation_level(
		SOCK_STREAM, 1, KACS_IMLEVEL_DELEGATION, &view);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, view.max_impersonation,
			(u32)KACS_IMLEVEL_IMPERSONATION);
}


static void pkm_kunit_peer_socket_set_level_unsupported_type_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_socket_view view = { };
	long ret;

	ret = pkm_kacs_kunit_set_socket_impersonation_level(
		SOCK_DGRAM, 0, KACS_IMLEVEL_IDENTIFICATION, &view);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, view.max_impersonation,
			(u32)KACS_IMLEVEL_IMPERSONATION);
}


static void pkm_kunit_peer_socket_capture_identification_on_seqpacket(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot current_snapshot = { };
	struct pkm_kacs_boot_snapshot captured = { };
	struct pkm_kacs_kunit_socket_view listener = { };
	struct pkm_kacs_kunit_socket_view accepted = { };
	const void *captured_token = NULL;
	long ret;

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  pkm_kacs_current_effective_token_ptr(),
				  &current_snapshot));

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_SEQPACKET,
		KACS_IMLEVEL_IDENTIFICATION, 0, 0, &captured_token,
		&listener, &accepted);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(captured_token,
							 &captured));
	KUNIT_EXPECT_PTR_EQ(test, listener.socket_sd_ptr, NULL);
	KUNIT_EXPECT_EQ(test, captured.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, captured.impersonation_level,
			(u32)KACS_IMLEVEL_IDENTIFICATION);
	pkm_kunit_expect_bytes_eq(test, captured.user_sid_ptr,
				  captured.user_sid_len,
				  current_snapshot.user_sid_ptr,
				  current_snapshot.user_sid_len);
	kacs_rust_token_drop(captured_token);
}


static void pkm_kunit_peer_socket_capture_anonymous_shape(struct kunit *test)
{
	struct pkm_kacs_boot_snapshot captured = { };
	struct pkm_kacs_kunit_socket_view listener = { };
	struct pkm_kacs_kunit_socket_view accepted = { };
	const void *captured_token = NULL;
	u32 everyone_attributes = 0;
	long ret;

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_STREAM,
		KACS_IMLEVEL_ANONYMOUS, 0, 0, &captured_token,
		&listener, &accepted);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(captured_token,
							 &captured));
	pkm_kunit_expect_bytes_eq(test, captured.user_sid_ptr,
				  captured.user_sid_len,
				  pkm_kunit_anonymous_sid,
				  sizeof(pkm_kunit_anonymous_sid));
	KUNIT_EXPECT_EQ(test, captured.auth_id, 998ULL);
	KUNIT_EXPECT_EQ(test, captured.logon_type,
			(u32)PKM_KUNIT_LOGON_TYPE_NETWORK);
	KUNIT_EXPECT_EQ(test, captured.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, captured.impersonation_level,
			(u32)KACS_IMLEVEL_ANONYMOUS);
	KUNIT_EXPECT_EQ(test, captured.integrity_level,
			(u32)PKM_KUNIT_IL_UNTRUSTED);
	KUNIT_EXPECT_EQ(test, captured.privileges_present, 0ULL);
	KUNIT_EXPECT_EQ(test, captured.group_count, 1U);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_snapshot_has_group(
				  &captured, pkm_kunit_everyone_sid,
				  sizeof(pkm_kunit_everyone_sid),
				  &everyone_attributes));
	KUNIT_EXPECT_NE(test,
			everyone_attributes & PKM_KUNIT_SE_GROUP_ENABLED, 0U);
	KUNIT_EXPECT_FALSE(test,
			   pkm_kunit_snapshot_has_group(
				   &captured,
				   pkm_kunit_authenticated_users_sid,
				   sizeof(pkm_kunit_authenticated_users_sid),
				   NULL));
	kacs_rust_token_drop(captured_token);
}


static void pkm_kunit_peer_socket_anonymous_capture_uses_boot_token(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot boot = { };
	struct pkm_kacs_boot_snapshot captured = { };
	const void *anonymous_token;
	const void *captured_token = NULL;
	long ret;

	anonymous_token = pkm_kacs_boot_anonymous_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, anonymous_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(anonymous_token,
							 &boot));

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_STREAM,
		KACS_IMLEVEL_ANONYMOUS, 0, 0, &captured_token, NULL, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);
	KUNIT_EXPECT_PTR_EQ(test, captured_token, anonymous_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(captured_token,
							 &captured));
	pkm_kunit_expect_boot_snapshot_eq(test, &boot, &captured);
	kacs_rust_token_drop(captured_token);
}


static void pkm_kunit_peer_socket_abstract_connect_denied_without_write_data(
	struct kunit *test)
{
	struct pkm_kacs_kunit_socket_view listener = { };
	struct pkm_kacs_kunit_socket_view accepted = { };
	long ret;

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_STREAM,
		KACS_IMLEVEL_IMPERSONATION, 1, 0, NULL, &listener, &accepted);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_ASSERT_NOT_NULL(test, listener.socket_sd_ptr);
	KUNIT_EXPECT_PTR_EQ(test, accepted.peer_token, NULL);
}


static void pkm_kunit_peer_socket_dgram_send_checks_abstract_sd(
	struct kunit *test)
{
	struct pkm_kacs_kunit_socket_view sender = { };
	struct pkm_kacs_kunit_socket_view target = { };
	long ret;

	ret = pkm_kacs_kunit_unix_dgram_send_for_subject(
		pkm_kacs_current_effective_token_ptr(), 1, 1, &sender,
		&target);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, target.socket_sd_ptr);
	KUNIT_EXPECT_PTR_EQ(test, target.peer_token, NULL);
	KUNIT_EXPECT_PTR_EQ(test, sender.peer_token, NULL);

	memset(&sender, 0, sizeof(sender));
	memset(&target, 0, sizeof(target));
	ret = pkm_kacs_kunit_unix_dgram_send_for_subject(
		pkm_kacs_current_effective_token_ptr(), 1, 0, &sender,
		&target);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_ASSERT_NOT_NULL(test, target.socket_sd_ptr);
	KUNIT_EXPECT_PTR_EQ(test, target.peer_token, NULL);
	KUNIT_EXPECT_PTR_EQ(test, sender.peer_token, NULL);

	memset(&sender, 0, sizeof(sender));
	memset(&target, 0, sizeof(target));
	ret = pkm_kacs_kunit_unix_dgram_send_for_subject(
		pkm_kacs_current_effective_token_ptr(), 0, 0, &sender,
		&target);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, target.socket_sd_ptr, NULL);
	KUNIT_EXPECT_PTR_EQ(test, target.peer_token, NULL);
	KUNIT_EXPECT_PTR_EQ(test, sender.peer_token, NULL);
}


static void pkm_kunit_peer_socket_open_token_fixed_rights(struct kunit *test)
{
	struct pkm_kacs_token_fd_view view = { };
	const void *captured_token = NULL;
	long ret;
	long fd;

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_STREAM,
		KACS_IMLEVEL_IMPERSONATION, 0, 0, &captured_token,
		NULL, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);

	fd = pkm_kacs_kunit_open_peer_token_for_socket(1, captured_token);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_EXPECT_EQ(test, view.access_mask,
			KACS_TOKEN_QUERY | KACS_TOKEN_IMPERSONATE);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(captured_token);
}


static void pkm_kunit_peer_socket_impersonate_success_and_revert(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *captured_token = NULL;
	const void *client_token;
	const void *primary_token;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		client_token, SOCK_STREAM, KACS_IMLEVEL_DELEGATION, 0, 0,
		&captured_token, NULL, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);

	ret = pkm_kacs_kunit_impersonate_peer_for_socket(1, captured_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  pkm_kacs_current_effective_token_ptr(),
				  &effective));
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  primary_token);
	KUNIT_EXPECT_EQ(test, effective.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_IMLEVEL_DELEGATION);
	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	kacs_rust_token_drop(captured_token);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_peer_socket_seqpacket_impersonate_success_and_revert(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	const void *captured_token = NULL;
	const void *client_token;
	const void *primary_token;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		client_token, SOCK_SEQPACKET, KACS_IMLEVEL_DELEGATION, 0, 0,
		&captured_token, NULL, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);

	ret = pkm_kacs_kunit_impersonate_peer_for_socket_type(
		SOCK_SEQPACKET, 1, captured_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  pkm_kacs_current_effective_token_ptr(),
				  &effective));
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(),
			    primary_token);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_current_effective_token_ptr() !=
				  primary_token);
	KUNIT_EXPECT_EQ(test, effective.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_IMLEVEL_DELEGATION);
	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	kacs_rust_token_drop(captured_token);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_peer_socket_impersonation_cascades_identity(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	struct pkm_kacs_boot_snapshot captured = { };
	const void *captured_token = NULL;
	const void *client_token;
	const void *primary_token;
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

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, primary_token);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_EXPECT_TRUE(
		test,
		kacs_rust_kunit_token_snapshot(
			pkm_kacs_current_effective_token_ptr(), &effective));
	if (effective.token_type != (u32)KACS_TOKEN_TYPE_IMPERSONATION ||
	    effective.impersonation_level != (u32)KACS_IMLEVEL_IMPERSONATION)
		goto out_restore;
	KUNIT_EXPECT_EQ(test, effective.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_IMLEVEL_IMPERSONATION);

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_STREAM,
		KACS_IMLEVEL_IMPERSONATION, 0, 0, &captured_token, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (!ret && captured_token) {
		KUNIT_EXPECT_TRUE(test,
				  kacs_rust_kunit_token_snapshot(
					  captured_token, &captured));
		KUNIT_EXPECT_EQ(test, captured.token_type,
				(u32)KACS_TOKEN_TYPE_IMPERSONATION);
		KUNIT_EXPECT_EQ(test, captured.impersonation_level,
				(u32)KACS_IMLEVEL_IMPERSONATION);
		pkm_kunit_expect_bytes_eq(test, captured.user_sid_ptr,
					  captured.user_sid_len,
					  effective.user_sid_ptr,
					  effective.user_sid_len);
	} else {
		KUNIT_EXPECT_NOT_NULL(test, captured_token);
	}

out_restore:
	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	if (captured_token)
		kacs_rust_token_drop(captured_token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_peer_socket_capture_cannot_raise_effective_level(
	struct kunit *test)
{
	const void *captured_token = NULL;
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IDENTIFICATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, primary_token);
	KUNIT_ASSERT_EQ(test, ret, 0L);

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_STREAM,
		KACS_IMLEVEL_DELEGATION, 0, 0, &captured_token, NULL, NULL);
	KUNIT_EXPECT_LT(test, ret, 0L);
	KUNIT_EXPECT_PTR_EQ(test, captured_token, NULL);

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_STREAM,
		KACS_IMLEVEL_IDENTIFICATION, 0, 0, &captured_token, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_EXPECT_NOT_NULL(test, captured_token);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);
	if (captured_token)
		kacs_rust_token_drop(captured_token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_peer_socket_impersonate_caps_identification_without_privilege(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot effective = { };
	struct pkm_kacs_token_fd_view view = { };
	const void *captured_token = NULL;
	const void *server_token;
	const void *client_token;
	long token_fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		client_token, SOCK_STREAM, KACS_IMLEVEL_DELEGATION, 0, 0,
		&captured_token, NULL, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);

	token_fd = pkm_kacs_kunit_open_peer_token_for_socket(1, captured_token);
	KUNIT_ASSERT_GE(test, token_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)token_fd, &view),
			0);
	KUNIT_EXPECT_EQ(test, view.access_mask,
			KACS_TOKEN_QUERY | KACS_TOKEN_IMPERSONATE);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)token_fd, server_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  pkm_kacs_current_effective_token_ptr(),
				  &effective));
	KUNIT_EXPECT_EQ(test, effective.impersonation_level,
			(u32)KACS_IMLEVEL_IDENTIFICATION);
	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(captured_token);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}


static void pkm_kunit_peer_socket_restricted_mismatch_hard_denies(
	struct kunit *test)
{
	const void *captured_token = NULL;
	const void *server_token;
	const void *client_token;
	long token_fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	server_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 1, 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_SYSTEM, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, server_token);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		client_token, SOCK_STREAM, KACS_IMLEVEL_DELEGATION, 0, 0,
		&captured_token, NULL, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0L);
	KUNIT_ASSERT_NOT_NULL(test, captured_token);

	token_fd = pkm_kacs_kunit_open_peer_token_for_socket(1, captured_token);
	KUNIT_ASSERT_GE(test, token_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)token_fd, server_token);
	KUNIT_EXPECT_EQ(test, ret, (long)-EPERM);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)token_fd), 0);
	kacs_rust_token_drop(captured_token);
	kacs_rust_token_drop(client_token);
	kacs_rust_token_drop(server_token);
}


static void pkm_kunit_peer_socket_unsupported_or_uncaptured_fail_closed(
	struct kunit *test)
{
	long ret;

	ret = pkm_kacs_kunit_capture_peer_socket_for_subject(
		pkm_kacs_current_effective_token_ptr(), SOCK_DGRAM,
		KACS_IMLEVEL_IMPERSONATION, 0, 0, NULL, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_peer_token_for_socket(0, NULL),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_peer_token_for_socket(1, NULL),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_open_peer_token_for_socket_type(
				SOCK_DGRAM, 1,
				pkm_kacs_current_effective_token_ptr()),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_impersonate_peer_for_socket(0, NULL),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_impersonate_peer_for_socket(1, NULL),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_impersonate_peer_for_socket_type(
				SOCK_DGRAM, 1,
				pkm_kacs_current_effective_token_ptr()),
			(long)-EACCES);
}


static void pkm_kunit_token_impersonate_rejects_primary_token(
	struct kunit *test)
{
	const void *client_token;
	const void *primary_token;
	long fd;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_PRIMARY,
		KACS_IMLEVEL_ANONYMOUS, PKM_KUNIT_IL_SYSTEM, 0, 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, client_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)fd, primary_token);
	KUNIT_EXPECT_EQ(test, ret, (long)-EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_token_query_user_probe_and_payload(struct kunit *test)
{
	static const u8 system_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_USER,
	};
	u8 buf[32] = { };
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, (u32)sizeof(system_sid));

	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, (u32)sizeof(system_sid));
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len, system_sid,
				  sizeof(system_sid));
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_token_query_groups_payload(struct kunit *test)
{
	static const u8 administrators_sid[] = {
		1, 2, 0, 0, 0, 0, 0, 5,
		32, 0, 0, 0, 32, 2, 0, 0,
	};
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_GROUPS,
		.buf_len = 160,
	};
	u8 buf[160] = { };
	u32 first_sid_len;
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0), 5U);

	first_sid_len = pkm_kunit_read_u32(buf, 4);
	KUNIT_ASSERT_EQ(test, first_sid_len, (u32)sizeof(administrators_sid));
	pkm_kunit_expect_bytes_eq(test, &buf[8], first_sid_len,
				  administrators_sid,
				  sizeof(administrators_sid));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 8 + first_sid_len),
			0x0000000FU);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_token_query_privileges_payload(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_PRIVILEGES,
		.buf_len = 32,
	};
	u8 buf[32] = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);
	kacs_rust_token_drop(target_token);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 32U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 0),
			PKM_KUNIT_SYSTEM_PRIVILEGES_ALL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 8),
			PKM_KUNIT_SYSTEM_PRIVILEGES_ALL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 16),
			PKM_KUNIT_SYSTEM_PRIVILEGES_ALL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 24), 0ULL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_token_query_optional_empty_shapes(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_APPCONTAINER_SID,
	};
	u8 buf[4] = { 0xff, 0xff, 0xff, 0xff };
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 0U);

	args.token_class = KACS_TOKEN_CLASS_RESTRICTED_SIDS;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 4U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0), 0U);

	args.token_class = KACS_TOKEN_CLASS_USER_CLAIMS;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 0U);

	args.token_class = KACS_TOKEN_CLASS_DEVICE_CLAIMS;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 0U);

	memset(buf, 0xff, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 4U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0), 0U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_token_query_requires_cached_query(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_USER,
	};
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_token_query_invalid_class(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = 0,
	};
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)-EINVAL);

	args.token_class = 0x19;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_token_query_public_tail_payload(struct kunit *test)
{
	static const u32 supplementary_gids[] = {
		3001U, 3002U,
	};
	static const u8 octet_value[] = {
		0xde, 0xad,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.projected_uid = 1200U,
		.projected_gid = 1201U,
		.source_name = "KUNITQRY",
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.projected_supplementary_gids = supplementary_gids,
		.projected_supplementary_gid_count =
			ARRAY_SIZE(supplementary_gids),
	};
	struct kacs_query_args args = { };
	u8 session_spec[96] = { };
	u8 user_claim_entry[96] = { };
	u8 user_claim_empty_entry[96] = { };
	u8 user_claim_uint_entry[96] = { };
	u8 device_claim_string_entry[96] = { };
	u8 device_claim_sid_entry[96] = { };
	u8 device_claim_octet_entry[96] = { };
	u8 device_claim_boolean_entry[96] = { };
	u8 *token_spec;
	u8 *user_claims;
	u8 *device_claims;
	u8 *buf;
	size_t user_claims_len = 0;
	size_t device_claims_len = 0;
	size_t entry_len;
	size_t token_spec_len;
	u64 session_id = 0;
	const void *subject_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	token_spec = kunit_kzalloc(test, 1024, GFP_KERNEL);
	user_claims = kunit_kzalloc(test, 320, GFP_KERNEL);
	device_claims = kunit_kzalloc(test, 384, GFP_KERNEL);
	buf = kunit_kzalloc(test, 384, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, token_spec);
	KUNIT_ASSERT_NOT_NULL(test, user_claims);
	KUNIT_ASSERT_NOT_NULL(test, device_claims);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	entry_len = pkm_kunit_build_claim_entry_scalar(
		user_claim_entry, sizeof(user_claim_entry), "Level",
		PKM_KUNIT_CLAIM_TYPE_INT64, 0U, 42U);
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(
				user_claims, 320U,
				&user_claims_len, user_claim_entry, entry_len),
			0);

	entry_len = pkm_kunit_build_claim_entry_empty(
		user_claim_empty_entry, sizeof(user_claim_empty_entry),
		"Tags", PKM_KUNIT_CLAIM_TYPE_STRING, PKM_KUNIT_CLAIM_DISABLED);
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(
				user_claims, 320U,
				&user_claims_len, user_claim_empty_entry,
				entry_len),
			0);

	entry_len = pkm_kunit_build_claim_entry_scalar(
		user_claim_uint_entry, sizeof(user_claim_uint_entry), "Quota",
		PKM_KUNIT_CLAIM_TYPE_UINT64, 0U, 9U);
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(
				user_claims, 320U,
				&user_claims_len, user_claim_uint_entry,
				entry_len),
			0);

	entry_len = pkm_kunit_build_claim_entry_string(
		device_claim_string_entry, sizeof(device_claim_string_entry),
		"Kind", 0U, "svc");
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(
				device_claims, 384U,
				&device_claims_len, device_claim_string_entry,
				entry_len),
			0);

	entry_len = pkm_kunit_build_claim_entry_sid(
		device_claim_sid_entry, sizeof(device_claim_sid_entry),
		"Principal", 0U, pkm_kunit_local_service_sid,
		sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(
				device_claims, 384U,
				&device_claims_len, device_claim_sid_entry,
				entry_len),
			0);

	entry_len = pkm_kunit_build_claim_entry_octet(
		device_claim_octet_entry, sizeof(device_claim_octet_entry),
		"Blob", 0U, octet_value, sizeof(octet_value));
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(
				device_claims, 384U,
				&device_claims_len, device_claim_octet_entry,
				entry_len),
			0);

	entry_len = pkm_kunit_build_claim_entry_scalar(
		device_claim_boolean_entry, sizeof(device_claim_boolean_entry),
		"Remote", PKM_KUNIT_CLAIM_TYPE_BOOLEAN, 0U, 1U);
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(
				device_claims, 384U,
				&device_claims_len, device_claim_boolean_entry,
				entry_len),
			0);

	spec_args.user_claims = user_claims;
	spec_args.user_claims_len = user_claims_len;
	spec_args.device_claims = device_claims;
	spec_args.device_claims_len = device_claims_len;

	entry_len = pkm_kunit_build_session_spec(session_spec,
						 PKM_KUNIT_LOGON_TYPE_NETWORK,
						 "Kerberos",
						 pkm_kunit_local_service_sid,
						 sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, entry_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec, 1024U,
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);

	args.token_class = KACS_TOKEN_CLASS_USER_CLAIMS;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)0);
	KUNIT_ASSERT_EQ(test, args.buf_len, (u32)user_claims_len);
	args.buf_ptr = (u64)(unsigned long)buf;
	args.buf_len = 384U;
	memset(buf, 0, 384U);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len, user_claims,
				  user_claims_len);

	args.token_class = KACS_TOKEN_CLASS_DEVICE_CLAIMS;
	args.buf_len = 0U;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)0);
	KUNIT_ASSERT_EQ(test, args.buf_len, (u32)device_claims_len);
	args.buf_ptr = (u64)(unsigned long)buf;
	args.buf_len = 384U;
	memset(buf, 0, 384U);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len, device_claims,
				  device_claims_len);

	args.token_class = KACS_TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS;
	args.buf_len = 384U;
	args.buf_ptr = (u64)(unsigned long)buf;
	memset(buf, 0, 384U);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_ASSERT_EQ(test, args.buf_len, 12U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0), 2U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 4), 3001U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 8), 3002U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
}


static void pkm_kunit_token_query_public_tail_short_buffers(struct kunit *test)
{
	static const u32 supplementary_gids[] = {
		44U, 55U,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.projected_uid = 1400U,
		.projected_gid = 1401U,
		.source_name = "KQRYTAIL",
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.projected_supplementary_gids = supplementary_gids,
		.projected_supplementary_gid_count =
			ARRAY_SIZE(supplementary_gids),
	};
	struct kacs_query_args args = { };
	u8 session_spec[96] = { };
	u8 token_spec[640] = { };
	u8 claim_entry[96] = { };
	u8 claim_array[160] = { };
	u8 buf[64] = { 0xaa };
	size_t claim_array_len = 0;
	size_t entry_len;
	size_t token_spec_len;
	u64 session_id = 0;
	const void *subject_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	entry_len = pkm_kunit_build_claim_entry_string(
		claim_entry, sizeof(claim_entry), "Kind", 0U, "svc");
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(
				claim_array, sizeof(claim_array),
				&claim_array_len, claim_entry, entry_len),
			0);

	spec_args.user_claims = claim_array;
	spec_args.user_claims_len = claim_array_len;

	entry_len = pkm_kunit_build_session_spec(session_spec,
						 PKM_KUNIT_LOGON_TYPE_NETWORK,
						 "Kerberos",
						 pkm_kunit_local_service_sid,
						 sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, entry_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);

	args.token_class = KACS_TOKEN_CLASS_USER_CLAIMS;
	args.buf_len = 1U;
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)-ERANGE);
	KUNIT_EXPECT_EQ(test, args.buf_len, (u32)claim_array_len);
	KUNIT_EXPECT_EQ(test, buf[0], 0xaa);

	memset(buf, 0xaa, sizeof(buf));
	args.buf_len = 34U;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)-ERANGE);
	KUNIT_EXPECT_EQ(test, args.buf_len, (u32)claim_array_len);
	KUNIT_EXPECT_EQ(test, buf[0], 0xaa);

	args.token_class = KACS_TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS;
	args.buf_len = 8U;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)-ERANGE);
	KUNIT_EXPECT_EQ(test, args.buf_len, 12U);
	KUNIT_EXPECT_EQ(test, buf[0], 0xaa);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
}


static void pkm_kunit_token_query_short_and_fault_buffers(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_USER,
		.buf_len = 1,
	};
	u8 buf[12] = { 0xaa };
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)-ERANGE);
	KUNIT_EXPECT_EQ(test, args.buf_len, 12U);
	KUNIT_EXPECT_EQ(test, buf[0], 0xaa);

	args.buf_len = sizeof(buf);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test, args.buf_len, 12U);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_token_query_deferred_fields_payload(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_OWNER,
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot snapshot = { };
	static const u8 system_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	static const u8 administrators_sid[] = {
		1, 2, 0, 0, 0, 0, 0, 5,
		32, 0, 0, 0, 32, 2, 0, 0,
	};
	u8 buf[64] = { };
	long fd;

	fd = pkm_kacs_open_self_token_internal(0, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token, &snapshot));

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, (u32)sizeof(system_sid));
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len, system_sid,
				  sizeof(system_sid));

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_PRIMARY_GROUP;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, (u32)sizeof(administrators_sid));
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len, administrators_sid,
				  sizeof(administrators_sid));

	memset(buf, 0xff, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_STATISTICS;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 40U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 0), snapshot.token_id);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 8), snapshot.session_id);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 16), snapshot.modified_id);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 24), 1U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 28), 0U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 32), 0ULL);

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_DEFAULT_DACL;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len,
			(u32)sizeof(pkm_kunit_system_default_dacl));
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  pkm_kunit_system_default_dacl,
				  sizeof(pkm_kunit_system_default_dacl));
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
}


static void pkm_kunit_token_query_boolean_preserves_raw_u64(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_USER_CLAIMS,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.source_name = "KBOOLRAW",
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	u8 session_spec[96] = { };
	u8 token_spec[512] = { };
	u8 claim_entry[96] = { };
	u8 claim_array[128] = { };
	u8 buf[128] = { };
	size_t claim_array_len = 0;
	size_t entry_len;
	size_t token_spec_len;
	u64 session_id = 0;
	const void *subject_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	entry_len = pkm_kunit_build_claim_entry_scalar(
		claim_entry, sizeof(claim_entry), "RawBool",
		PKM_KUNIT_CLAIM_TYPE_BOOLEAN, 0U, 2ULL);
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(claim_array,
						    sizeof(claim_array),
						    &claim_array_len,
						    claim_entry, entry_len),
			0);

	entry_len = pkm_kunit_build_session_spec(session_spec,
						 PKM_KUNIT_LOGON_TYPE_NETWORK,
						 "Kerberos",
						 pkm_kunit_local_service_sid,
						 sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, entry_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	spec_args.user_claims = claim_array;
	spec_args.user_claims_len = claim_array_len;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, NULL),
			(long)0);
	KUNIT_ASSERT_EQ(test, args.buf_len, (u32)claim_array_len);
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len, claim_array,
				  claim_array_len);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
}


static void pkm_kunit_token_link_success_sets_roles_and_gets_partner(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_get_linked_token_args get = {
		.result_fd = -1,
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot caller_after = { };
	const void *caller_token;
	const void *actual_partner = NULL;
	u32 access_mask = 0;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_linked_pair(test, caller_token, &pair),
			0);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)pair.elevated_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_FULL);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)pair.filtered_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_LIMITED);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_token_fd_clone_token((int)pair.filtered_fd,
						      &actual_partner,
						      &access_mask),
			0);
	KUNIT_EXPECT_EQ(test, access_mask,
			KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_get_linked(
				(int)pair.elevated_fd, caller_token, &get),
			(long)0);
	KUNIT_ASSERT_GE(test, (long)get.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(get.result_fd, &view),
			0);
	KUNIT_EXPECT_PTR_EQ(test, view.token, actual_partner);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_ALL_ACCESS);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(caller_token,
							 &caller_after));
	KUNIT_EXPECT_EQ(test,
			caller_after.privileges_used & PKM_KUNIT_SE_TCB_PRIVILEGE,
			PKM_KUNIT_SE_TCB_PRIVILEGE);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)get.result_fd), 0);
	kacs_rust_token_drop(actual_partner);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_get_linked_unprivileged_returns_query_copy(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_get_linked_token_args get = {
		.result_fd = -1,
	};
	struct pkm_kacs_token_fd_view view = { };
	const void *caller_token;
	const void *caller_without_tcb;
	const void *actual_partner = NULL;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	caller_without_tcb = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, caller_without_tcb);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_linked_pair(test, caller_token, &pair),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_token_fd_clone_token((int)pair.elevated_fd,
						      &actual_partner, NULL),
			0);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_get_linked(
				(int)pair.filtered_fd, caller_without_tcb, &get),
			(long)0);
	KUNIT_ASSERT_GE(test, (long)get.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(get.result_fd, &view),
			0);
	KUNIT_EXPECT_FALSE(test, view.token == actual_partner);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, get.result_fd,
						  KACS_TOKEN_CLASS_TYPE),
			KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, get.result_fd,
						  KACS_TOKEN_CLASS_IMPERSONATION_LEVEL),
			KACS_IMLEVEL_IDENTIFICATION);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, get.result_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_FULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)get.result_fd), 0);
	kacs_rust_token_drop(actual_partner);
	kacs_rust_token_drop(caller_without_tcb);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_get_linked_query_copy_duplicate_semantics(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_get_linked_token_args get = {
		.result_fd = -1,
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot actual = { };
	struct pkm_kacs_boot_snapshot copy = { };
	const void *caller_token;
	const void *caller_without_tcb;
	const void *actual_partner = NULL;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	caller_without_tcb = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, caller_without_tcb);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_linked_pair(test, caller_token, &pair),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_token_fd_clone_token((int)pair.elevated_fd,
						      &actual_partner, NULL),
			0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(actual_partner,
							 &actual));

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_get_linked(
				(int)pair.filtered_fd, caller_without_tcb, &get),
			(long)0);
	KUNIT_ASSERT_GE(test, (long)get.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(get.result_fd, &view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token, &copy));

	KUNIT_EXPECT_FALSE(test, view.token == actual_partner);
	KUNIT_EXPECT_EQ(test, view.access_mask, KACS_TOKEN_QUERY);
	KUNIT_EXPECT_EQ(test, copy.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, copy.impersonation_level,
			(u32)KACS_IMLEVEL_IDENTIFICATION);
	KUNIT_EXPECT_EQ(test, copy.elevation_type, actual.elevation_type);
	KUNIT_EXPECT_TRUE(test, copy.token_id != actual.token_id);
	KUNIT_EXPECT_EQ(test, copy.modified_id, copy.token_id);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)get.result_fd), 0);
	kacs_rust_token_drop(actual_partner);
	kacs_rust_token_drop(caller_without_tcb);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_get_linked_query_copy_fresh_sd_and_default_dacl(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_get_linked_token_args get = {
		.result_fd = -1,
	};
	struct kacs_adjust_default_args adjust = {
		.dacl_ptr = 1,
		.dacl_len = sizeof(pkm_kunit_replacement_default_dacl),
		.owner_index = 0xFFFF,
		.group_index = 0xFFFF,
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot actual_after = { };
	struct pkm_kacs_boot_snapshot copy = { };
	const u8 *input_sd = NULL;
	const u8 *result_sd = NULL;
	const void *caller_token;
	const void *caller_without_tcb;
	const void *actual_partner = NULL;
	size_t input_sd_len = 0;
	size_t result_sd_len = 0;
	long write_fd;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	caller_without_tcb = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, caller_without_tcb);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_linked_pair(test, caller_token, &pair),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_token_fd_clone_token((int)pair.elevated_fd,
						      &actual_partner, NULL),
			0);

	write_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		caller_token, actual_partner,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT |
			KACS_ACCESS_WRITE_DAC);
	KUNIT_ASSERT_GE(test, write_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default(
				(int)write_fd, &adjust,
				pkm_kunit_replacement_default_dacl),
			(long)0);

	input_sd = kacs_rust_kunit_create_query_only_token_sd(&input_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, input_sd);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_set_token_sd_for_subject(
				(int)write_fd, caller_token,
				PKM_KUNIT_DACL_SECURITY_INFORMATION, input_sd,
				input_sd_len, &result_sd, &result_sd_len),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(actual_partner,
							 &actual_after));

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_get_linked(
				(int)pair.filtered_fd, caller_without_tcb, &get),
			(long)0);
	KUNIT_ASSERT_GE(test, (long)get.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(get.result_fd, &view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token, &copy));

	KUNIT_EXPECT_TRUE(test, copy.token_id != actual_after.token_id);
	KUNIT_EXPECT_EQ(test, copy.modified_id, copy.token_id);
	KUNIT_EXPECT_EQ(test, copy.default_dacl_len,
			actual_after.default_dacl_len);
	pkm_kunit_expect_bytes_eq(test, copy.default_dacl_ptr,
				  copy.default_dacl_len,
				  actual_after.default_dacl_ptr,
				  actual_after.default_dacl_len);
	KUNIT_EXPECT_FALSE(test,
			   copy.default_dacl_ptr ==
				   actual_after.default_dacl_ptr);
	pkm_kunit_expect_bytes_eq(test, copy.default_dacl_ptr,
				  copy.default_dacl_len,
				  pkm_kunit_replacement_default_dacl,
				  sizeof(pkm_kunit_replacement_default_dacl));

	KUNIT_ASSERT_NOT_NULL(test, copy.own_sd_ptr);
	KUNIT_ASSERT_NOT_NULL(test, actual_after.own_sd_ptr);
	KUNIT_EXPECT_FALSE(test, copy.own_sd_ptr == actual_after.own_sd_ptr);
	KUNIT_EXPECT_TRUE(test,
			  copy.own_sd_len != actual_after.own_sd_len ||
				  memcmp(copy.own_sd_ptr,
					 actual_after.own_sd_ptr,
					 copy.own_sd_len) != 0);
	pkm_kunit_expect_sd_sid_component(test, copy.own_sd_ptr,
					  copy.own_sd_len, 4,
					  actual_after.user_sid_ptr,
					  actual_after.user_sid_len);
	pkm_kunit_expect_owner_rights_read_control_ace(
		test, copy.own_sd_ptr, copy.own_sd_len, 0);
	pkm_kunit_expect_allow_ace(test, copy.own_sd_ptr, copy.own_sd_len, 1,
				   PKM_KUNIT_DEFAULT_TOKEN_SELF_ACCESS,
				   actual_after.user_sid_ptr,
				   actual_after.user_sid_len);
	pkm_kunit_expect_allow_ace(test, copy.own_sd_ptr, copy.own_sd_len, 2,
				   KACS_TOKEN_ALL_ACCESS, pkm_kunit_system_sid,
				   sizeof(pkm_kunit_system_sid));
	KUNIT_EXPECT_PTR_EQ(test,
			    pkm_kunit_dacl_ace_const(copy.own_sd_ptr,
						     copy.own_sd_len, 3),
			    NULL);

	pkm_kacs_free((void *)result_sd);
	pkm_kacs_free((void *)input_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)get.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)write_fd), 0);
	kacs_rust_token_drop(actual_partner);
	kacs_rust_token_drop(caller_without_tcb);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_own_sd_constructor_matrix(struct kunit *test)
{
	static const u8 source_name[8] = {
		'O', 'w', 'n', 'S', 'D', 0, 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
	};
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_duplicate_args duplicate = {
		.access_mask = KACS_TOKEN_QUERY,
		.token_type = KACS_TOKEN_TYPE_IMPERSONATION,
		.impersonation_level = KACS_IMLEVEL_IMPERSONATION,
		.result_fd = -1,
	};
	struct kacs_restrict_args restrict_args = {
		.privs_to_delete = 1ULL << PKM_KUNIT_PRIV_LUID_REMOVE,
		.num_deny_indices = 1,
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct kacs_get_linked_token_args get = {
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot source_snapshot = { };
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.owner_sid_index = 0,
		.primary_group_index = 1,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	struct pkm_kacs_token_fd_view view = { };
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	u8 restrict_payload[64] = { };
	u32 deny_indices[1] = { 0 };
	const void *subject_token;
	const void *token;
	const void *anonymous_clone = NULL;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;
	long fd;
	long source_fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	pkm_kunit_expect_token_own_sd_valid(test, subject_token);
	pkm_kunit_expect_token_own_sd_valid(test,
					    pkm_kacs_boot_anonymous_token_ptr());

	token = kacs_rust_kunit_create_query_only_token();
	pkm_kunit_expect_token_own_sd_valid(test, token);
	kacs_rust_token_drop(token);

	token = kacs_rust_kunit_create_without_tcb_token();
	pkm_kunit_expect_token_own_sd_valid(test, token);
	kacs_rust_token_drop(token);

	KUNIT_ASSERT_EQ(test,
			kacs_rust_create_anonymous_impersonation_token(
				&anonymous_clone),
			0);
	pkm_kunit_expect_token_own_sd_valid(test, anonymous_clone);
	kacs_rust_token_drop(anonymous_clone);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test, pkm_kacs_kunit_token_fd_snapshot((int)fd, &view),
			0);
	pkm_kunit_expect_token_own_sd_valid(test, view.token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();

	token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	source_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, token, KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, source_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_duplicate(
				(int)source_fd, subject_token, subject_token,
				&duplicate),
			(long)0);
	KUNIT_ASSERT_GE(test, (long)duplicate.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(duplicate.result_fd,
							 &view),
			0);
	pkm_kunit_expect_token_own_sd_valid(test, view.token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)duplicate.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
	kacs_rust_token_drop(token);

	token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	source_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, token, KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, source_fd, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token,
							 &source_snapshot));
	KUNIT_ASSERT_GT(test, source_snapshot.group_count, 0U);
	restrict_args.data_len = pkm_kunit_build_restrict_payload(
		restrict_payload, deny_indices, ARRAY_SIZE(deny_indices),
		source_snapshot.groups_ptr, 1);
	KUNIT_ASSERT_GT(test, restrict_args.data_len, sizeof(u32));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict(
				(int)source_fd, subject_token, subject_token,
				&restrict_args, restrict_payload),
			(long)0);
	KUNIT_ASSERT_GE(test, (long)restrict_args.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(restrict_args.result_fd,
							 &view),
			0);
	pkm_kunit_expect_token_own_sd_valid(test, view.token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)restrict_args.result_fd),
			0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
	kacs_rust_token_drop(token);

	KUNIT_ASSERT_EQ(test, pkm_kunit_create_linked_pair(test, subject_token,
							   &pair),
			0);
	token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_get_linked((int)pair.filtered_fd,
							   token, &get),
			(long)0);
	KUNIT_ASSERT_GE(test, (long)get.result_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(get.result_fd, &view),
			0);
	pkm_kunit_expect_token_own_sd_valid(test, view.token);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)get.result_fd), 0);
	kacs_rust_token_drop(token);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_link_requires_tcb(struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_link_tokens_args link;
	const void *caller_token;
	const void *caller_without_tcb;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	caller_without_tcb = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, caller_without_tcb);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_link_candidates(test, caller_token,
							 &pair),
			0);

	link.elevated_fd = (s32)pair.elevated_fd;
	link.filtered_fd = (s32)pair.filtered_fd;
	link.session_id = pair.session_id;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_link((int)pair.elevated_fd,
						      caller_without_tcb,
						      &link),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)pair.elevated_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_DEFAULT);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)pair.filtered_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_DEFAULT);

	kacs_rust_token_drop(caller_without_tcb);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_link_requires_duplicate_rights(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_link_tokens_args link;
	const void *caller_token;
	const void *filtered_token = NULL;
	long readonly_fd;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_link_candidates(test, caller_token,
							 &pair),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_token_fd_clone_token((int)pair.filtered_fd,
						      &filtered_token, NULL),
			0);
	KUNIT_ASSERT_EQ(test, close_fd((unsigned int)pair.filtered_fd), 0);
	readonly_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		caller_token, filtered_token, KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, readonly_fd, 0L);
	pair.filtered_fd = readonly_fd;

	link.elevated_fd = (s32)pair.elevated_fd;
	link.filtered_fd = (s32)pair.filtered_fd;
	link.session_id = pair.session_id;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_link((int)pair.elevated_fd,
						      caller_token, &link),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)pair.elevated_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_DEFAULT);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)pair.filtered_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_DEFAULT);

	kacs_rust_token_drop(filtered_token);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_link_self_denies(struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_link_tokens_args link;
	const void *caller_token;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_link_candidates(test, caller_token,
							 &pair),
			0);

	link.elevated_fd = (s32)pair.elevated_fd;
	link.filtered_fd = (s32)pair.elevated_fd;
	link.session_id = pair.session_id;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_link((int)pair.elevated_fd,
						      caller_token, &link),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)pair.elevated_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_DEFAULT);

	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_link_session_mismatch_denies(struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_link_tokens_args link;
	const void *caller_token;
	long mismatch_fd;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_link_candidates(test, caller_token,
							 &pair),
			0);

	mismatch_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		caller_token, pkm_kacs_boot_system_token_ptr(),
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, mismatch_fd, 0L);

	link.elevated_fd = (s32)pair.elevated_fd;
	link.filtered_fd = (s32)mismatch_fd;
	link.session_id = pair.session_id;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_link((int)pair.elevated_fd,
						      caller_token, &link),
			(long)-EINVAL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mismatch_fd), 0);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_link_non_primary_denies(struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_link_tokens_args link;
	const void *caller_token;
	const void *impersonation_token;
	long impersonation_fd;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_link_candidates(test, caller_token,
							 &pair),
			0);

	impersonation_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE,
		KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IDENTIFICATION,
		PKM_KUNIT_IL_MEDIUM, 0U, 0ULL);
	KUNIT_ASSERT_NOT_NULL(test, impersonation_token);
	impersonation_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		caller_token, impersonation_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, impersonation_fd, 0L);

	link.elevated_fd = (s32)pair.elevated_fd;
	link.filtered_fd = (s32)impersonation_fd;
	link.session_id = pair.session_id;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_link((int)pair.elevated_fd,
						      caller_token, &link),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)pair.elevated_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_DEFAULT);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)impersonation_fd), 0);

	kacs_rust_token_drop(impersonation_token);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_link_role_swap_denies(struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_link_tokens_args link;
	const void *caller_token;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_linked_pair(test, caller_token, &pair),
			0);

	link.elevated_fd = (s32)pair.filtered_fd;
	link.filtered_fd = (s32)pair.elevated_fd;
	link.session_id = pair.session_id;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_link((int)pair.elevated_fd,
						      caller_token, &link),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)pair.elevated_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_FULL);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)pair.filtered_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_LIMITED);

	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_link_replacement_invalidates_old_partner(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_duplicate_args duplicate = {
		.access_mask = KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE,
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.result_fd = -1,
	};
	struct kacs_link_tokens_args link;
	struct kacs_get_linked_token_args get = {
		.result_fd = -1,
	};
	const void *caller_token;
	long old_filtered_fd;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_linked_pair(test, caller_token, &pair),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_duplicate(
				(int)pair.elevated_fd, caller_token,
				pair.source_token, &duplicate),
			(long)0);
	KUNIT_ASSERT_GE(test, (long)duplicate.result_fd, 0L);

	old_filtered_fd = pair.filtered_fd;
	link.elevated_fd = (s32)pair.elevated_fd;
	link.filtered_fd = duplicate.result_fd;
	link.session_id = pair.session_id;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_link((int)pair.elevated_fd,
						      caller_token, &link),
			(long)0);
	pair.filtered_fd = duplicate.result_fd;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_get_linked((int)old_filtered_fd,
						      caller_token, &get),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)old_filtered_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_LIMITED);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)old_filtered_fd), 0);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_link_replacement_invalidates_old_elevated(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_duplicate_args duplicate = {
		.access_mask = KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE,
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.result_fd = -1,
	};
	struct kacs_link_tokens_args link;
	struct kacs_get_linked_token_args get = {
		.result_fd = -1,
	};
	const void *caller_token;
	long old_elevated_fd;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_linked_pair(test, caller_token, &pair),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_duplicate(
				(int)pair.elevated_fd, caller_token,
				pair.source_token, &duplicate),
			(long)0);
	KUNIT_ASSERT_GE(test, (long)duplicate.result_fd, 0L);

	old_elevated_fd = pair.elevated_fd;
	link.elevated_fd = duplicate.result_fd;
	link.filtered_fd = (s32)pair.filtered_fd;
	link.session_id = pair.session_id;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_link(duplicate.result_fd,
						      caller_token, &link),
			(long)0);
	pair.elevated_fd = duplicate.result_fd;

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_get_linked((int)old_elevated_fd,
						      caller_token, &get),
			(long)-ENOENT);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)old_elevated_fd,
						  KACS_TOKEN_CLASS_ELEVATION_TYPE),
			KACS_ELEVATION_FULL);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)old_elevated_fd), 0);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_get_linked_requires_query_right(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_get_linked_token_args get = {
		.result_fd = -1,
	};
	const void *caller_token;
	long no_query_fd;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_linked_pair(test, caller_token, &pair),
			0);

	no_query_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		caller_token, pair.source_token, KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, no_query_fd, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_get_linked((int)no_query_fd,
						      caller_token, &get),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)no_query_fd), 0);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_token_get_linked_default_token_returns_enoent(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct kacs_get_linked_token_args get = {
		.result_fd = -1,
	};
	const void *caller_token;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_link_candidates(test, caller_token,
							 &pair),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_get_linked((int)pair.elevated_fd,
						      caller_token, &get),
			(long)-ENOENT);
	pkm_kunit_cleanup_linked_pair(test, &pair);
}


static void pkm_kunit_linked_session_destroy_emits_single_kmes_event(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct pkm_kacs_session_snapshot snapshot = { };
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	u8 *buffer;
	const void *caller_token;
	size_t written = 0;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_dynamic_linked_pair(test, caller_token,
							      &pair),
			0);
	KUNIT_ASSERT_EQ(test, kacs_rust_kunit_session_snapshot(pair.session_id,
							       &snapshot),
			0);

	pkm_kunit_reset_kmes();
	kacs_rust_token_drop(pair.source_token);
	pair.source_token = NULL;
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)pair.elevated_fd), 0);
	flush_delayed_fput();
	pair.elevated_fd = -1;
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)pair.filtered_fd), 0);
	flush_delayed_fput();
	pair.filtered_fd = -1;

	KUNIT_EXPECT_EQ(test, kacs_rust_kunit_session_snapshot(pair.session_id,
							       &snapshot),
			-EACCES);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&kmes_snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_EQ(test, kmes_snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, kmes_snapshot.dropped_events, 0ULL);
	pkm_kunit_expect_bytes_eq(test, view.type_ptr, view.type_len,
				  (const u8 *)"logon-session-destroyed",
				  sizeof("logon-session-destroyed") - 1);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 (const u8 *)"Negotiate",
						 sizeof("Negotiate") - 1));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_contains_bytes(view.payload_ptr,
						 view.payload_len,
						 pkm_kunit_local_service_sid,
						 sizeof(pkm_kunit_local_service_sid)));
}


static void pkm_kunit_linked_session_destroy_waits_for_external_fd(
	struct kunit *test)
{
	struct pkm_kunit_linked_pair pair = {
		.elevated_fd = -1,
		.filtered_fd = -1,
	};
	struct pkm_kacs_session_snapshot snapshot = { };
	struct pkm_kmes_kunit_snapshot kmes_snapshot = { };
	const void *caller_token;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_create_dynamic_linked_pair(test, caller_token,
							      &pair),
			0);
	KUNIT_ASSERT_EQ(test, kacs_rust_kunit_session_snapshot(pair.session_id,
							       &snapshot),
			0);

	pkm_kunit_reset_kmes();
	kacs_rust_token_drop(pair.source_token);
	pair.source_token = NULL;
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)pair.filtered_fd), 0);
	flush_delayed_fput();
	pair.filtered_fd = -1;

	KUNIT_EXPECT_EQ(test, kacs_rust_kunit_session_snapshot(pair.session_id,
							       &snapshot),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kmes_kunit_snapshot_single_active(&kmes_snapshot),
			-ENOENT);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)pair.elevated_fd), 0);
	flush_delayed_fput();
	pair.elevated_fd = -1;
	KUNIT_EXPECT_EQ(test, kacs_rust_kunit_session_snapshot(pair.session_id,
							       &snapshot),
			-EACCES);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_snapshot_single_active(&kmes_snapshot),
			0);
	KUNIT_EXPECT_EQ(test, kmes_snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, kmes_snapshot.dropped_events, 0ULL);
}


static void pkm_kunit_token_adjust_sessionid_updates_target(struct kunit *test)
{
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_SESSION_ID,
		.buf_len = 4,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kacs_boot_snapshot caller_after = { };
	u8 buf[40] = { };
	const void *caller_token;
	const void *target_token;
	long fd;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);

	target_token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		caller_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_SESSIONID);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_session_for_token(
				(int)fd, caller_token, 7U),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, before.interactive_session_id, 0U);
	KUNIT_EXPECT_EQ(test, after.interactive_session_id, 7U);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0), 7U);

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_STATISTICS;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 16), after.modified_id);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(caller_token,
							 &caller_after));
	KUNIT_EXPECT_EQ(test,
			caller_after.privileges_used & PKM_KUNIT_SE_TCB_PRIVILEGE,
			PKM_KUNIT_SE_TCB_PRIVILEGE);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_sessionid_requires_cached_right(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *caller_token;
	const void *target_token;
	long fd;

	caller_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, caller_token);

	target_token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(caller_token,
						      target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_session_for_token(
				(int)fd, caller_token, 9U),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.interactive_session_id,
			before.interactive_session_id);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_sessionid_requires_tcb(struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	const void *caller_without_tcb;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	caller_without_tcb = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, caller_without_tcb);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_SESSIONID);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_session_for_token(
				(int)fd, caller_without_tcb, 11U),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.interactive_session_id,
			before.interactive_session_id);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(caller_without_tcb);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_surfaces_preserve_mandatory_policy(
	struct kunit *test)
{
	struct kacs_adjust_default_args default_adjust = {
		.dacl_ptr = 1,
		.dacl_len = sizeof(pkm_kunit_replacement_default_dacl),
		.owner_index = 0xFFFF,
		.group_index = 0xFFFF,
	};
	struct kacs_adjust_groups_args group_adjust = {
		.count = 1,
	};
	struct kacs_group_entry group_entry = {
		.index = 0,
		.enable = 0,
	};
	struct kacs_adjust_privs_args priv_adjust = {
		.count = 1,
	};
	struct kacs_priv_entry priv_entry = {
		.luid = PKM_KUNIT_PRIV_LUID_DISABLE,
		.attributes = 0,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	u32 mandatory_policy;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_without_tcb_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_SESSIONID);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	mandatory_policy = pkm_kunit_query_token_u32(
		test, (int)fd, KACS_TOKEN_CLASS_MANDATORY_POLICY);
	KUNIT_ASSERT_EQ(test, mandatory_policy, before.mandatory_policy);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_session_for_token(
				(int)fd, subject_token, 17U),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.mandatory_policy, mandatory_policy);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)fd,
						  KACS_TOKEN_CLASS_MANDATORY_POLICY),
			mandatory_policy);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	mandatory_policy = pkm_kunit_query_token_u32(
		test, (int)fd, KACS_TOKEN_CLASS_MANDATORY_POLICY);
	KUNIT_ASSERT_EQ(test, mandatory_policy, before.mandatory_policy);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default(
				(int)fd, &default_adjust,
				pkm_kunit_replacement_default_dacl),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.mandatory_policy, mandatory_policy);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)fd,
						  KACS_TOKEN_CLASS_MANDATORY_POLICY),
			mandatory_policy);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	mandatory_policy = pkm_kunit_query_token_u32(
		test, (int)fd, KACS_TOKEN_CLASS_MANDATORY_POLICY);
	KUNIT_ASSERT_EQ(test, mandatory_policy, before.mandatory_policy);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups(
				(int)fd, &group_adjust, &group_entry),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.mandatory_policy, mandatory_policy);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)fd,
						  KACS_TOKEN_CLASS_MANDATORY_POLICY),
			mandatory_policy);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	mandatory_policy = pkm_kunit_query_token_u32(
		test, (int)fd, KACS_TOKEN_CLASS_MANDATORY_POLICY);
	KUNIT_ASSERT_EQ(test, mandatory_policy, before.mandatory_policy);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd,
							    &priv_adjust,
							    &priv_entry),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.mandatory_policy, mandatory_policy);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)fd,
						  KACS_TOKEN_CLASS_MANDATORY_POLICY),
			mandatory_policy);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_default_updates_fields(struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.dacl_ptr = 1,
		.dacl_len = sizeof(pkm_kunit_replacement_default_dacl),
		.owner_index = 1,
		.group_index = 2,
	};
	struct kacs_query_args args = {
		.buf_len = 64,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 buf[64] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default(
				(int)fd, &adjust,
				pkm_kunit_replacement_default_dacl),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, before.owner_sid_index, 0U);
	KUNIT_EXPECT_EQ(test, after.owner_sid_index, 1U);
	KUNIT_EXPECT_EQ(test, before.primary_group_index, 1U);
	KUNIT_EXPECT_EQ(test, after.primary_group_index, 2U);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);
	pkm_kunit_expect_bytes_eq(test, after.default_dacl_ptr,
				  after.default_dacl_len,
				  pkm_kunit_replacement_default_dacl,
				  sizeof(pkm_kunit_replacement_default_dacl));

	args.token_class = KACS_TOKEN_CLASS_OWNER;
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, after.groups_ptr[0].sid_len);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  after.groups_ptr[0].sid_ptr,
				  after.groups_ptr[0].sid_len);

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_PRIMARY_GROUP;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, after.groups_ptr[1].sid_len);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  after.groups_ptr[1].sid_ptr,
				  after.groups_ptr[1].sid_len);

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_DEFAULT_DACL;
	args.buf_len = sizeof(buf);
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len,
			(u32)sizeof(pkm_kunit_replacement_default_dacl));
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  pkm_kunit_replacement_default_dacl,
				  sizeof(pkm_kunit_replacement_default_dacl));

	memset(buf, 0, sizeof(buf));
	args.token_class = KACS_TOKEN_CLASS_STATISTICS;
	args.buf_len = 40;
	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 16), after.modified_id);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_default_clear_dacl(struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.dacl_ptr = 1,
		.dacl_len = 0,
		.owner_index = 0xFFFF,
		.group_index = 0xFFFF,
	};
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_DEFAULT_DACL,
		.buf_len = 8,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 buf[8] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default((int)fd, &adjust,
							      NULL),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.default_dacl_len, 0U);
	KUNIT_EXPECT_EQ(test, after.owner_sid_index, before.owner_sid_index);
	KUNIT_EXPECT_EQ(test, after.primary_group_index,
			before.primary_group_index);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_default_owner_user_sid_success(
	struct kunit *test)
{
	struct kacs_adjust_default_args group_owner = {
		.owner_index = 1,
		.group_index = 0xFFFF,
	};
	struct kacs_adjust_default_args user_owner = {
		.owner_index = 0,
		.group_index = 0xFFFF,
	};
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_OWNER,
		.buf_len = 64,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after_group = { };
	struct pkm_kacs_boot_snapshot after_user = { };
	u8 buf[64] = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default((int)fd,
							      &group_owner,
							      NULL),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token,
							 &after_group));
	KUNIT_EXPECT_EQ(test, after_group.owner_sid_index, 1U);
	KUNIT_EXPECT_EQ(test, after_group.modified_id, before.modified_id + 1);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default((int)fd,
							      &user_owner,
							      NULL),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token,
							 &after_user));
	KUNIT_EXPECT_EQ(test, after_user.owner_sid_index, 0U);
	KUNIT_EXPECT_EQ(test, after_user.modified_id,
			after_group.modified_id + 1);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, after_user.user_sid_len);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  after_user.user_sid_ptr,
				  after_user.user_sid_len);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_default_primary_group_user_sid_success(
	struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.owner_index = 0xFFFF,
		.group_index = 0,
	};
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_PRIMARY_GROUP,
		.buf_len = 64,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 buf[64] = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	KUNIT_ASSERT_NE(test, before.primary_group_index, 0U);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default((int)fd,
							      &adjust,
							      NULL),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.primary_group_index, 0U);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, after.user_sid_len);
	pkm_kunit_expect_bytes_eq(test, buf, args.buf_len,
				  after.user_sid_ptr, after.user_sid_len);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_default_requires_cached_right(
	struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.owner_index = 1,
		.group_index = 2,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token,
						      target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default((int)fd, &adjust,
							      NULL),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_default_invalid_owner_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.owner_index = 2,
		.group_index = 0xFFFF,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default((int)fd, &adjust,
							      NULL),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_default_invalid_primary_group_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.owner_index = 0xFFFF,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	KUNIT_ASSERT_LT(test, before.group_count, 0xFFFFU);
	adjust.group_index = (u16)(before.group_count + 1);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default((int)fd, &adjust,
							      NULL),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_default_invalid_dacl_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.dacl_ptr = 1,
		.dacl_len = sizeof(pkm_kunit_invalid_default_dacl),
		.owner_index = 0xFFFF,
		.group_index = 0xFFFF,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default(
				(int)fd, &adjust, pkm_kunit_invalid_default_dacl),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_default_null_dacl_ptr_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_default_args adjust = {
		.dacl_ptr = 0,
		.dacl_len = sizeof(pkm_kunit_replacement_default_dacl),
		.owner_index = 0xFFFF,
		.group_index = 0xFFFF,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_query_only_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_DEFAULT);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_default((int)fd, &adjust,
							      NULL),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_updates_and_queries_live_state(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 2,
	};
	struct kacs_group_entry entries[2] = {
		{ .index = 0, .enable = 0 },
		{ .index = 1, .enable = 1 },
	};
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_GROUPS,
		.buf_len = 160,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 buf[160] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     entries),
			(long)0);
	KUNIT_EXPECT_EQ(test, adjust.previous_state[0],
			PKM_KUNIT_ADJUSTABLE_GROUP_PREV_MASK);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.group_count, 5U);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[0].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP0_DEFAULT &
				~PKM_KUNIT_SE_GROUP_ENABLED);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[1].attributes,
			PKM_KUNIT_SE_GROUP_ENABLED);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[2].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP2_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[3].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP3_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[4].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP4_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(buf, 0), 5U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_groups_query_attr(buf, 0),
			PKM_KUNIT_ADJUSTABLE_GROUP0_DEFAULT &
				~PKM_KUNIT_SE_GROUP_ENABLED);
	KUNIT_EXPECT_EQ(test, pkm_kunit_groups_query_attr(buf, 1),
			PKM_KUNIT_SE_GROUP_ENABLED);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_preserves_projected_gids(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'P', 'r', 'j', 'G', 'i', 'd', 's', 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes =
				PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT,
		},
		{
			.sid = pkm_kunit_authenticated_users_sid,
			.sid_len = sizeof(pkm_kunit_authenticated_users_sid),
			.attributes = 0U,
		},
	};
	static const u32 supplementary_gids[] = {
		7001U, 7002U,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.projected_uid = 1200U,
		.projected_gid = 1201U,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
		.projected_supplementary_gids = supplementary_gids,
		.projected_supplementary_gid_count =
			ARRAY_SIZE(supplementary_gids),
	};
	struct kacs_adjust_groups_args adjust = {
		.count = 2,
	};
	struct kacs_group_entry entries[2] = {
		{ .index = 0, .enable = 0 },
		{ .index = 1, .enable = 1 },
	};
	struct kacs_query_args query = {
		.token_class = KACS_TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS,
		.buf_len = 16U,
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 session_spec[64] = { };
	u8 token_spec[384] = { };
	u8 before_buf[16] = { };
	u8 after_buf[16] = { };
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view), 0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token, &before));

	query.buf_ptr = (u64)(unsigned long)before_buf;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &query,
						      before_buf),
			(long)0);
	KUNIT_ASSERT_EQ(test, query.buf_len, 12U);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     entries),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token, &after));
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);
	KUNIT_EXPECT_EQ(test, after.projected_supplementary_gid_count,
			before.projected_supplementary_gid_count);

	query.buf_len = sizeof(after_buf);
	query.buf_ptr = (u64)(unsigned long)after_buf;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &query,
						      after_buf),
			(long)0);
	KUNIT_ASSERT_EQ(test, query.buf_len, 12U);
	pkm_kunit_expect_bytes_eq(test, after_buf, query.buf_len, before_buf,
				  sizeof(u32) * (1 + ARRAY_SIZE(supplementary_gids)));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(after_buf, 0), 2U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(after_buf, 4), 7001U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(after_buf, 8), 7002U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
}


static void pkm_kunit_token_adjust_groups_reset_restores_defaults(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 2,
	};
	struct kacs_group_entry entries[2] = {
		{ .index = 0, .enable = 0 },
		{ .index = 1, .enable = 1 },
	};
	struct kacs_adjust_groups_args reset = {
		.count = 1,
	};
	struct kacs_group_entry reset_entry = {
		.index = 0xFFFFFFFFU,
		.enable = 0,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot mutated = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     entries),
			(long)0);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &mutated));
	KUNIT_EXPECT_EQ(test, mutated.groups_ptr[0].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP0_DEFAULT &
				~PKM_KUNIT_SE_GROUP_ENABLED);
	KUNIT_EXPECT_EQ(test, mutated.groups_ptr[1].attributes,
			PKM_KUNIT_SE_GROUP_ENABLED);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &reset,
							     &reset_entry),
			(long)0);
	KUNIT_EXPECT_EQ(test, reset.previous_state[0],
			PKM_KUNIT_ADJUSTABLE_GROUP_MUTATED_MASK);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.groups_ptr[0].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP0_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[1].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP1_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[2].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP2_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[3].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP3_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.groups_ptr[4].attributes,
			PKM_KUNIT_ADJUSTABLE_GROUP4_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 2);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_requires_cached_right(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 1,
	};
	struct kacs_group_entry entry = {
		.index = 0,
		.enable = 0,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token,
						      target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     &entry),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_count_zero_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 0,
	};
	struct kacs_group_entry entry = {
		.index = 0,
		.enable = 0,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_count_over_max_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = PKM_KUNIT_MAX_TOKEN_GROUPS + 1U,
	};
	struct kacs_group_entry entry = {
		.index = 0,
		.enable = 0,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_null_entries_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     NULL),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_out_of_range_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 1,
	};
	struct kacs_group_entry entry = {
		.enable = 1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	entry.index = before.group_count;

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_ioctl_usercopy_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_ioctl((int)fd,
						      KACS_IOC_ADJUST_GROUPS,
						      0),
			(long)-EFAULT);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_ioctl((int)fd,
						      KACS_IOC_ADJUST_GROUPS,
						      1),
			(long)-EFAULT);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_duplicate_indices_fail_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 2,
	};
	struct kacs_group_entry entries[2] = {
		{ .index = 0, .enable = 0 },
		{ .index = 0, .enable = 1 },
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     entries),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_deny_only_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 2,
	};
	struct kacs_group_entry entries[2] = {
		{ .index = 0, .enable = 0 },
		{ .index = 2, .enable = 1 },
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     entries),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_deny_only_disable_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 1,
	};
	struct kacs_group_entry entry = {
		.index = 2,
		.enable = 0,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_mandatory_non_logon_fails_closed(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'd', 'j', 'G', 'r', 'p', 0, 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.owner_sid_index = 0,
		.primary_group_index = 1,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	struct kacs_adjust_groups_args adjust = {
		.count = 1,
	};
	struct kacs_group_entry entry = {
		.index = 0,
		.enable = 0,
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	const void *subject_token;
	size_t session_spec_len;
	size_t token_spec_len;
	u64 session_id = 0;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(view.token,
							       &before));
	KUNIT_ASSERT_GE(test, before.group_count, 1U);
	KUNIT_EXPECT_EQ(test,
			before.groups_ptr[0].attributes &
				PKM_KUNIT_SE_GROUP_MANDATORY,
			PKM_KUNIT_SE_GROUP_MANDATORY);
	KUNIT_EXPECT_EQ(test,
			before.groups_ptr[0].attributes &
				PKM_KUNIT_SE_GROUP_LOGON_ID,
			0U);
	KUNIT_EXPECT_TRUE(test,
			  before.groups_ptr[0].sid_len != before.user_sid_len ||
				  memcmp(before.groups_ptr[0].sid_ptr,
					 before.user_sid_ptr,
					 before.user_sid_len));

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(view.token,
							       &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
}


static void
pkm_kunit_token_adjust_groups_mandatory_non_logon_enable_fails_closed(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'A', 'd', 'j', 'G', 'r', 'p', 'E', 0,
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.owner_sid_index = 0,
		.primary_group_index = 1,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
	};
	struct kacs_adjust_groups_args adjust = {
		.count = 1,
	};
	struct kacs_group_entry entry = {
		.index = 0,
		.enable = 1,
	};
	struct pkm_kacs_token_fd_view view = { };
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	const void *subject_token;
	size_t session_spec_len;
	size_t token_spec_len;
	u64 session_id = 0;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);

	fd = pkm_kacs_kunit_create_token_for_subject(subject_token, token_spec,
						     token_spec_len);
	KUNIT_ASSERT_GE(test, fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)fd, &view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(view.token,
							       &before));
	KUNIT_ASSERT_GE(test, before.group_count, 1U);
	KUNIT_EXPECT_EQ(test,
			before.groups_ptr[0].attributes &
				PKM_KUNIT_SE_GROUP_MANDATORY,
			PKM_KUNIT_SE_GROUP_MANDATORY);
	KUNIT_EXPECT_EQ(test,
			before.groups_ptr[0].attributes &
				PKM_KUNIT_SE_GROUP_LOGON_ID,
			0U);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(view.token,
							       &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	flush_delayed_fput();
}


static void pkm_kunit_token_adjust_groups_logon_sid_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 2,
	};
	struct kacs_group_entry entries[2] = {
		{ .index = 0, .enable = 0 },
		{ .index = 4, .enable = 0 },
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     entries),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_logon_sid_enable_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 1,
	};
	struct kacs_group_entry entry = {
		.index = 4,
		.enable = 1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_user_sid_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 1,
	};
	struct kacs_group_entry entry = {
		.index = 1,
		.enable = 0,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_groups_invalid_reset_encoding_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_groups_args adjust = {
		.count = 2,
	};
	struct kacs_group_entry entries[2] = {
		{ .index = 0xFFFFFFFFU, .enable = 0 },
		{ .index = 0, .enable = 0 },
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups((int)fd, &adjust,
							     entries),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_privs_updates_and_queries_live_state(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 2,
	};
	struct kacs_priv_entry entries[2] = {
		{ .luid = PKM_KUNIT_PRIV_LUID_DISABLE, .attributes = 0 },
		{ .luid = PKM_KUNIT_PRIV_LUID_ENABLE,
		  .attributes = PKM_KUNIT_SE_PRIVILEGE_ENABLED },
	};
	struct kacs_query_args args = {
		.token_class = KACS_TOKEN_CLASS_PRIVILEGES,
		.buf_len = 32,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 buf[32] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    entries),
			(long)0);
	KUNIT_EXPECT_EQ(test, adjust.previous_enabled,
			PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_present,
			PKM_KUNIT_ADJUSTABLE_PRIV_PRESENT);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled,
			PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_ENABLE_DISABLE);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled_by_default,
			PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED_BY_DEFAULT);
	KUNIT_EXPECT_EQ(test, after.privileges_used, 0ULL);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);

	args.buf_ptr = (u64)(unsigned long)buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)fd, &args, buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, args.buf_len, 32U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 0),
			PKM_KUNIT_ADJUSTABLE_PRIV_PRESENT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 8),
			PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_ENABLE_DISABLE);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 16),
			PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED_BY_DEFAULT);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(buf, 24), 0ULL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_privs_remove_preserves_used_and_reset(
	struct kunit *test)
{
	struct kacs_adjust_privs_args remove = {
		.count = 1,
	};
	struct kacs_priv_entry remove_entry = {
		.luid = PKM_KUNIT_PRIV_LUID_REMOVE,
		.attributes = PKM_KUNIT_SE_PRIVILEGE_REMOVED,
	};
	struct kacs_adjust_privs_args mutate = {
		.count = 2,
	};
	struct kacs_priv_entry mutate_entries[2] = {
		{ .luid = PKM_KUNIT_PRIV_LUID_DISABLE, .attributes = 0 },
		{ .luid = PKM_KUNIT_PRIV_LUID_ENABLE,
		  .attributes = PKM_KUNIT_SE_PRIVILEGE_ENABLED },
	};
	struct kacs_adjust_privs_args reset = {
		.count = 1,
	};
	struct kacs_priv_entry reset_entry = {
		.luid = 0,
		.attributes = PKM_KUNIT_PRIV_RESET_ALL_DEFAULTS,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot removed = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_token_mark_privileges_used(
				  target_token,
				  1ULL << PKM_KUNIT_PRIV_LUID_REMOVE));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &remove,
							    &remove_entry),
			(long)0);
	KUNIT_EXPECT_EQ(test, remove.previous_enabled,
			PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &removed));
	KUNIT_EXPECT_EQ(test, removed.privileges_present,
			PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_REMOVE);
	KUNIT_EXPECT_EQ(test, removed.privileges_enabled,
			1ULL << PKM_KUNIT_PRIV_LUID_DISABLE);
	KUNIT_EXPECT_EQ(test, removed.privileges_enabled_by_default,
			1ULL << PKM_KUNIT_PRIV_LUID_DISABLE);
	KUNIT_EXPECT_EQ(test,
			removed.privileges_used &
				(1ULL << PKM_KUNIT_PRIV_LUID_REMOVE),
			1ULL << PKM_KUNIT_PRIV_LUID_REMOVE);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &mutate,
							    mutate_entries),
			(long)0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &reset,
							    &reset_entry),
			(long)0);
	KUNIT_EXPECT_EQ(test, reset.previous_enabled,
			1ULL << PKM_KUNIT_PRIV_LUID_ENABLE);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_present,
			PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_REMOVE);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled,
			1ULL << PKM_KUNIT_PRIV_LUID_DISABLE);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled_by_default,
			1ULL << PKM_KUNIT_PRIV_LUID_DISABLE);
	KUNIT_EXPECT_EQ(test,
			after.privileges_used &
				(1ULL << PKM_KUNIT_PRIV_LUID_REMOVE),
			1ULL << PKM_KUNIT_PRIV_LUID_REMOVE);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 3);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_privs_absent_disable_remove_noop(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 2,
	};
	struct kacs_priv_entry entries[2] = {
		{ .luid = PKM_KUNIT_PRIV_LUID_ABSENT_DISABLE, .attributes = 0 },
		{ .luid = PKM_KUNIT_PRIV_LUID_ABSENT_REMOVE,
		  .attributes = PKM_KUNIT_SE_PRIVILEGE_REMOVED },
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    entries),
			(long)0);
	KUNIT_EXPECT_EQ(test, adjust.previous_enabled,
			PKM_KUNIT_ADJUSTABLE_PRIV_ENABLED);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	KUNIT_EXPECT_EQ(test, after.privileges_present, before.privileges_present);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled, before.privileges_enabled);
	KUNIT_EXPECT_EQ(test, after.privileges_enabled_by_default,
			before.privileges_enabled_by_default);
	KUNIT_EXPECT_EQ(test, after.privileges_used, before.privileges_used);
	KUNIT_EXPECT_EQ(test, after.modified_id, before.modified_id + 1);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_privs_requires_cached_right(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 1,
	};
	struct kacs_priv_entry entry = {
		.luid = PKM_KUNIT_PRIV_LUID_DISABLE,
		.attributes = 0,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token,
						      target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    &entry),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_privs_duplicate_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 2,
	};
	struct kacs_priv_entry entries[2] = {
		{ .luid = PKM_KUNIT_PRIV_LUID_DISABLE, .attributes = 0 },
		{ .luid = PKM_KUNIT_PRIV_LUID_DISABLE,
		  .attributes = PKM_KUNIT_SE_PRIVILEGE_ENABLED },
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    entries),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_privs_enable_absent_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 1,
	};
	struct kacs_priv_entry entry = {
		.luid = PKM_KUNIT_PRIV_LUID_ABSENT_DISABLE,
		.attributes = PKM_KUNIT_SE_PRIVILEGE_ENABLED,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_privs_invalid_reset_encoding_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 1,
	};
	struct kacs_priv_entry entry = {
		.luid = 1,
		.attributes = PKM_KUNIT_PRIV_RESET_ALL_DEFAULTS,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_adjust_privs_invalid_attributes_fails_closed(
	struct kunit *test)
{
	struct kacs_adjust_privs_args adjust = {
		.count = 1,
	};
	struct kacs_priv_entry entry = {
		.luid = PKM_KUNIT_PRIV_LUID_DISABLE,
		.attributes = PKM_KUNIT_SE_PRIVILEGE_ENABLED |
			      PKM_KUNIT_SE_PRIVILEGE_REMOVED,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_ADJUST_PRIVS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_privs((int)fd, &adjust,
							    &entry),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_updates_query_and_source_unchanged(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.privs_to_delete = 1ULL << PKM_KUNIT_PRIV_LUID_REMOVE,
		.num_deny_indices = 1,
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct kacs_query_args priv_query = {
		.token_class = KACS_TOKEN_CLASS_PRIVILEGES,
		.buf_len = 32,
	};
	struct kacs_query_args group_query = {
		.token_class = KACS_TOKEN_CLASS_GROUPS,
		.buf_len = 256,
	};
	struct kacs_query_args restricted_query = {
		.token_class = KACS_TOKEN_CLASS_RESTRICTED_SIDS,
		.buf_len = 128,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 payload[64] = { 0 };
	u8 priv_buf[32] = { 0 };
	u8 group_buf[256] = { 0 };
	u8 restricted_buf[128] = { 0 };
	const void *subject_token;
	const void *target_token;
	size_t first_group_attr_offset;
	size_t restricted_attr_offset;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(
		payload, (u32[]){ 0U }, 1, before.groups_ptr, 1);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &restrict_args,
							payload),
			(long)0);
	KUNIT_ASSERT_GE(test, restrict_args.result_fd, 0);

	priv_query.buf_ptr = (u64)(unsigned long)priv_buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query(restrict_args.result_fd,
						      &priv_query, priv_buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(priv_buf, 0),
			PKM_KUNIT_ADJUSTABLE_PRIV_AFTER_REMOVE);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(priv_buf, 8),
			1ULL << PKM_KUNIT_PRIV_LUID_DISABLE);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(priv_buf, 16),
			1ULL << PKM_KUNIT_PRIV_LUID_DISABLE);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(priv_buf, 24), 0ULL);

	group_query.buf_ptr = (u64)(unsigned long)group_buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query(restrict_args.result_fd,
						      &group_query, group_buf),
			(long)0);
	first_group_attr_offset = 4U + 4U + before.groups_ptr[0].sid_len;
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_read_u32(group_buf, first_group_attr_offset) &
				PKM_KUNIT_SE_GROUP_USE_FOR_DENY_ONLY,
			PKM_KUNIT_SE_GROUP_USE_FOR_DENY_ONLY);

	restricted_query.buf_ptr = (u64)(unsigned long)restricted_buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query(restrict_args.result_fd,
						      &restricted_query,
						      restricted_buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf, 0), 1U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf, 4),
			(u32)before.groups_ptr[0].sid_len);
	pkm_kunit_expect_bytes_eq(test, restricted_buf + 8,
				  before.groups_ptr[0].sid_len,
				  before.groups_ptr[0].sid_ptr,
				  before.groups_ptr[0].sid_len);
	restricted_attr_offset = 8U + before.groups_ptr[0].sid_len;
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf,
						 restricted_attr_offset),
			PKM_KUNIT_SE_GROUP_ENABLED);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)restrict_args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_result_fd_preserves_source_access_mask(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct kacs_query_args query = {
		.token_class = KACS_TOKEN_CLASS_STATISTICS,
		.buf_len = 40,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_token_fd_view result_view = { };
	u8 payload[64] = { 0 };
	u8 query_buf[40] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token, KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(
		payload, NULL, 0, before.groups_ptr, 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token,
							&restrict_args,
							payload),
			(long)0);
	KUNIT_ASSERT_GE(test, restrict_args.result_fd, 0);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(restrict_args.result_fd,
							 &result_view),
			0);
	KUNIT_EXPECT_EQ(test, result_view.access_mask, KACS_TOKEN_DUPLICATE);

	query.buf_ptr = (u64)(unsigned long)query_buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query(restrict_args.result_fd,
						      &query, query_buf),
			(long)-EACCES);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)restrict_args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_deny_only_survives_group_reset(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.num_deny_indices = 1,
		.result_fd = -1,
	};
	struct kacs_adjust_groups_args enable_deny_only = {
		.count = 1,
	};
	struct kacs_group_entry enable_deny_only_entry = {
		.index = 0,
		.enable = 1,
	};
	struct kacs_adjust_groups_args mutate = {
		.count = 1,
	};
	struct kacs_group_entry mutate_entry = {
		.index = 1,
		.enable = 1,
	};
	struct kacs_adjust_groups_args reset = {
		.count = 1,
	};
	struct kacs_group_entry reset_entry = {
		.index = 0xFFFFFFFFU,
		.enable = 0,
	};
	struct kacs_query_args group_query = {
		.token_class = KACS_TOKEN_CLASS_GROUPS,
		.buf_len = 256,
	};
	u32 deny_indices[1] = { 0U };
	u8 payload[16] = { 0 };
	u8 group_buf[256] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE |
			KACS_TOKEN_ADJUST_GROUPS);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(
		payload, deny_indices, ARRAY_SIZE(deny_indices), NULL, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token,
							&restrict_args, payload),
			(long)0);
	KUNIT_ASSERT_GE(test, restrict_args.result_fd, 0);

	group_query.buf_ptr = (u64)(unsigned long)group_buf;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query(restrict_args.result_fd,
						      &group_query, group_buf),
			(long)0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_groups_query_attr(group_buf, 0) &
				PKM_KUNIT_SE_GROUP_USE_FOR_DENY_ONLY,
			PKM_KUNIT_SE_GROUP_USE_FOR_DENY_ONLY);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups(
				restrict_args.result_fd, &enable_deny_only,
				&enable_deny_only_entry),
			(long)-EINVAL);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups(
				restrict_args.result_fd, &mutate, &mutate_entry),
			(long)0);

	memset(group_buf, 0, sizeof(group_buf));
	group_query.buf_len = sizeof(group_buf);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query(restrict_args.result_fd,
						      &group_query, group_buf),
			(long)0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_groups_query_attr(group_buf, 0) &
				PKM_KUNIT_SE_GROUP_USE_FOR_DENY_ONLY,
			PKM_KUNIT_SE_GROUP_USE_FOR_DENY_ONLY);
	KUNIT_EXPECT_EQ(test, pkm_kunit_groups_query_attr(group_buf, 1),
			PKM_KUNIT_SE_GROUP_ENABLED);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_adjust_groups(
				restrict_args.result_fd, &reset, &reset_entry),
			(long)0);

	memset(group_buf, 0, sizeof(group_buf));
	group_query.buf_len = sizeof(group_buf);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query(restrict_args.result_fd,
						      &group_query, group_buf),
			(long)0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_groups_query_attr(group_buf, 0) &
				PKM_KUNIT_SE_GROUP_USE_FOR_DENY_ONLY,
			PKM_KUNIT_SE_GROUP_USE_FOR_DENY_ONLY);
	KUNIT_EXPECT_EQ(test, pkm_kunit_groups_query_attr(group_buf, 1),
			PKM_KUNIT_ADJUSTABLE_GROUP1_DEFAULT);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)restrict_args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_intersects_existing_restricted_sids(
	struct kunit *test)
{
	struct kacs_restrict_args first = {
		.num_restrict_sids = 2,
		.result_fd = -1,
	};
	struct kacs_restrict_args second = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct kacs_query_args restricted_query = {
		.token_class = KACS_TOKEN_CLASS_RESTRICTED_SIDS,
		.buf_len = 128,
	};
	struct pkm_kacs_boot_snapshot before = { };
	u8 first_payload[64] = { 0 };
	u8 second_payload[64] = { 0 };
	u8 restricted_buf[128] = { 0 };
	const void *subject_token;
	const void *target_token;
	const struct pkm_kacs_boot_group_view *everyone_group;
	size_t restricted_attr_offset;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	everyone_group = &before.groups_ptr[1];

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	first.data_len = pkm_kunit_build_restrict_payload(first_payload, NULL, 0,
							  before.groups_ptr, 2);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &first,
							first_payload),
			(long)0);
	KUNIT_ASSERT_GE(test, first.result_fd, 0);

	second.data_len = pkm_kunit_build_restrict_payload(
		second_payload, NULL, 0, everyone_group, 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict(first.result_fd,
							subject_token,
							subject_token, &second,
							second_payload),
			(long)0);
	KUNIT_ASSERT_GE(test, second.result_fd, 0);

	restricted_query.buf_ptr = (u64)(unsigned long)restricted_buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query(second.result_fd,
						      &restricted_query,
						      restricted_buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf, 0), 1U);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf, 4),
			(u32)everyone_group->sid_len);
	pkm_kunit_expect_bytes_eq(test, restricted_buf + 8, everyone_group->sid_len,
				  everyone_group->sid_ptr,
				  everyone_group->sid_len);
	restricted_attr_offset = 8U + everyone_group->sid_len;
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf,
						 restricted_attr_offset),
			PKM_KUNIT_SE_GROUP_ENABLED);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)second.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)first.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_empty_intersection_fails_closed(
	struct kunit *test)
{
	struct kacs_restrict_args first = {
		.num_restrict_sids = 2,
		.result_fd = -1,
	};
	struct kacs_restrict_args second = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct kacs_query_args restricted_query = {
		.token_class = KACS_TOKEN_CLASS_RESTRICTED_SIDS,
		.buf_len = 128,
	};
	struct pkm_kacs_boot_snapshot before = { };
	u8 first_payload[64] = { 0 };
	u8 second_payload[64] = { 0 };
	u8 restricted_buf[128] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	KUNIT_ASSERT_GE(test, before.group_count, 3U);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	first.data_len = pkm_kunit_build_restrict_payload(first_payload, NULL, 0,
							  before.groups_ptr, 2);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &first,
							first_payload),
			(long)0);
	KUNIT_ASSERT_GE(test, first.result_fd, 0);

	second.data_len = pkm_kunit_build_restrict_payload(
		second_payload, NULL, 0, &before.groups_ptr[2], 1);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict(first.result_fd,
							subject_token,
							subject_token, &second,
							second_payload),
			(long)-EINVAL);

	restricted_query.buf_ptr = (u64)(unsigned long)restricted_buf;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_query(first.result_fd,
						      &restricted_query,
						      restricted_buf),
			(long)0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(restricted_buf, 0), 2U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)first.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_write_restricted_bypasses_read_pass(
	struct kunit *test)
{
	struct kacs_restrict_args restricted = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct kacs_restrict_args write_restricted = {
		.num_restrict_sids = 1,
		.flags = KACS_TOKEN_RESTRICT_WRITE_RESTRICTED,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	u8 payload[64] = { 0 };
	u32 granted = 0;
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restricted.data_len = pkm_kunit_build_restrict_payload(payload, NULL, 0,
							       before.groups_ptr, 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token,
							&restricted, payload),
			(long)0);
	KUNIT_ASSERT_GE(test, restricted.result_fd, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_run_read_control_with_token_fd(
				restricted.result_fd, pkm_kunit_everyone_read_sd,
				sizeof(pkm_kunit_everyone_read_sd), &granted),
			(long)-EACCES);

	write_restricted.data_len = restricted.data_len;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token,
							&write_restricted,
							payload),
			(long)0);
	KUNIT_ASSERT_GE(test, write_restricted.result_fd, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_run_read_control_with_token_fd(
				write_restricted.result_fd,
				pkm_kunit_everyone_read_sd,
				sizeof(pkm_kunit_everyone_read_sd), &granted),
			(long)KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, granted, KACS_ACCESS_READ_CONTROL);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)write_restricted.result_fd),
			0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)restricted.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_deny_only_access_check_polarity(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.num_deny_indices = 1,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kunit_read_ace_spec allow_admin[] = {
		{
			.ace_type = PKM_KUNIT_ACCESS_ALLOWED_ACE_TYPE,
			.sid = pkm_kunit_administrators_sid,
			.sid_len = sizeof(pkm_kunit_administrators_sid),
		},
	};
	struct pkm_kunit_read_ace_spec deny_admin_allow_system[] = {
		{
			.ace_type = PKM_KUNIT_ACCESS_DENIED_ACE_TYPE,
			.sid = pkm_kunit_administrators_sid,
			.sid_len = sizeof(pkm_kunit_administrators_sid),
		},
		{
			.ace_type = PKM_KUNIT_ACCESS_ALLOWED_ACE_TYPE,
			.sid = pkm_kunit_system_sid,
			.sid_len = sizeof(pkm_kunit_system_sid),
		},
	};
	u32 deny_indices[1] = { 0U };
	u8 payload[16] = { 0 };
	u8 allow_admin_sd[96] = { 0 };
	u8 deny_admin_allow_system_sd[128] = { 0 };
	u32 granted = U32_MAX;
	size_t allow_admin_sd_len;
	size_t deny_admin_allow_system_sd_len;
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(
		payload, deny_indices, ARRAY_SIZE(deny_indices), NULL, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token,
							&restrict_args, payload),
			(long)0);
	KUNIT_ASSERT_GE(test, restrict_args.result_fd, 0);

	allow_admin_sd_len = pkm_kunit_build_read_control_sd(
		allow_admin_sd, sizeof(allow_admin_sd),
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid),
		allow_admin, ARRAY_SIZE(allow_admin));
	KUNIT_ASSERT_GT(test, (long)allow_admin_sd_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_run_read_control_with_token_fd(
				restrict_args.result_fd, allow_admin_sd,
				allow_admin_sd_len, &granted),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	granted = U32_MAX;
	deny_admin_allow_system_sd_len = pkm_kunit_build_read_control_sd(
		deny_admin_allow_system_sd, sizeof(deny_admin_allow_system_sd),
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid),
		deny_admin_allow_system, ARRAY_SIZE(deny_admin_allow_system));
	KUNIT_ASSERT_GT(test, (long)deny_admin_allow_system_sd_len, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_run_read_control_with_token_fd(
				restrict_args.result_fd,
				deny_admin_allow_system_sd,
				deny_admin_allow_system_sd_len, &granted),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)restrict_args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_access_requires_restricted_pass(
	struct kunit *test)
{
	struct kacs_restrict_args admin_restrict = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct kacs_restrict_args everyone_restrict = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kunit_read_ace_spec allow_admin[] = {
		{
			.ace_type = PKM_KUNIT_ACCESS_ALLOWED_ACE_TYPE,
			.sid = pkm_kunit_administrators_sid,
			.sid_len = sizeof(pkm_kunit_administrators_sid),
		},
	};
	u8 admin_payload[64] = { 0 };
	u8 everyone_payload[64] = { 0 };
	u8 allow_admin_sd[96] = { 0 };
	u32 granted = 0;
	size_t allow_admin_sd_len;
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	KUNIT_ASSERT_GE(test, before.group_count, 2U);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	admin_restrict.data_len = pkm_kunit_build_restrict_payload(
		admin_payload, NULL, 0, before.groups_ptr, 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict(
				(int)fd, subject_token, subject_token,
				&admin_restrict, admin_payload),
			(long)0);
	KUNIT_ASSERT_GE(test, admin_restrict.result_fd, 0);

	everyone_restrict.data_len = pkm_kunit_build_restrict_payload(
		everyone_payload, NULL, 0, &before.groups_ptr[1], 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict(
				(int)fd, subject_token, subject_token,
				&everyone_restrict, everyone_payload),
			(long)0);
	KUNIT_ASSERT_GE(test, everyone_restrict.result_fd, 0);

	allow_admin_sd_len = pkm_kunit_build_read_control_sd(
		allow_admin_sd, sizeof(allow_admin_sd),
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid),
		allow_admin, ARRAY_SIZE(allow_admin));
	KUNIT_ASSERT_GT(test, (long)allow_admin_sd_len, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_run_read_control_with_token_fd(
				admin_restrict.result_fd, allow_admin_sd,
				allow_admin_sd_len, &granted),
			(long)KACS_ACCESS_READ_CONTROL);
	KUNIT_EXPECT_EQ(test, granted, KACS_ACCESS_READ_CONTROL);

	granted = U32_MAX;
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_run_read_control_with_token_fd(
				everyone_restrict.result_fd, allow_admin_sd,
				allow_admin_sd_len, &granted),
			(long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)everyone_restrict.result_fd),
			0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)admin_restrict.result_fd),
			0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_write_restricted_sets_user_deny_only(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.num_restrict_sids = 1,
		.flags = KACS_TOKEN_RESTRICT_WRITE_RESTRICTED,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot restricted = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kacs_token_fd_view view = { };
	u8 payload[64] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(
		payload, NULL, 0, before.groups_ptr, 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token,
							&restrict_args, payload),
			(long)0);
	KUNIT_ASSERT_GE(test, restrict_args.result_fd, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(restrict_args.result_fd,
							 &view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token,
							 &restricted));
	KUNIT_EXPECT_EQ(test, restricted.restricted, 1U);
	KUNIT_EXPECT_EQ(test, restricted.write_restricted, 1U);
	KUNIT_EXPECT_EQ(test, restricted.user_deny_only, 1U);
	KUNIT_EXPECT_EQ(test, restricted.modified_id, restricted.token_id);
	KUNIT_EXPECT_TRUE(test, restricted.token_id != before.token_id);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)restrict_args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_write_restricted_sticky_from_source(
	struct kunit *test)
{
	struct kacs_restrict_args first = {
		.num_restrict_sids = 2,
		.flags = KACS_TOKEN_RESTRICT_WRITE_RESTRICTED,
		.result_fd = -1,
	};
	struct kacs_restrict_args second = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot first_snapshot = { };
	struct pkm_kacs_boot_snapshot second_snapshot = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kacs_token_fd_view first_view = { };
	struct pkm_kacs_token_fd_view second_view = { };
	u8 first_payload[96] = { 0 };
	u8 second_payload[64] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	KUNIT_ASSERT_GE(test, before.group_count, 2U);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	first.data_len = pkm_kunit_build_restrict_payload(
		first_payload, NULL, 0, before.groups_ptr, 2);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &first,
							first_payload),
			(long)0);
	KUNIT_ASSERT_GE(test, first.result_fd, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(first.result_fd,
							 &first_view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, first_view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(first_view.token,
							 &first_snapshot));
	KUNIT_EXPECT_EQ(test, first_snapshot.restricted, 1U);
	KUNIT_EXPECT_EQ(test, first_snapshot.write_restricted, 1U);
	KUNIT_EXPECT_EQ(test, first_snapshot.user_deny_only, 1U);
	KUNIT_EXPECT_EQ(test, first_snapshot.restricted_sid_count, 2U);

	second.data_len = pkm_kunit_build_restrict_payload(
		second_payload, NULL, 0, &before.groups_ptr[1], 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict(first.result_fd,
							subject_token,
							subject_token, &second,
							second_payload),
			(long)0);
	KUNIT_ASSERT_GE(test, second.result_fd, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(second.result_fd,
							 &second_view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, second_view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(second_view.token,
							 &second_snapshot));
	KUNIT_EXPECT_EQ(test, second_snapshot.restricted, 1U);
	KUNIT_EXPECT_EQ(test, second_snapshot.write_restricted, 1U);
	KUNIT_EXPECT_EQ(test, second_snapshot.user_deny_only, 1U);
	KUNIT_EXPECT_EQ(test, second_snapshot.restricted_sid_count, 1U);
	KUNIT_EXPECT_EQ(test, second_snapshot.modified_id,
			second_snapshot.token_id);
	KUNIT_EXPECT_TRUE(test,
			  second_snapshot.token_id != first_snapshot.token_id);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)second.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)first.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_out_of_range_deny_index_fails_closed(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.num_deny_indices = 1,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 payload[16] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;
	u32 deny_index;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	deny_index = before.group_count;
	restrict_args.data_len = pkm_kunit_build_restrict_payload(
		payload, &deny_index, 1, NULL, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token,
							&restrict_args, payload),
			(long)-EINVAL);
	KUNIT_EXPECT_EQ(test, restrict_args.result_fd, -1);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_new_identity_and_copied_metadata(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.privs_to_delete = 1ULL << PKM_KUNIT_PRIV_LUID_REMOVE,
		.num_deny_indices = 1,
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot restricted = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kacs_token_fd_view view = { };
	u8 payload[64] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_token_mark_privileges_used(
				  target_token,
				  1ULL << PKM_KUNIT_PRIV_LUID_DISABLE));
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(
		payload, (u32[]){ 0U }, 1, before.groups_ptr, 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token,
							&restrict_args, payload),
			(long)0);
	KUNIT_ASSERT_GE(test, restrict_args.result_fd, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(restrict_args.result_fd,
							 &view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token,
							 &restricted));

	KUNIT_EXPECT_TRUE(test, restricted.token_id != before.token_id);
	KUNIT_EXPECT_EQ(test, restricted.modified_id, restricted.token_id);
	KUNIT_EXPECT_PTR_EQ(test, restricted.session_ptr, before.session_ptr);
	KUNIT_EXPECT_EQ(test, restricted.session_id, before.session_id);
	KUNIT_EXPECT_EQ(test, restricted.auth_id, before.auth_id);
	KUNIT_EXPECT_EQ(test, restricted.created_at, before.created_at);
	KUNIT_EXPECT_EQ(test, restricted.logon_type, before.logon_type);
	pkm_kunit_expect_bytes_eq(test, restricted.auth_pkg_ptr,
				  restricted.auth_pkg_len, before.auth_pkg_ptr,
				  before.auth_pkg_len);
	pkm_kunit_expect_bytes_eq(test, restricted.user_sid_ptr,
				  restricted.user_sid_len, before.user_sid_ptr,
				  before.user_sid_len);
	pkm_kunit_expect_bytes_eq(test, restricted.logon_sid_ptr,
				  restricted.logon_sid_len, before.logon_sid_ptr,
				  before.logon_sid_len);
	KUNIT_EXPECT_EQ(test, restricted.integrity_level,
			before.integrity_level);
	KUNIT_EXPECT_EQ(test, restricted.mandatory_policy,
			before.mandatory_policy);
	KUNIT_EXPECT_EQ(test, restricted.token_type, before.token_type);
	KUNIT_EXPECT_EQ(test, restricted.impersonation_level,
			before.impersonation_level);
	KUNIT_EXPECT_EQ(test, restricted.interactive_session_id,
			before.interactive_session_id);
	KUNIT_EXPECT_EQ(test, restricted.projected_uid, before.projected_uid);
	KUNIT_EXPECT_EQ(test, restricted.projected_gid, before.projected_gid);
	KUNIT_EXPECT_EQ(test, restricted.audit_policy, before.audit_policy);
	KUNIT_EXPECT_EQ(test, restricted.owner_sid_index,
			before.owner_sid_index);
	KUNIT_EXPECT_EQ(test, restricted.primary_group_index,
			before.primary_group_index);
	pkm_kunit_expect_bytes_eq(test, restricted.default_dacl_ptr,
				  restricted.default_dacl_len,
				  before.default_dacl_ptr,
				  before.default_dacl_len);
	KUNIT_EXPECT_EQ(test, restricted.privileges_present,
			before.privileges_present &
				~(1ULL << PKM_KUNIT_PRIV_LUID_REMOVE));
	KUNIT_EXPECT_EQ(test, restricted.privileges_enabled,
			before.privileges_enabled &
				~(1ULL << PKM_KUNIT_PRIV_LUID_REMOVE));
	KUNIT_EXPECT_EQ(test, restricted.privileges_enabled_by_default,
			before.privileges_enabled_by_default &
				~(1ULL << PKM_KUNIT_PRIV_LUID_REMOVE));
	KUNIT_EXPECT_EQ(test, restricted.privileges_used, 0ULL);
	KUNIT_EXPECT_EQ(test, restricted.restricted, 1U);
	KUNIT_EXPECT_EQ(test, restricted.write_restricted, 0U);
	KUNIT_EXPECT_EQ(test, restricted.user_deny_only, 0U);
	KUNIT_EXPECT_EQ(test, restricted.elevation_type, KACS_ELEVATION_DEFAULT);
	KUNIT_EXPECT_EQ(test, restricted.confinement_exempt,
			before.confinement_exempt);
	KUNIT_EXPECT_EQ(test, restricted.isolation_boundary,
			before.isolation_boundary);

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)restrict_args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_group_sids_fixed_attributes_modified(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.num_deny_indices = 2,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot restricted = { };
	struct pkm_kacs_boot_snapshot after = { };
	struct pkm_kacs_token_fd_view view = { };
	u32 deny_indices[2] = { 0U, 3U };
	u8 payload[16] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;
	u32 i;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_groups_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));
	KUNIT_ASSERT_GT(test, before.group_count, 3U);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(
		payload, deny_indices, ARRAY_SIZE(deny_indices), NULL, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token,
							&restrict_args, payload),
			(long)0);
	KUNIT_ASSERT_GE(test, restrict_args.result_fd, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(restrict_args.result_fd,
							 &view),
			0);
	KUNIT_ASSERT_NOT_NULL(test, view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(view.token,
							 &restricted));
	KUNIT_ASSERT_EQ(test, restricted.group_count, before.group_count);
	for (i = 0; i < before.group_count; i++) {
		u32 expected = before.groups_ptr[i].attributes;

		if (i == deny_indices[0] || i == deny_indices[1])
			expected |= PKM_KUNIT_SE_GROUP_USE_FOR_DENY_ONLY;
		pkm_kunit_expect_bytes_eq(test, restricted.groups_ptr[i].sid_ptr,
					  restricted.groups_ptr[i].sid_len,
					  before.groups_ptr[i].sid_ptr,
					  before.groups_ptr[i].sid_len);
		KUNIT_EXPECT_EQ(test, restricted.groups_ptr[i].attributes,
				expected);
	}

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)restrict_args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_copies_extended_field_matrix(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'F', 'l', 't', 'M', 'a', 't', 'r', 'x',
	};
	static const struct pkm_kunit_sid_attr_spec groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED |
				      PKM_KUNIT_SE_GROUP_OWNER,
		},
		{
			.sid = pkm_kunit_authenticated_users_sid,
			.sid_len = sizeof(pkm_kunit_authenticated_users_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED_BY_DEFAULT |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	static const struct pkm_kunit_sid_attr_spec restricted_sids[] = {
		{
			.sid = pkm_kunit_authenticated_users_sid,
			.sid_len = sizeof(pkm_kunit_authenticated_users_sid),
			.attributes = PKM_KUNIT_SE_GROUP_MANDATORY |
				      PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	static const struct pkm_kunit_sid_attr_spec device_groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	static const struct pkm_kunit_sid_attr_spec restricted_device_groups[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = 0U,
		},
	};
	static const struct pkm_kunit_sid_attr_spec confinement_caps[] = {
		{
			.sid = pkm_kunit_all_restricted_application_packages_sid,
			.sid_len =
				sizeof(pkm_kunit_all_restricted_application_packages_sid),
			.attributes = 0U,
		},
	};
	static const u32 supplementary_gids[] = {
		8001U, 8002U,
	};
	static const u32 copied_query_classes[] = {
		KACS_TOKEN_CLASS_USER,
		KACS_TOKEN_CLASS_TYPE,
		KACS_TOKEN_CLASS_INTEGRITY_LEVEL,
		KACS_TOKEN_CLASS_OWNER,
		KACS_TOKEN_CLASS_PRIMARY_GROUP,
		KACS_TOKEN_CLASS_SESSION_ID,
		KACS_TOKEN_CLASS_RESTRICTED_SIDS,
		KACS_TOKEN_CLASS_SOURCE,
		KACS_TOKEN_CLASS_ORIGIN,
		KACS_TOKEN_CLASS_ELEVATION_TYPE,
		KACS_TOKEN_CLASS_DEVICE_GROUPS,
		KACS_TOKEN_CLASS_APPCONTAINER_SID,
		KACS_TOKEN_CLASS_CAPABILITIES,
		KACS_TOKEN_CLASS_MANDATORY_POLICY,
		KACS_TOKEN_CLASS_LOGON_TYPE,
		KACS_TOKEN_CLASS_LOGON_SID,
		KACS_TOKEN_CLASS_DEFAULT_DACL,
		KACS_TOKEN_CLASS_IMPERSONATION_LEVEL,
		KACS_TOKEN_CLASS_USER_CLAIMS,
		KACS_TOKEN_CLASS_DEVICE_CLAIMS,
		KACS_TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.mandatory_policy = 0x00000003U,
		.privileges_present = PKM_KUNIT_SE_DEBUG_PRIVILEGE,
		.privileges_enabled = PKM_KUNIT_SE_DEBUG_PRIVILEGE,
		.projected_uid = 8765U,
		.projected_gid = 5678U,
		.audit_policy = PKM_KUNIT_AUDIT_POLICY_OBJECT_ACCESS_SUCCESS,
		.expiration = 0x8877665544332211ULL,
		.owner_sid_index = 1U,
		.primary_group_index = 2U,
		.source_name = source_name,
		.source_id = 0x1020304050607080ULL,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
		.groups = groups,
		.group_count = ARRAY_SIZE(groups),
		.default_dacl = pkm_kunit_replacement_default_dacl,
		.default_dacl_len = sizeof(pkm_kunit_replacement_default_dacl),
		.device_groups = device_groups,
		.device_group_count = ARRAY_SIZE(device_groups),
		.restricted_sids = restricted_sids,
		.restricted_sid_count = ARRAY_SIZE(restricted_sids),
		.confinement_sid = pkm_kunit_sample_confinement_sid,
		.confinement_sid_len = sizeof(pkm_kunit_sample_confinement_sid),
		.confinement_caps = confinement_caps,
		.confinement_cap_count = ARRAY_SIZE(confinement_caps),
		.confinement_exempt = 1U,
		.isolation_boundary = 1U,
		.projected_supplementary_gids = supplementary_gids,
		.projected_supplementary_gid_count =
			ARRAY_SIZE(supplementary_gids),
		.restricted_device_groups = restricted_device_groups,
		.restricted_device_group_count =
			ARRAY_SIZE(restricted_device_groups),
		.origin = 0x0102030405060708ULL,
		.interactive_session_id = 34U,
	};
	struct kacs_restrict_args restrict_args = {
		.num_deny_indices = 1,
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct kacs_query_args source_stats = {
		.token_class = KACS_TOKEN_CLASS_STATISTICS,
		.buf_len = 40U,
	};
	struct kacs_query_args restricted_stats = {
		.token_class = KACS_TOKEN_CLASS_STATISTICS,
		.buf_len = 40U,
	};
	struct pkm_kacs_token_fd_view source_view = { };
	struct pkm_kacs_token_fd_view restricted_view = { };
	struct pkm_kacs_boot_snapshot source_snapshot = { };
	struct pkm_kacs_boot_snapshot restricted_snapshot = { };
	struct pkm_kacs_boot_snapshot source_after = { };
	u8 session_spec[96] = { };
	u8 user_claim_entry[96] = { };
	u8 device_claim_entry[96] = { };
	u8 user_claims[128] = { };
	u8 device_claims[128] = { };
	u8 source_stats_buf[40] = { };
	u8 restricted_stats_buf[40] = { };
	u8 payload[64] = { 0 };
	u8 *token_spec;
	const void *subject_token;
	size_t user_claims_len = 0;
	size_t device_claims_len = 0;
	size_t entry_len;
	size_t token_spec_len;
	u64 session_id = 0;
	long source_fd;
	u32 i;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);
	token_spec = kunit_kzalloc(test, 1536U, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, token_spec);

	entry_len = pkm_kunit_build_claim_entry_scalar(
		user_claim_entry, sizeof(user_claim_entry), "FiltUser",
		PKM_KUNIT_CLAIM_TYPE_UINT64, 0U, 456U);
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(
				user_claims, sizeof(user_claims),
				&user_claims_len, user_claim_entry, entry_len),
			0);
	entry_len = pkm_kunit_build_claim_entry_string(
		device_claim_entry, sizeof(device_claim_entry), "FiltDevice",
		0U, "dev");
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kunit_append_claim_entry(
				device_claims, sizeof(device_claims),
				&device_claims_len, device_claim_entry,
				entry_len),
			0);
	spec_args.user_claims = user_claims;
	spec_args.user_claims_len = user_claims_len;
	spec_args.device_claims = device_claims;
	spec_args.device_claims_len = device_claims_len;

	entry_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)entry_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, entry_len,
				&session_id),
			0L);

	spec_args.session_id = session_id;
	token_spec_len = pkm_kunit_build_token_spec(token_spec, 1536U,
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	source_fd = pkm_kacs_kunit_create_token_for_subject(
		subject_token, token_spec, token_spec_len);
	KUNIT_ASSERT_GE(test, source_fd, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot((int)source_fd,
							 &source_view),
			0);
	KUNIT_EXPECT_EQ(test, source_view.access_mask, KACS_TOKEN_ALL_ACCESS);
	KUNIT_ASSERT_NOT_NULL(test, source_view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_token_mark_privileges_used(
				  source_view.token,
				  PKM_KUNIT_SE_DEBUG_PRIVILEGE));
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(source_view.token,
							 &source_snapshot));
	KUNIT_ASSERT_EQ(test, source_snapshot.restricted, 1U);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(
		payload, (u32[]){ 0U }, 1, &source_snapshot.groups_ptr[1], 1);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict(
				(int)source_fd, subject_token, subject_token,
				&restrict_args, payload),
			(long)0);
	KUNIT_ASSERT_GE(test, restrict_args.result_fd, 0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_snapshot(restrict_args.result_fd,
							 &restricted_view),
			0);
	KUNIT_EXPECT_EQ(test, restricted_view.access_mask,
			KACS_TOKEN_ALL_ACCESS);
	KUNIT_ASSERT_NOT_NULL(test, restricted_view.token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(
				  restricted_view.token, &restricted_snapshot));

	KUNIT_EXPECT_TRUE(test,
			  restricted_snapshot.token_id !=
				  source_snapshot.token_id);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.modified_id,
			restricted_snapshot.token_id);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.restricted, 1U);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.write_restricted, 0U);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.user_deny_only, 0U);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.confinement_exempt,
			source_snapshot.confinement_exempt);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.isolation_boundary,
			source_snapshot.isolation_boundary);
	KUNIT_EXPECT_EQ(test, source_snapshot.confinement_exempt, 1U);
	KUNIT_EXPECT_EQ(test, source_snapshot.isolation_boundary, 1U);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.projected_uid,
			source_snapshot.projected_uid);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.projected_gid,
			source_snapshot.projected_gid);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.audit_policy,
			source_snapshot.audit_policy);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.privileges_present,
			source_snapshot.privileges_present);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.privileges_enabled,
			source_snapshot.privileges_enabled);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.privileges_enabled_by_default,
			source_snapshot.privileges_enabled_by_default);
	KUNIT_EXPECT_EQ(test, restricted_snapshot.privileges_used, 0ULL);

	for (i = 0; i < ARRAY_SIZE(copied_query_classes); i++)
		pkm_kunit_expect_token_query_payload_eq(
			test, (int)source_fd, restrict_args.result_fd,
			copied_query_classes[i]);

	source_stats.buf_ptr = (u64)(unsigned long)source_stats_buf;
	restricted_stats.buf_ptr = (u64)(unsigned long)restricted_stats_buf;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query((int)source_fd,
						      &source_stats,
						      source_stats_buf),
			(long)0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_token_fd_query(restrict_args.result_fd,
						      &restricted_stats,
						      restricted_stats_buf),
			(long)0);
	KUNIT_EXPECT_NE(test, pkm_kunit_read_u64(source_stats_buf, 0),
			pkm_kunit_read_u64(restricted_stats_buf, 0));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(restricted_stats_buf, 16),
			pkm_kunit_read_u64(restricted_stats_buf, 0));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(source_stats_buf, 8),
			pkm_kunit_read_u64(restricted_stats_buf, 8));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(source_stats_buf, 24),
			pkm_kunit_read_u32(restricted_stats_buf, 24));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(source_stats_buf, 28),
			pkm_kunit_read_u32(restricted_stats_buf, 28));
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u64(source_stats_buf, 32),
			pkm_kunit_read_u64(restricted_stats_buf, 32));

	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(source_view.token,
							 &source_after));
	pkm_kunit_expect_boot_snapshot_eq(test, &source_snapshot, &source_after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)restrict_args.result_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)source_fd), 0);
	flush_delayed_fput();
}


static void pkm_kunit_token_restrict_requires_cached_duplicate(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 payload[64] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(payload, NULL, 0,
							       before.groups_ptr, 1);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &restrict_args,
							payload),
			(long)-EACCES);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_duplicate_deny_indices_fail_closed(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.num_deny_indices = 2,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 payload[16] = { 0 };
	u32 deny_indices[2] = { 0U, 0U };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(payload, deny_indices,
							      2, NULL, 0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &restrict_args,
							payload),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_reserved_flags_fail_closed(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.flags = 0x2U,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &restrict_args,
							NULL),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_token_restrict_malformed_payload_fails_closed(
	struct kunit *test)
{
	struct kacs_restrict_args restrict_args = {
		.num_restrict_sids = 1,
		.result_fd = -1,
	};
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };
	u8 payload[64] = { 0 };
	const void *subject_token;
	const void *target_token;
	long fd;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &before));

	fd = pkm_kacs_kunit_open_token_fd_for_subject(
		subject_token, target_token,
		KACS_TOKEN_QUERY | KACS_TOKEN_DUPLICATE);
	KUNIT_ASSERT_GE(test, fd, 0L);

	restrict_args.data_len = pkm_kunit_build_restrict_payload(payload, NULL, 0,
							       before.groups_ptr, 1);
	payload[restrict_args.data_len] = 0xaa;
	restrict_args.data_len += 1;
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_token_fd_restrict((int)fd, subject_token,
							subject_token, &restrict_args,
							payload),
			(long)-EINVAL);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(target_token, &after));
	pkm_kunit_expect_boot_snapshot_eq(test, &before, &after);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}


static void pkm_kunit_identification_impersonation_denies_access_check(
	struct kunit *test)
{
	struct kacs_query_args query = {
		.buf_len = sizeof(u32),
	};
	struct pkm_kacs_token_fd_view view = { };
	u8 query_buf[4] = { 0 };
	const void *client_token;
	const void *primary_token;
	long impersonation_fd;
	long query_fd = -1;
	u32 granted = 0;
	long ret;

	KUNIT_ASSERT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	ret = pkm_kunit_run_read_control_with_token_fd(
		-1, pkm_kunit_everyone_read_sd,
		sizeof(pkm_kunit_everyone_read_sd), &granted);
	KUNIT_ASSERT_GE(test, ret, 0L);
	KUNIT_ASSERT_NE(test, granted, 0U);

	client_token = kacs_rust_kunit_create_impersonation_variant_token(
		PKM_KUNIT_USER_KIND_LOCAL_SERVICE, KACS_TOKEN_TYPE_IMPERSONATION,
		KACS_IMLEVEL_IDENTIFICATION, PKM_KUNIT_IL_SYSTEM, 0, 0);
	KUNIT_ASSERT_NOT_NULL(test, client_token);

	impersonation_fd = pkm_kacs_kunit_open_token_fd_for_subject(
		primary_token, client_token, KACS_TOKEN_IMPERSONATE);
	KUNIT_ASSERT_GE(test, impersonation_fd, 0L);

	ret = pkm_kacs_kunit_token_fd_impersonate((int)impersonation_fd,
						 primary_token);
	KUNIT_EXPECT_EQ(test, ret, 0L);
	if (ret)
		goto out_close;

	query_fd = pkm_kacs_kunit_open_current_thread_token_for_subject(
		primary_token, KACS_TOKEN_QUERY);
	KUNIT_EXPECT_GE(test, query_fd, 0L);
	if (query_fd >= 0) {
		KUNIT_EXPECT_EQ(
			test,
			pkm_kacs_kunit_token_fd_snapshot((int)query_fd, &view),
			0);
		KUNIT_EXPECT_PTR_EQ(test, view.token,
				    pkm_kacs_current_effective_token_ptr());

		query.buf_ptr = (u64)(unsigned long)query_buf;
		query.token_class = KACS_TOKEN_CLASS_TYPE;
		query.buf_len = sizeof(query_buf);
		memset(query_buf, 0, sizeof(query_buf));
		ret = pkm_kacs_kunit_token_fd_query((int)query_fd, &query,
						    query_buf);
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (!ret)
			KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(query_buf, 0),
					(u32)KACS_TOKEN_TYPE_IMPERSONATION);

		query.token_class = KACS_TOKEN_CLASS_IMPERSONATION_LEVEL;
		query.buf_len = sizeof(query_buf);
		memset(query_buf, 0, sizeof(query_buf));
		ret = pkm_kacs_kunit_token_fd_query((int)query_fd, &query,
						    query_buf);
		KUNIT_EXPECT_EQ(test, ret, 0L);
		if (!ret)
			KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(query_buf, 0),
					(u32)KACS_IMLEVEL_IDENTIFICATION);
	}

	granted = 0;
	ret = pkm_kunit_run_read_control_with_token_fd(
		-1, pkm_kunit_everyone_read_sd,
		sizeof(pkm_kunit_everyone_read_sd), &granted);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	KUNIT_EXPECT_EQ(test, pkm_kacs_revert_impersonation(), 0);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(),
			    primary_token);

out_close:
	if (query_fd >= 0)
		KUNIT_EXPECT_EQ(test, close_fd((unsigned int)query_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)impersonation_fd), 0);
	kacs_rust_token_drop(client_token);
}


static void pkm_kunit_create_token_mandatory_policy_zero_disables_mic(
	struct kunit *test)
{
	static const u8 source_name[8] = {
		'M', 'i', 'c', 'O', 'f', 'f', 0, 0,
	};
	static const u8 high_label_write_sd[] = {
		1, 0, 20, 128, 20, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
		60, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
		2, 0, 28, 0, 1, 0, 0, 0,
		17, 0, 20, 0, 2, 0, 0, 0,
		1, 1, 0, 0, 0, 0, 0, 16, 0, 48, 0, 0,
		2, 0, 28, 0, 1, 0, 0, 0,
		0, 0, 20, 0, 0, 0, 4, 0,
		1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0,
	};
	struct pkm_kunit_token_spec_args spec_args = {
		.token_type = KACS_TOKEN_TYPE_PRIMARY,
		.impersonation_level = KACS_IMLEVEL_ANONYMOUS,
		.integrity_level = PKM_KUNIT_IL_MEDIUM,
		.source_name = source_name,
		.user_sid = pkm_kunit_local_service_sid,
		.user_sid_len = sizeof(pkm_kunit_local_service_sid),
	};
	u8 session_spec[64] = { };
	u8 token_spec[256] = { };
	u8 args[136];
	u8 granted_out[4] = { 0 };
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	const void *subject_token;
	u64 session_id = 0;
	size_t session_spec_len;
	size_t token_spec_len;
	long enforcing_fd;
	long disabled_fd;
	long ret;

	subject_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	session_spec_len = pkm_kunit_build_session_spec(
		session_spec, PKM_KUNIT_LOGON_TYPE_NETWORK, "Kerberos",
		pkm_kunit_local_service_sid, sizeof(pkm_kunit_local_service_sid));
	KUNIT_ASSERT_GT(test, (long)session_spec_len, 0L);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_create_session_for_subject(
				subject_token, session_spec, session_spec_len,
				&session_id),
			0L);
	spec_args.session_id = session_id;

	spec_args.mandatory_policy = 0x00000003U;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	enforcing_fd = pkm_kacs_kunit_create_token_for_subject(
		subject_token, token_spec, token_spec_len);
	KUNIT_ASSERT_GE(test, enforcing_fd, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)enforcing_fd,
						  KACS_TOKEN_CLASS_MANDATORY_POLICY),
			0x00000003U);

	spec_args.mandatory_policy = 0U;
	spec_args.source_id = 1U;
	token_spec_len = pkm_kunit_build_token_spec(token_spec,
						    sizeof(token_spec),
						    &spec_args);
	KUNIT_ASSERT_GT(test, (long)token_spec_len, 0L);
	disabled_fd = pkm_kacs_kunit_create_token_for_subject(
		subject_token, token_spec, token_spec_len);
	KUNIT_ASSERT_GE(test, disabled_fd, 0L);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_query_token_u32(test, (int)disabled_fd,
						  KACS_TOKEN_CLASS_MANDATORY_POLICY),
			0U);

	pkm_kunit_build_args_v136(args);
	pkm_kunit_write_u64(args, 8, 0x1000);
	pkm_kunit_write_u32(args, 16, sizeof(high_label_write_sd));
	pkm_kunit_write_u32(args, 20, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 24, KACS_ACCESS_READ_CONTROL);
	pkm_kunit_write_u32(args, 28, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u32(args, 36, KACS_ACCESS_WRITE_DAC);
	pkm_kunit_write_u64(args, 88, 0x3000);

	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)high_label_write_sd,
			      sizeof(high_label_write_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	pkm_kunit_write_u32(args, 4, (u32)enforcing_fd);
	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)-EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0), 0U);

	memset(granted_out, 0, sizeof(granted_out));
	pkm_kunit_write_u32(args, 4, (u32)disabled_fd);
	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, NULL);
	KUNIT_EXPECT_EQ(test, ret, (long)KACS_ACCESS_WRITE_DAC);
	KUNIT_EXPECT_EQ(test, pkm_kunit_read_u32(granted_out, 0),
			KACS_ACCESS_WRITE_DAC);

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)disabled_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)enforcing_fd), 0);
	flush_delayed_fput();
}


static void pkm_kunit_privilege_use_msgpack_schema(struct kunit *test)
{
	u8 args[136];
	u8 granted_out[4] = { 0 };
	u8 *buffer;
	struct pkm_kunit_mem mem = { };
	struct pkm_kacs_usercopy_ops ops = {
		.ctx = &mem,
		.read_bytes = pkm_kunit_mem_read,
		.write_bytes = pkm_kunit_mem_write,
	};
	struct pkm_kacs_ingress_summary summary = { };
	struct pkm_kmes_kunit_snapshot snapshot = { };
	struct pkm_kunit_kmes_event_view view = { };
	const void *subject_token;
	const void *target_token;
	size_t written = 0;
	long fd;
	long ret;

	buffer = kunit_kzalloc(test, PKM_KUNIT_KMES_CAPTURE_BYTES, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buffer);

	subject_token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, subject_token);

	target_token = kacs_rust_kunit_create_privilege_audit_token();
	KUNIT_ASSERT_NOT_NULL(test, target_token);

	fd = pkm_kacs_kunit_open_token_fd_for_subject(subject_token, target_token,
						      KACS_TOKEN_QUERY);
	KUNIT_ASSERT_GE(test, fd, 0L);

	pkm_kunit_reset_kmes();
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_set_process_override(
				4206, PKM_KUNIT_KMES_PRIV_PROCESS_NAME,
				PKM_KUNIT_KMES_PRIV_PROCESS_PATH),
			0);

	pkm_kunit_build_access_system_args(args, (s32)fd);
	pkm_kunit_add_region(&mem, 0x0100, args, sizeof(args));
	pkm_kunit_add_region(&mem, 0x1000, (u8 *)pkm_kunit_system_read_sd,
			      sizeof(pkm_kunit_system_read_sd));
	pkm_kunit_add_region(&mem, 0x3000, granted_out, sizeof(granted_out));

	ret = pkm_kacs_access_check_ingress_scalar_with_token_fd(
		&ops, 0x0100, NULL, &summary);
	KUNIT_EXPECT_EQ(test, ret, (long)PKM_KUNIT_SYSTEM_READ_CONTROL_GRANT);
	KUNIT_EXPECT_EQ(test, summary.privilege_use_event_count, 1U);
	KUNIT_ASSERT_EQ(test,
			pkm_kmes_kunit_copy_single_buffer(
				buffer, PKM_KUNIT_KMES_CAPTURE_BYTES, &written,
				&snapshot),
			0);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_parse_kmes_event(buffer, written, &view));
	KUNIT_EXPECT_TRUE(test,
			  pkm_kunit_expect_privilege_use_schema(
				  test, &view,
				  KACS_ACCESS_ACCESS_SYSTEM_SECURITY,
				  KACS_ACCESS_ACCESS_SYSTEM_SECURITY,
				  KACS_ACCESS_ACCESS_SYSTEM_SECURITY, true));

	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)fd), 0);
	kacs_rust_token_drop(target_token);
}

static struct kunit_case pkm_kunit_token_cases[] = {
	KUNIT_CASE(pkm_kunit_validate_sd_rejects_oversized_descriptor),
	KUNIT_CASE(pkm_kunit_token_eval_context_requires_subjective_cred),
	KUNIT_CASE(pkm_kunit_create_session_success),
	KUNIT_CASE(pkm_kunit_create_session_wire_format_edge_vectors),
	KUNIT_CASE(pkm_kunit_create_session_non_utf8_auth_package_fails_closed),
	KUNIT_CASE(pkm_kunit_create_session_requires_tcb),
	KUNIT_CASE(pkm_kunit_create_session_invalid_spec_fails_closed),
	KUNIT_CASE(pkm_kunit_create_token_success),
	KUNIT_CASE(pkm_kunit_create_token_rejects_uid0_non_system_projection),
	KUNIT_CASE(pkm_kunit_create_token_administrators_group_adds_no_privileges),
	KUNIT_CASE(pkm_kunit_create_token_default_enabled_derives_live_groups),
	KUNIT_CASE(pkm_kunit_create_token_preserves_resource_group_metadata),
	KUNIT_CASE(pkm_kunit_create_token_requires_privilege),
	KUNIT_CASE(pkm_kunit_create_token_invalid_session_fails_closed),
	KUNIT_CASE(pkm_kunit_create_token_write_restricted_requires_user_deny_only),
	KUNIT_CASE(pkm_kunit_create_token_malformed_claims_fail_closed),
	KUNIT_CASE(pkm_kunit_create_token_primary_non_anonymous_denies),
	KUNIT_CASE(pkm_kunit_create_token_impersonation_levels_query),
	KUNIT_CASE(pkm_kunit_create_token_invalid_mandatory_policy_fails_closed),
	KUNIT_CASE(pkm_kunit_create_token_invalid_audit_policy_fails_closed),
	KUNIT_CASE(pkm_kunit_create_token_invalid_default_dacl_fails_closed),
	KUNIT_CASE(pkm_kunit_create_token_enabled_privilege_subset_fails_closed),
	KUNIT_CASE(pkm_kunit_create_token_isolation_requires_confinement),
	KUNIT_CASE(pkm_kunit_create_token_invalid_owner_index_denies),
	KUNIT_CASE(pkm_kunit_create_token_owner_group_requires_owner_attr),
	KUNIT_CASE(pkm_kunit_create_token_primary_group_excludes_injected_logon),
	KUNIT_CASE(pkm_kunit_create_token_reserved_elevation_denies),
	KUNIT_CASE(pkm_kunit_create_token_wire_format_edge_vectors),
	KUNIT_CASE(pkm_kunit_create_token_malformed_sid_sections_fail_closed),
	KUNIT_CASE(pkm_kunit_create_token_caller_logon_sid_denies),
	KUNIT_CASE(pkm_kunit_create_token_max_groups_succeeds),
	KUNIT_CASE(pkm_kunit_create_token_over_max_groups_fails_closed),
	KUNIT_CASE(pkm_kunit_session_destroy_last_token_emits_kmes),
	KUNIT_CASE(pkm_kunit_logon_session_destroyed_msgpack_schema),
	KUNIT_CASE(pkm_kunit_destroy_empty_session_success_emits_kmes),
	KUNIT_CASE(pkm_kunit_destroy_empty_session_requires_tcb),
	KUNIT_CASE(pkm_kunit_destroy_empty_session_busy_with_live_token),
	KUNIT_CASE(pkm_kunit_destroy_empty_session_missing_returns_enoent),
	KUNIT_CASE(pkm_kunit_current_token_resolution),
	KUNIT_CASE(pkm_kunit_projected_fsids_follow_effective_token),
	KUNIT_CASE(pkm_kunit_projected_fsids_fallback_to_raw_without_token),
	KUNIT_CASE(pkm_kunit_token_projection_sets_linux_cred_fields),
	KUNIT_CASE(pkm_kunit_token_install_projection_preserves_impersonation_split),
	KUNIT_CASE(pkm_kunit_token_deep_copy_independent),
	KUNIT_CASE(pkm_kunit_token_lowered_impersonation_clone_gets_fresh_identity),
	KUNIT_CASE(pkm_kunit_token_created_at_preserved_by_derivations),
	KUNIT_CASE(pkm_kunit_token_expiration_not_enforced_by_access_check),
	KUNIT_CASE(pkm_kunit_session_metadata_not_enforced_by_access_check),
	KUNIT_CASE(pkm_kunit_create_token_same_sid_creator_keeps_self_limited),
	KUNIT_CASE(pkm_kunit_create_token_distinct_sid_default_sd_template),
	KUNIT_CASE(pkm_kunit_token_query_source_only_denied),
	KUNIT_CASE(pkm_kunit_token_fd_shared_file_preserves_cached_mask),
	KUNIT_CASE(pkm_kunit_token_fd_holds_ref_after_source_drop),
	KUNIT_CASE(pkm_kunit_identity_guid_accessors),
	KUNIT_CASE(pkm_kunit_shared_token_adjustment_mutations_visible),
	KUNIT_CASE(pkm_kunit_thread_token_inspection_returns_impersonation_token),
	KUNIT_CASE(pkm_kunit_thread_token_inspection_self_bypasses_process_sd),
	KUNIT_CASE(pkm_kunit_token_duplicate_primary_to_impersonation),
	KUNIT_CASE(pkm_kunit_token_duplicate_impersonation_level_escalation_fails_closed),
	KUNIT_CASE(pkm_kunit_token_duplicate_impersonation_lowers_level),
	KUNIT_CASE(pkm_kunit_token_duplicate_new_handle_checks_new_token_sd_against_subject),
	KUNIT_CASE(pkm_kunit_token_duplicate_primary_to_impersonation_all_levels),
	KUNIT_CASE(pkm_kunit_token_duplicate_impersonation_to_primary_forces_anonymous),
	KUNIT_CASE(pkm_kunit_token_duplicate_linked_elevation_resets_default),
	KUNIT_CASE(pkm_kunit_token_duplicate_copies_field_matrix),
	KUNIT_CASE(pkm_kunit_token_duplicate_mutations_are_independent),
	KUNIT_CASE(pkm_kunit_token_impersonate_caps_identification_without_privilege),
	KUNIT_CASE(pkm_kunit_token_impersonate_integrity_ceiling_caps_identification),
	KUNIT_CASE(pkm_kunit_token_impersonate_integrity_cap_preserves_label),
	KUNIT_CASE(pkm_kunit_token_impersonation_gate_composition_matrix),
	KUNIT_CASE(pkm_kunit_token_impersonation_gate_uses_primary_token),
	KUNIT_CASE(pkm_kunit_double_impersonation_replaces_effective_token),
	KUNIT_CASE(pkm_kunit_token_impersonate_same_user_restriction_mismatch_denies),
	KUNIT_CASE(pkm_kunit_token_impersonate_anonymous_bypasses_gates),
	KUNIT_CASE(pkm_kunit_anonymous_impersonation_access_check_matrix),
	KUNIT_CASE(pkm_kunit_token_install_requires_assign_primary_handle),
	KUNIT_CASE(pkm_kunit_token_install_requires_assign_primary_privilege),
	KUNIT_CASE(pkm_kunit_token_install_rejects_impersonation_token),
	KUNIT_CASE(pkm_kunit_token_install_same_user_preserves_process_sd),
	KUNIT_CASE(pkm_kunit_token_install_different_user_regenerates_process_sd),
	KUNIT_CASE(pkm_kunit_token_install_under_impersonation_revert_lands_on_new_primary),
	KUNIT_CASE(pkm_kunit_peer_socket_abstract_bind_stamps_once),
	KUNIT_CASE(pkm_kunit_peer_socket_abstract_default_sd_shape),
	KUNIT_CASE(pkm_kunit_peer_socket_set_level_updates_unconnected),
	KUNIT_CASE(pkm_kunit_peer_socket_set_level_invalid_fails_closed),
	KUNIT_CASE(pkm_kunit_peer_socket_set_level_connected_fails_closed),
	KUNIT_CASE(pkm_kunit_peer_socket_set_level_unsupported_type_fails_closed),
	KUNIT_CASE(pkm_kunit_peer_socket_capture_identification_on_seqpacket),
	KUNIT_CASE(pkm_kunit_peer_socket_capture_anonymous_shape),
	KUNIT_CASE(pkm_kunit_peer_socket_anonymous_capture_uses_boot_token),
	KUNIT_CASE(pkm_kunit_peer_socket_abstract_connect_denied_without_write_data),
	KUNIT_CASE(pkm_kunit_peer_socket_dgram_send_checks_abstract_sd),
	KUNIT_CASE(pkm_kunit_peer_socket_open_token_fixed_rights),
	KUNIT_CASE(pkm_kunit_peer_socket_impersonate_success_and_revert),
	KUNIT_CASE(pkm_kunit_peer_socket_seqpacket_impersonate_success_and_revert),
	KUNIT_CASE(pkm_kunit_peer_socket_impersonation_cascades_identity),
	KUNIT_CASE(pkm_kunit_peer_socket_capture_cannot_raise_effective_level),
	KUNIT_CASE(pkm_kunit_peer_socket_impersonate_caps_identification_without_privilege),
	KUNIT_CASE(pkm_kunit_peer_socket_restricted_mismatch_hard_denies),
	KUNIT_CASE(pkm_kunit_peer_socket_unsupported_or_uncaptured_fail_closed),
	KUNIT_CASE(pkm_kunit_token_impersonate_rejects_primary_token),
	KUNIT_CASE(pkm_kunit_token_query_user_probe_and_payload),
	KUNIT_CASE(pkm_kunit_token_query_groups_payload),
	KUNIT_CASE(pkm_kunit_token_query_privileges_payload),
	KUNIT_CASE(pkm_kunit_token_query_optional_empty_shapes),
	KUNIT_CASE(pkm_kunit_token_query_requires_cached_query),
	KUNIT_CASE(pkm_kunit_token_query_invalid_class),
	KUNIT_CASE(pkm_kunit_token_query_public_tail_payload),
	KUNIT_CASE(pkm_kunit_token_query_public_tail_short_buffers),
	KUNIT_CASE(pkm_kunit_token_query_short_and_fault_buffers),
	KUNIT_CASE(pkm_kunit_token_query_deferred_fields_payload),
	KUNIT_CASE(pkm_kunit_token_query_boolean_preserves_raw_u64),
	KUNIT_CASE(pkm_kunit_token_link_success_sets_roles_and_gets_partner),
	KUNIT_CASE(pkm_kunit_token_get_linked_unprivileged_returns_query_copy),
	KUNIT_CASE(pkm_kunit_token_get_linked_query_copy_duplicate_semantics),
	KUNIT_CASE(pkm_kunit_token_get_linked_query_copy_fresh_sd_and_default_dacl),
	KUNIT_CASE(pkm_kunit_token_own_sd_constructor_matrix),
	KUNIT_CASE(pkm_kunit_token_link_requires_tcb),
	KUNIT_CASE(pkm_kunit_token_link_requires_duplicate_rights),
	KUNIT_CASE(pkm_kunit_token_link_self_denies),
	KUNIT_CASE(pkm_kunit_token_link_session_mismatch_denies),
	KUNIT_CASE(pkm_kunit_token_link_non_primary_denies),
	KUNIT_CASE(pkm_kunit_token_link_role_swap_denies),
	KUNIT_CASE(pkm_kunit_token_link_replacement_invalidates_old_partner),
	KUNIT_CASE(pkm_kunit_token_link_replacement_invalidates_old_elevated),
	KUNIT_CASE(pkm_kunit_token_get_linked_requires_query_right),
	KUNIT_CASE(pkm_kunit_token_get_linked_default_token_returns_enoent),
	KUNIT_CASE(pkm_kunit_linked_session_destroy_emits_single_kmes_event),
	KUNIT_CASE(pkm_kunit_linked_session_destroy_waits_for_external_fd),
	KUNIT_CASE(pkm_kunit_token_adjust_sessionid_updates_target),
	KUNIT_CASE(pkm_kunit_token_adjust_sessionid_requires_cached_right),
	KUNIT_CASE(pkm_kunit_token_adjust_sessionid_requires_tcb),
	KUNIT_CASE(pkm_kunit_token_adjust_surfaces_preserve_mandatory_policy),
	KUNIT_CASE(pkm_kunit_token_adjust_default_updates_fields),
	KUNIT_CASE(pkm_kunit_token_adjust_default_clear_dacl),
	KUNIT_CASE(pkm_kunit_token_adjust_default_owner_user_sid_success),
	KUNIT_CASE(pkm_kunit_token_adjust_default_primary_group_user_sid_success),
	KUNIT_CASE(pkm_kunit_token_adjust_default_requires_cached_right),
	KUNIT_CASE(pkm_kunit_token_adjust_default_invalid_owner_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_default_invalid_primary_group_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_default_invalid_dacl_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_default_null_dacl_ptr_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_updates_and_queries_live_state),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_preserves_projected_gids),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_reset_restores_defaults),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_requires_cached_right),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_count_zero_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_count_over_max_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_null_entries_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_out_of_range_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_ioctl_usercopy_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_duplicate_indices_fail_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_deny_only_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_deny_only_disable_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_mandatory_non_logon_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_mandatory_non_logon_enable_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_logon_sid_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_logon_sid_enable_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_user_sid_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_groups_invalid_reset_encoding_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_updates_and_queries_live_state),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_remove_preserves_used_and_reset),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_absent_disable_remove_noop),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_requires_cached_right),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_duplicate_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_enable_absent_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_invalid_reset_encoding_fails_closed),
	KUNIT_CASE(pkm_kunit_token_adjust_privs_invalid_attributes_fails_closed),
	KUNIT_CASE(pkm_kunit_token_restrict_updates_query_and_source_unchanged),
	KUNIT_CASE(pkm_kunit_token_restrict_result_fd_preserves_source_access_mask),
	KUNIT_CASE(pkm_kunit_token_restrict_deny_only_survives_group_reset),
	KUNIT_CASE(pkm_kunit_token_restrict_intersects_existing_restricted_sids),
	KUNIT_CASE(pkm_kunit_token_restrict_empty_intersection_fails_closed),
	KUNIT_CASE(pkm_kunit_token_restrict_write_restricted_bypasses_read_pass),
	KUNIT_CASE(pkm_kunit_token_restrict_deny_only_access_check_polarity),
	KUNIT_CASE(pkm_kunit_token_restrict_access_requires_restricted_pass),
	KUNIT_CASE(pkm_kunit_token_restrict_write_restricted_sets_user_deny_only),
	KUNIT_CASE(pkm_kunit_token_restrict_write_restricted_sticky_from_source),
	KUNIT_CASE(pkm_kunit_token_restrict_out_of_range_deny_index_fails_closed),
	KUNIT_CASE(pkm_kunit_token_restrict_new_identity_and_copied_metadata),
	KUNIT_CASE(pkm_kunit_token_restrict_group_sids_fixed_attributes_modified),
	KUNIT_CASE(pkm_kunit_token_restrict_copies_extended_field_matrix),
	KUNIT_CASE(pkm_kunit_token_restrict_requires_cached_duplicate),
	KUNIT_CASE(pkm_kunit_token_restrict_duplicate_deny_indices_fail_closed),
	KUNIT_CASE(pkm_kunit_token_restrict_reserved_flags_fail_closed),
	KUNIT_CASE(pkm_kunit_token_restrict_malformed_payload_fails_closed),
	KUNIT_CASE(pkm_kunit_identification_impersonation_denies_access_check),
	KUNIT_CASE(pkm_kunit_create_token_mandatory_policy_zero_disables_mic),
	KUNIT_CASE(pkm_kunit_privilege_use_msgpack_schema),
	{}
};

static struct kunit_suite pkm_kunit_token_suite = {
	.name = "pkm_kunit_token",
	.test_cases = pkm_kunit_token_cases,
};

kunit_test_suite(pkm_kunit_token_suite);
