// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"


static void pkm_kunit_boot_system_defaults(struct kunit *test)
{
	static const u8 system_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	static const u8 logon_sid[] = {
		1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	};
	static const u8 admin_sid[] = {
		1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0,
	};
	static const u8 everyone_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
	};
	static const u8 auth_users_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0,
	};
	static const u8 local_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0,
	};
	static const char auth_pkg[] = "Negotiate";
	static const char source_name[] = "PeiosKrn";
	static const u32 expected_attrs[] = {
		0x0000000f,
		0x00000007,
		0x00000007,
		0x00000007,
		0xc0000007,
	};
	static const u8 *expected_group_sids[] = {
		admin_sid,
		everyone_sid,
		auth_users_sid,
		local_sid,
		logon_sid,
	};
	static const size_t expected_group_lens[] = {
		sizeof(admin_sid),
		sizeof(everyone_sid),
		sizeof(auth_users_sid),
		sizeof(local_sid),
		sizeof(logon_sid),
	};
	struct pkm_kacs_boot_snapshot snapshot = { };
	struct pkm_kacs_boot_snapshot effective_snapshot = { };
	const void *effective_token;
	const void *primary_token;
	u32 i;

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_boot_snapshot(&snapshot));

	effective_token = pkm_kacs_current_effective_token_ptr();
	primary_token = pkm_kacs_current_primary_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, effective_token);
	KUNIT_ASSERT_NOT_NULL(test, primary_token);

	KUNIT_EXPECT_PTR_EQ(test, effective_token, primary_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(effective_token,
							 &effective_snapshot));
	KUNIT_EXPECT_PTR_EQ(test, effective_snapshot.token_ptr, effective_token);
	KUNIT_EXPECT_EQ(test, snapshot.session_id, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.auth_id, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.token_id, 0ULL);
	pkm_kunit_expect_guid_v4(test, snapshot.token_guid);
	pkm_kunit_expect_guid_v4(test, effective_snapshot.token_guid);
	KUNIT_EXPECT_EQ(test, snapshot.modified_id, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.logon_type, 5U);
	pkm_kunit_expect_bytes_eq(test, snapshot.auth_pkg_ptr, snapshot.auth_pkg_len,
				  (const u8 *)auth_pkg, sizeof(auth_pkg) - 1);
	pkm_kunit_expect_bytes_eq(test, snapshot.user_sid_ptr, snapshot.user_sid_len,
				  system_sid, sizeof(system_sid));
	pkm_kunit_expect_bytes_eq(test, snapshot.logon_sid_ptr,
				  snapshot.logon_sid_len, logon_sid,
				  sizeof(logon_sid));
	KUNIT_ASSERT_NOT_NULL(test, snapshot.groups_ptr);
	KUNIT_EXPECT_EQ(test, snapshot.group_count, 5U);
	for (i = 0; i < snapshot.group_count; i++) {
		KUNIT_EXPECT_EQ(test, snapshot.groups_ptr[i].attributes,
				expected_attrs[i]);
		pkm_kunit_expect_bytes_eq(test, snapshot.groups_ptr[i].sid_ptr,
					  snapshot.groups_ptr[i].sid_len,
					  expected_group_sids[i],
					  expected_group_lens[i]);
	}
	KUNIT_EXPECT_EQ(test, snapshot.owner_sid_index, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.primary_group_index, 1U);
	pkm_kunit_expect_bytes_eq(test, snapshot.default_dacl_ptr,
				  snapshot.default_dacl_len,
				  pkm_kunit_system_default_dacl,
				  sizeof(pkm_kunit_system_default_dacl));
	KUNIT_EXPECT_EQ(test, snapshot.privileges_present, 0xc000000ffffffffcULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_enabled, 0xc000000ffffffffcULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_enabled_by_default,
			0xc000000ffffffffcULL);
	/*
	 * privileges_used is the only runtime-mutable privilege field: the live
	 * boot system token legitimately accumulates SeChangeNotify (bypass
	 * traverse checking) from boot-time path traversal as SYSTEM, so it is
	 * not a stable construction default and is excluded from this check.
	 */
	KUNIT_EXPECT_EQ(test, snapshot.integrity_level, 16384U);
	KUNIT_EXPECT_EQ(test, snapshot.token_type, 1U);
	KUNIT_EXPECT_EQ(test, snapshot.impersonation_level, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.mandatory_policy, 0x00000003U);
	KUNIT_EXPECT_EQ(test, snapshot.interactive_session_id, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.projected_uid, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.projected_gid, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.audit_policy, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.elevation_type, KACS_ELEVATION_DEFAULT);
	KUNIT_EXPECT_EQ(test, snapshot.restricted, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.user_deny_only, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.write_restricted, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.confinement_exempt, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.isolation_boundary, 0U);
	pkm_kunit_expect_bytes_eq(test, snapshot.source_name_ptr,
				  snapshot.source_name_len,
				  (const u8 *)source_name,
				  sizeof(source_name) - 1);
	KUNIT_EXPECT_EQ(test, snapshot.source_id, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.expiration, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.origin, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.restricted_sid_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.confinement_sid_present, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.confinement_capability_count, 0U);
	KUNIT_EXPECT_EQ(test, snapshot.projected_supplementary_gid_count, 0U);
	KUNIT_ASSERT_NOT_NULL(test, snapshot.own_sd_ptr);
	KUNIT_ASSERT_GT(test, (long)snapshot.own_sd_len, 20L);
	pkm_kunit_expect_sd_sid_component(test, snapshot.own_sd_ptr,
					  snapshot.own_sd_len, 4, system_sid,
					  sizeof(system_sid));
	pkm_kunit_expect_owner_rights_read_control_ace(
		test, snapshot.own_sd_ptr, snapshot.own_sd_len, 0);
	pkm_kunit_expect_allow_ace(test, snapshot.own_sd_ptr,
				   snapshot.own_sd_len, 1,
				   PKM_KUNIT_DEFAULT_TOKEN_SELF_ACCESS,
				   system_sid, sizeof(system_sid));
	pkm_kunit_expect_allow_ace(test, snapshot.own_sd_ptr,
				   snapshot.own_sd_len, 2,
				   KACS_TOKEN_ALL_ACCESS, system_sid,
				   sizeof(system_sid));
	pkm_kunit_expect_allow_ace(test, snapshot.own_sd_ptr,
				   snapshot.own_sd_len, 3,
				   KACS_TOKEN_ALL_ACCESS, admin_sid,
				   sizeof(admin_sid));
	KUNIT_EXPECT_PTR_EQ(test,
			    pkm_kunit_dacl_ace_const(snapshot.own_sd_ptr,
						     snapshot.own_sd_len, 4),
			    NULL);
	/*
	 * Same reason: exclude the runtime-mutable privileges_used from the
	 * boot-vs-effective comparison by aligning it, so the shared field-by-
	 * field helper does not flag expected runtime privilege accounting.
	 */
	effective_snapshot.privileges_used = snapshot.privileges_used;
	pkm_kunit_expect_boot_snapshot_eq_except_identity(test, &snapshot,
								  &effective_snapshot);
}


static void pkm_kunit_boot_anonymous_defaults(struct kunit *test)
{
	static const char auth_pkg[] = "Negotiate";
	struct pkm_kacs_boot_snapshot snapshot = { };
	const void *anonymous_token;
	u8 logon_sid[20] = { };
	u32 everyone_attributes = 0;

	pkm_kunit_build_logon_sid(998ULL, logon_sid);
	anonymous_token = pkm_kacs_boot_anonymous_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, anonymous_token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(anonymous_token,
							 &snapshot));
	KUNIT_EXPECT_PTR_EQ(test, snapshot.token_ptr, anonymous_token);
	KUNIT_EXPECT_EQ(test, snapshot.session_id, 998ULL);
	KUNIT_EXPECT_EQ(test, snapshot.auth_id, 998ULL);
	pkm_kunit_expect_guid_v4(test, snapshot.token_guid);
	KUNIT_EXPECT_EQ(test, snapshot.created_at, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.logon_type,
			(u32)PKM_KUNIT_LOGON_TYPE_NETWORK);
	pkm_kunit_expect_bytes_eq(test, snapshot.auth_pkg_ptr,
				  snapshot.auth_pkg_len, (const u8 *)auth_pkg,
				  sizeof(auth_pkg) - 1);
	pkm_kunit_expect_bytes_eq(test, snapshot.user_sid_ptr,
				  snapshot.user_sid_len,
				  pkm_kunit_anonymous_sid,
				  sizeof(pkm_kunit_anonymous_sid));
	pkm_kunit_expect_bytes_eq(test, snapshot.logon_sid_ptr,
				  snapshot.logon_sid_len, logon_sid,
				  sizeof(logon_sid));
	KUNIT_EXPECT_EQ(test, snapshot.group_count, 1U);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kunit_snapshot_has_group(
				  &snapshot, pkm_kunit_everyone_sid,
				  sizeof(pkm_kunit_everyone_sid),
				  &everyone_attributes));
	KUNIT_EXPECT_NE(test,
			everyone_attributes & PKM_KUNIT_SE_GROUP_ENABLED, 0U);
	KUNIT_EXPECT_FALSE(test,
			   pkm_kunit_snapshot_has_group(
				   &snapshot,
				   pkm_kunit_authenticated_users_sid,
				   sizeof(pkm_kunit_authenticated_users_sid),
				   NULL));
	KUNIT_EXPECT_EQ(test, snapshot.privileges_present, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_enabled, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_enabled_by_default, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.privileges_used, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.integrity_level,
			(u32)PKM_KUNIT_IL_UNTRUSTED);
	KUNIT_EXPECT_EQ(test, snapshot.token_type,
			(u32)KACS_TOKEN_TYPE_IMPERSONATION);
	KUNIT_EXPECT_EQ(test, snapshot.impersonation_level,
			(u32)KACS_IMLEVEL_ANONYMOUS);
	KUNIT_EXPECT_EQ(test, snapshot.elevation_type, KACS_ELEVATION_DEFAULT);
	KUNIT_EXPECT_EQ(test, snapshot.projected_uid, 65534U);
	KUNIT_EXPECT_EQ(test, snapshot.projected_gid, 65534U);
	KUNIT_EXPECT_EQ(test, snapshot.audit_policy, 0U);
}


static void pkm_kunit_boot_session_registered(struct kunit *test)
{
	static const u8 system_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	static const u8 logon_sid[] = {
		1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	};
	static const char auth_pkg[] = "Negotiate";
	struct pkm_kacs_session_snapshot snapshot = { };

	KUNIT_ASSERT_EQ(test, kacs_rust_kunit_session_snapshot(0, &snapshot), 0);
	KUNIT_ASSERT_NOT_NULL(test, snapshot.session_ptr);
	KUNIT_EXPECT_EQ(test, snapshot.session_id, 0ULL);
	KUNIT_EXPECT_EQ(test, snapshot.logon_type, 5U);
	pkm_kunit_expect_bytes_eq(test, snapshot.auth_pkg_ptr, snapshot.auth_pkg_len,
				  (const u8 *)auth_pkg, sizeof(auth_pkg) - 1);
	pkm_kunit_expect_bytes_eq(test, snapshot.user_sid_ptr, snapshot.user_sid_len,
				  system_sid, sizeof(system_sid));
	pkm_kunit_expect_bytes_eq(test, snapshot.logon_sid_ptr,
				  snapshot.logon_sid_len, logon_sid,
				  sizeof(logon_sid));
}


static void pkm_kunit_boot_allow_caps(struct kunit *test)
{
	const struct cred *cred = current_cred();
	kernel_cap_t empty = CAP_EMPTY_SET;

	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_CHOWN));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_DAC_OVERRIDE));
	KUNIT_EXPECT_TRUE(test,
			  cap_raised(cred->cap_effective, CAP_DAC_READ_SEARCH));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_FOWNER));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_FSETID));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_KILL));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_SETGID));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_SETUID));
	KUNIT_EXPECT_TRUE(test,
			  cap_raised(cred->cap_effective, CAP_NET_BROADCAST));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_IPC_OWNER));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_effective, CAP_LEASE));

	KUNIT_EXPECT_EQ(test,
			memcmp(&cred->cap_effective, &cred->cap_permitted,
			       sizeof(kernel_cap_t)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(&cred->cap_effective, &cred->cap_inheritable,
			       sizeof(kernel_cap_t)),
			0);
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_bset, CAP_CHOWN));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_bset, CAP_DAC_OVERRIDE));
	KUNIT_EXPECT_TRUE(test,
			  cap_raised(cred->cap_bset, CAP_DAC_READ_SEARCH));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_bset, CAP_FOWNER));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_bset, CAP_FSETID));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_bset, CAP_KILL));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_bset, CAP_SETGID));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_bset, CAP_SETUID));
	KUNIT_EXPECT_TRUE(test,
			  cap_raised(cred->cap_bset, CAP_NET_BROADCAST));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_bset, CAP_IPC_OWNER));
	KUNIT_EXPECT_TRUE(test, cap_raised(cred->cap_bset, CAP_LEASE));
	KUNIT_EXPECT_EQ(test,
			memcmp(&cred->cap_ambient, &empty, sizeof(kernel_cap_t)),
			0);
}


static void pkm_kunit_blob_lifecycle_defaults(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_blob_lifecycle_defaults(), 0);
}


static void pkm_kunit_ed25519_crypto_rfc8032_vectors(struct kunit *test)
{
	static const u8 public_key_empty[32] = {
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
		0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
		0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
	};
	static const u8 signature_empty[64] = {
		0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
		0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
		0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
		0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
		0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
		0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
		0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
		0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
	};
	static const u8 public_key_one_byte[32] = {
		0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
		0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
		0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
		0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
	};
	static const u8 msg_one_byte[1] = { 0x72 };
	static const u8 signature_one_byte[64] = {
		0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
		0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
		0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
		0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
		0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
		0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
		0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
		0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
	};
	static const u8 empty_msg[1] = {};

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_ed25519_crypto_verify(
				public_key_empty, sizeof(public_key_empty),
				empty_msg, 0, signature_empty,
				sizeof(signature_empty)),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_ed25519_crypto_verify(
				public_key_one_byte, sizeof(public_key_one_byte),
				msg_one_byte, sizeof(msg_one_byte),
				signature_one_byte, sizeof(signature_one_byte)),
			0);
}


static void pkm_kunit_ed25519_crypto_rejects_bad_inputs(struct kunit *test)
{
	static const u8 public_key_vector[32] = {
		0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
		0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
		0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
		0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
	};
	static const u8 signature_vector[64] = {
		0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
		0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
		0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
		0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
		0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
		0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
		0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
		0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
	};
	struct crypto_sig *tfm;
	u8 public_key[32];
	u8 signature[64];
	u8 msg[1] = { 0x72 };

	memcpy(public_key, public_key_vector, sizeof(public_key));
	memcpy(signature, signature_vector, sizeof(signature));
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_ed25519_crypto_verify(
				public_key, sizeof(public_key), msg, sizeof(msg),
				signature, sizeof(signature)),
			0);

	msg[0] ^= 0x01;
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_ed25519_crypto_verify(
				public_key, sizeof(public_key), msg, sizeof(msg),
				signature, sizeof(signature)),
			-EKEYREJECTED);
	msg[0] ^= 0x01;

	signature[0] ^= 0x01;
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_ed25519_crypto_verify(
				public_key, sizeof(public_key), msg, sizeof(msg),
				signature, sizeof(signature)),
			-EKEYREJECTED);
	signature[0] ^= 0x01;

	public_key[0] ^= 0x01;
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_ed25519_crypto_verify(
				public_key, sizeof(public_key), msg, sizeof(msg),
				signature, sizeof(signature)),
			-EKEYREJECTED);
	public_key[0] ^= 0x01;

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_ed25519_crypto_verify(
				public_key, sizeof(public_key) - 1, msg,
				sizeof(msg), signature, sizeof(signature)),
			-EINVAL);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_ed25519_crypto_verify(
				public_key, sizeof(public_key), msg, sizeof(msg),
				signature, sizeof(signature) - 1),
			-EINVAL);

	tfm = crypto_alloc_sig("ed25519", 0, 0);
	KUNIT_ASSERT_FALSE(test, IS_ERR(tfm));
	KUNIT_EXPECT_EQ(test,
			crypto_sig_verify(tfm, signature, sizeof(signature), msg,
					  sizeof(msg)),
			-EINVAL);
	crypto_free_sig(tfm);
}


static void pkm_kunit_signing_crypto_verify_sets_tcb_trust(
	struct kunit *test)
{
	static const u8 public_key[32] = {
		0x03, 0xa1, 0x07, 0xbf, 0xf3, 0xce, 0x10, 0xbe,
		0x1d, 0x70, 0xdd, 0x18, 0xe7, 0x4b, 0xc0, 0x99,
		0x67, 0xe4, 0xd6, 0x30, 0x9b, 0xa5, 0x0d, 0x5f,
		0x1d, 0xdc, 0x86, 0x64, 0x12, 0x55, 0x31, 0xb8,
	};
	static const u8 hash[32] = {
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
		0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	};
	static const u8 signature[64] = {
		0x01, 0x05, 0x5e, 0xed, 0x19, 0xb9, 0x4a, 0x3a,
		0x8d, 0x1f, 0x9d, 0x45, 0xa1, 0x3f, 0x2b, 0x69,
		0x02, 0x04, 0xcb, 0x20, 0x62, 0xdb, 0xfe, 0x84,
		0xcc, 0xb2, 0xf8, 0x37, 0x8a, 0x0d, 0xad, 0x26,
		0x9e, 0x81, 0x4a, 0xe4, 0x54, 0xfb, 0x5b, 0x30,
		0xd3, 0x6a, 0x24, 0x42, 0xe8, 0xa3, 0x2f, 0x6b,
		0xa2, 0xfc, 0xbb, 0x41, 0xba, 0x2e, 0x52, 0x93,
		0x68, 0xd2, 0x26, 0x73, 0x15, 0xc1, 0x3e, 0x02,
	};
	struct pkm_kacs_kunit_signing_key_entry keys[2] = {};
	struct pkm_kacs_kunit_signing_probe material = {};
	struct pkm_kacs_kunit_signing_verify_out out = {};

	material.source = PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR;
	memcpy(material.hash, hash, sizeof(material.hash));
	memcpy(material.signature, signature, sizeof(material.signature));
	memcpy(keys[0].public_key, public_key, sizeof(keys[0].public_key));
	keys[0].pip_type = PKM_KUNIT_SIGNING_PIP_PROTECTED;
	keys[0].pip_trust = PKM_KUNIT_SIGNING_TRUST_TCB;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material_crypto(
				&material, keys, ARRAY_SIZE(keys), &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 1U);
	KUNIT_EXPECT_EQ(test, out.pip_type,
			PKM_KUNIT_SIGNING_PIP_PROTECTED);
	KUNIT_EXPECT_EQ(test, out.pip_trust, PKM_KUNIT_SIGNING_TRUST_TCB);

	material.hash[0] ^= 0x01;
	memset(&out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material_crypto(
				&material, keys, ARRAY_SIZE(keys), &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_type, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_trust, 0U);
}


static void pkm_kunit_signed_exec_pin_tracks_verified_material(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe material = {};
	u32 pinned = 0;

	pkm_kunit_signing_fill_tcb_vector_material(&material);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_signed_exec_pin_from_signing_material(
				&material, &pinned),
			0);
	KUNIT_EXPECT_EQ(test, pinned, 1U);

	material.signature[0] ^= 0x01;
	pinned = 1;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_signed_exec_pin_from_signing_material(
				&material, &pinned),
			0);
	KUNIT_EXPECT_EQ(test, pinned, 0U);

	material.source = PKM_KACS_KUNIT_SIGNING_SOURCE_NONE;
	pinned = 1;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_signed_exec_pin_from_signing_material(
				&material, &pinned),
			0);
	KUNIT_EXPECT_EQ(test, pinned, 0U);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_signed_exec_pin_from_signing_material(
				NULL, &pinned),
			-EINVAL);
}


static void pkm_kunit_signed_exec_pin_blocks_content_mutation(
	struct kunit *test)
{
	static const u32 ops[] = {
		PKM_KACS_KUNIT_PIN_OP_WRITE_PERMISSION,
		PKM_KACS_KUNIT_PIN_OP_WRITE_INTENT,
		PKM_KACS_KUNIT_PIN_OP_TRUNCATE,
		PKM_KACS_KUNIT_PIN_OP_FALLOCATE_MUTATE,
		PKM_KACS_KUNIT_PIN_OP_FALLOCATE_ALLOCATE,
		PKM_KACS_KUNIT_PIN_OP_IOCTL_MUTATE,
		PKM_KACS_KUNIT_PIN_OP_IOCTL_UNKNOWN,
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ops); i++) {
		KUNIT_EXPECT_EQ(test,
				pkm_kacs_kunit_check_signed_exec_pin_mutation(
					1, 1, PKM_KUNIT_FILE_WRITE_DATA,
					ops[i]),
				-EACCES);
	}
}


static void pkm_kunit_signed_exec_pin_blocks_unmanaged_mutation(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				1, 0, 0,
				PKM_KACS_KUNIT_PIN_OP_WRITE_PERMISSION),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				1, 0, 0,
				PKM_KACS_KUNIT_PIN_OP_FALLOCATE_MUTATE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				1, 0, 0,
				PKM_KACS_KUNIT_PIN_OP_IOCTL_MUTATE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				1, 0, 0,
				PKM_KACS_KUNIT_PIN_OP_IOCTL_UNKNOWN),
			-EACCES);
}


static void pkm_kunit_signed_exec_pin_preserves_unpinned_facs(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				0, 1, PKM_KUNIT_FILE_WRITE_DATA,
				PKM_KACS_KUNIT_PIN_OP_WRITE_PERMISSION),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				0, 1, PKM_KUNIT_FILE_WRITE_DATA,
				PKM_KACS_KUNIT_PIN_OP_WRITE_INTENT),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				0, 1, PKM_KUNIT_FILE_WRITE_DATA,
				PKM_KACS_KUNIT_PIN_OP_TRUNCATE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				0, 1, PKM_KUNIT_FILE_WRITE_DATA,
				PKM_KACS_KUNIT_PIN_OP_FALLOCATE_MUTATE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				0, 1, PKM_KUNIT_FILE_WRITE_DATA,
				PKM_KACS_KUNIT_PIN_OP_FALLOCATE_ALLOCATE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				0, 1, PKM_KUNIT_FILE_WRITE_DATA,
				PKM_KACS_KUNIT_PIN_OP_IOCTL_MUTATE),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				0, 1, PKM_KUNIT_FILE_WRITE_DATA,
				PKM_KACS_KUNIT_PIN_OP_IOCTL_UNKNOWN),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				0, 1, 0,
				PKM_KACS_KUNIT_PIN_OP_WRITE_PERMISSION),
			-EACCES);
}


static void pkm_kunit_signed_exec_pin_blocks_path_and_sig_xattr(
	struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				1, 1, PKM_KUNIT_FILE_WRITE_DATA,
				PKM_KACS_KUNIT_PIN_OP_PATH_TRUNCATE),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				1, 1, PKM_KUNIT_FILE_WRITE_EA,
				PKM_KACS_KUNIT_PIN_OP_SIGNING_XATTR_SET),
			-EACCES);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_signed_exec_pin_mutation(
				0, 1, PKM_KUNIT_FILE_WRITE_DATA, 0),
			-EINVAL);
}


static void pkm_kunit_signing_xattr_hashes_non_elf(struct kunit *test)
{
	static const u8 file[] = "abc";
	static const u8 expected_hash[32] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	};
	struct pkm_kacs_kunit_signing_probe out = {};
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];

	pkm_kunit_signing_fill_blob(sig_blob, 0x20);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file) - 1, sig_blob,
				sizeof(sig_blob), &out),
			0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR);
	KUNIT_EXPECT_EQ(test,
			memcmp(out.signature, sig_blob + 1,
			       PKM_KUNIT_SIGNING_SIG_LEN),
			0);
	KUNIT_EXPECT_EQ(test, memcmp(out.hash, expected_hash,
				     sizeof(expected_hash)),
			0);
}


static void pkm_kunit_signing_short_file_uses_xattr(struct kunit *test)
{
	static const u8 file[] = { 0x7f, 'E', 'L' };
	struct pkm_kacs_kunit_signing_probe out = {};
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];

	pkm_kunit_signing_fill_blob(sig_blob, 0x30);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file), sig_blob, sizeof(sig_blob),
				&out),
			0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR);
}


static void pkm_kunit_signing_elf_section_zeroes_signature_bytes(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe out = {};
	u8 expected_file[PKM_KUNIT_ELF_LEN];
	u8 expected_hash[32];
	u8 raw_hash[32];
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];
	u8 file[PKM_KUNIT_ELF_LEN];

	pkm_kunit_signing_fill_blob(sig_blob, 0x40);
	pkm_kunit_signing_build_elf(file, sig_blob, true, true);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file), NULL, 0, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_ELF);
	KUNIT_EXPECT_EQ(test,
			memcmp(out.signature, sig_blob + 1,
			       PKM_KUNIT_SIGNING_SIG_LEN),
			0);

	memcpy(expected_file, file, sizeof(expected_file));
	memset(expected_file + PKM_KUNIT_ELF_SIG_OFFSET, 0,
	       PKM_KUNIT_SIGNING_BLOB_LEN);
	sha256(expected_file, sizeof(expected_file), expected_hash);
	sha256(file, sizeof(file), raw_hash);
	KUNIT_EXPECT_EQ(test, memcmp(out.hash, expected_hash,
				     sizeof(expected_hash)),
			0);
	KUNIT_EXPECT_NE(test, memcmp(out.hash, raw_hash, sizeof(raw_hash)), 0);
}


static void pkm_kunit_signing_elf_priority_blocks_xattr_fallback(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe out = {};
	u8 xattr_blob[PKM_KUNIT_SIGNING_BLOB_LEN];
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];
	u8 file[PKM_KUNIT_ELF_LEN];

	pkm_kunit_signing_fill_blob(sig_blob, 0x50);
	pkm_kunit_signing_fill_blob(xattr_blob, 0x60);
	pkm_kunit_signing_build_elf(file, sig_blob, true, false);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file), xattr_blob,
				sizeof(xattr_blob), &out),
			0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_malformed_elf_metadata_blocks_xattr(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe out = {};
	u8 xattr_blob[PKM_KUNIT_SIGNING_BLOB_LEN];
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];
	u8 file[PKM_KUNIT_ELF_LEN];
	Elf64_Shdr shstr = {};

	pkm_kunit_signing_fill_blob(sig_blob, 0xa0);
	pkm_kunit_signing_fill_blob(xattr_blob, 0xb0);
	pkm_kunit_signing_build_elf(file, sig_blob, true, true);

	memcpy(&shstr, file + PKM_KUNIT_ELF_SHOFF + sizeof(Elf64_Shdr),
	       sizeof(shstr));
	shstr.sh_offset = PKM_KUNIT_ELF_LEN + 1;
	memcpy(file + PKM_KUNIT_ELF_SHOFF + sizeof(Elf64_Shdr), &shstr,
	       sizeof(shstr));

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file), xattr_blob,
				sizeof(xattr_blob), &out),
			0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_elf_without_section_uses_xattr(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe out = {};
	u8 xattr_blob[PKM_KUNIT_SIGNING_BLOB_LEN];
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];
	u8 expected_hash[32];
	u8 file[PKM_KUNIT_ELF_LEN];

	pkm_kunit_signing_fill_blob(sig_blob, 0x70);
	pkm_kunit_signing_fill_blob(xattr_blob, 0x80);
	pkm_kunit_signing_build_elf(file, sig_blob, false, false);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file), xattr_blob,
				sizeof(xattr_blob), &out),
			0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR);
	KUNIT_EXPECT_EQ(test,
			memcmp(out.signature, xattr_blob + 1,
			       PKM_KUNIT_SIGNING_SIG_LEN),
			0);
	sha256(file, sizeof(file), expected_hash);
	KUNIT_EXPECT_EQ(test, memcmp(out.hash, expected_hash,
				     sizeof(expected_hash)),
			0);
}


static void pkm_kunit_signing_invalid_xattr_unsigned(struct kunit *test)
{
	static const u8 file[] = "plain";
	struct pkm_kacs_kunit_signing_probe out = {};
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];

	pkm_kunit_signing_fill_blob(sig_blob, 0x90);
	sig_blob[0] = 0x02;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file) - 1, sig_blob,
				sizeof(sig_blob), &out),
			0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);

	pkm_kunit_signing_fill_blob(sig_blob, 0x90);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file) - 1, sig_blob,
				sizeof(sig_blob) - 1, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_reader_matches_buffer_for_elf(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_reader_args args = {};
	struct pkm_kacs_kunit_signing_probe reader_out = {};
	struct pkm_kacs_kunit_signing_probe buffer_out = {};
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];
	u8 file[PKM_KUNIT_ELF_LEN];

	pkm_kunit_signing_fill_blob(sig_blob, 0xc0);
	pkm_kunit_signing_build_elf(file, sig_blob, true, true);
	args.file_bytes = file;
	args.file_len = sizeof(file);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file), NULL, 0, &buffer_out),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args,
							    &reader_out),
			0);
	KUNIT_EXPECT_EQ(test, reader_out.source, buffer_out.source);
	KUNIT_EXPECT_EQ(test,
			memcmp(reader_out.signature, buffer_out.signature,
			       sizeof(reader_out.signature)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(reader_out.hash, buffer_out.hash,
			       sizeof(reader_out.hash)),
			0);
}


static void pkm_kunit_signing_reader_xattr_hashes_non_elf(struct kunit *test)
{
	static const u8 file[] = "reader-file";
	struct pkm_kacs_kunit_signing_reader_args args = {};
	struct pkm_kacs_kunit_signing_probe out = {};
	u8 expected_hash[32];
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];

	pkm_kunit_signing_fill_blob(sig_blob, 0xd0);
	args.file_bytes = file;
	args.file_len = sizeof(file) - 1;
	args.xattr_sig = sig_blob;
	args.xattr_sig_len = sizeof(sig_blob);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, &out), 0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR);
	KUNIT_EXPECT_EQ(test,
			memcmp(out.signature, sig_blob + 1,
			       PKM_KUNIT_SIGNING_SIG_LEN),
			0);
	sha256(file, sizeof(file) - 1, expected_hash);
	KUNIT_EXPECT_EQ(test,
			memcmp(out.hash, expected_hash, sizeof(expected_hash)),
			0);
}


static void pkm_kunit_signing_reader_missing_xattr_unsigned(
	struct kunit *test)
{
	static const u8 file[] = "unsigned";
	struct pkm_kacs_kunit_signing_reader_args args = {
		.file_bytes = file,
		.file_len = sizeof(file) - 1,
	};
	struct pkm_kacs_kunit_signing_probe out = {};

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, &out), 0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_reader_invalid_xattr_unsigned(
	struct kunit *test)
{
	static const u8 file[] = "reader-invalid-xattr";
	struct pkm_kacs_kunit_signing_reader_args args = {};
	struct pkm_kacs_kunit_signing_probe out = {};
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];

	pkm_kunit_signing_fill_blob(sig_blob, 0xe0);
	args.file_bytes = file;
	args.file_len = sizeof(file) - 1;
	args.xattr_sig = sig_blob;
	args.xattr_sig_len = sizeof(sig_blob) - 1;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, &out), 0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);

	args.xattr_sig_len = sizeof(sig_blob);
	sig_blob[0] = 0x02;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, &out), 0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_reader_size_change_invalidates(
	struct kunit *test)
{
	static const u8 file[] = "size-change";
	struct pkm_kacs_kunit_signing_reader_args args = {};
	struct pkm_kacs_kunit_signing_probe out = {};
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];

	pkm_kunit_signing_fill_blob(sig_blob, 0xf0);
	args.file_bytes = file;
	args.file_len = sizeof(file) - 1;
	args.xattr_sig = sig_blob;
	args.xattr_sig_len = sizeof(sig_blob);
	args.use_final_file_len = 1;
	args.final_file_len = args.file_len + 1;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, &out), 0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_reader_read_failure_invalidates(
	struct kunit *test)
{
	static const u8 file[] = "read-failure";
	struct pkm_kacs_kunit_signing_reader_args args = {};
	struct pkm_kacs_kunit_signing_probe out = {};
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];

	pkm_kunit_signing_fill_blob(sig_blob, 0x10);
	args.file_bytes = file;
	args.file_len = sizeof(file) - 1;
	args.xattr_sig = sig_blob;
	args.xattr_sig_len = sizeof(sig_blob);
	args.fail_reads = 1;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, &out), 0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_reader_malformed_elf_blocks_xattr(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_reader_args args = {};
	struct pkm_kacs_kunit_signing_probe out = {};
	u8 xattr_blob[PKM_KUNIT_SIGNING_BLOB_LEN];
	u8 sig_blob[PKM_KUNIT_SIGNING_BLOB_LEN];
	u8 file[PKM_KUNIT_ELF_LEN];
	Elf64_Shdr shstr = {};

	pkm_kunit_signing_fill_blob(sig_blob, 0x20);
	pkm_kunit_signing_fill_blob(xattr_blob, 0x30);
	pkm_kunit_signing_build_elf(file, sig_blob, true, true);

	memcpy(&shstr, file + PKM_KUNIT_ELF_SHOFF + sizeof(Elf64_Shdr),
	       sizeof(shstr));
	shstr.sh_offset = PKM_KUNIT_ELF_LEN + 1;
	memcpy(file + PKM_KUNIT_ELF_SHOFF + sizeof(Elf64_Shdr), &shstr,
	       sizeof(shstr));

	args.file_bytes = file;
	args.file_len = sizeof(file);
	args.xattr_sig = xattr_blob;
	args.xattr_sig_len = sizeof(xattr_blob);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, &out), 0);
	KUNIT_EXPECT_EQ(test, out.source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_verify_unsigned_has_no_trust(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe material = {};
	struct pkm_kacs_kunit_signing_verify_out out = {};

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				&material, NULL, 0, 0, 0, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_type, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_trust, 0U);
}


static void pkm_kunit_signing_verify_first_key_sets_tcb_trust(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry keys[2] = {};
	struct pkm_kacs_kunit_signing_probe material = {};
	struct pkm_kacs_kunit_signing_verify_out out = {};

	pkm_kunit_signing_fill_probe(&material);
	pkm_kunit_signing_fill_key(&keys[0], 0x10,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				&material, keys, ARRAY_SIZE(keys), 0, 1,
				&out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 1U);
	KUNIT_EXPECT_EQ(test, out.pip_type,
			PKM_KUNIT_SIGNING_PIP_PROTECTED);
	KUNIT_EXPECT_EQ(test, out.pip_trust, PKM_KUNIT_SIGNING_TRUST_TCB);
}


static void pkm_kunit_signing_verify_later_key_after_miss(struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry keys[3] = {};
	struct pkm_kacs_kunit_signing_probe material = {};
	struct pkm_kacs_kunit_signing_verify_out out = {};

	pkm_kunit_signing_fill_probe(&material);
	pkm_kunit_signing_fill_key(&keys[0], 0x20,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);
	pkm_kunit_signing_fill_key(&keys[1], 0x40,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				&material, keys, ARRAY_SIZE(keys), 1, 1,
				&out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 1U);
	KUNIT_EXPECT_EQ(test, out.pip_type,
			PKM_KUNIT_SIGNING_PIP_PROTECTED);
	KUNIT_EXPECT_EQ(test, out.pip_trust, PKM_KUNIT_SIGNING_TRUST_TCB);
}


static void pkm_kunit_signing_verify_no_matching_key_unsigned(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry keys[2] = {};
	struct pkm_kacs_kunit_signing_probe material = {};
	struct pkm_kacs_kunit_signing_verify_out out = {};

	pkm_kunit_signing_fill_probe(&material);
	pkm_kunit_signing_fill_key(&keys[0], 0x50,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				&material, keys, ARRAY_SIZE(keys), 0, 0,
				&out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_type, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_trust, 0U);
}


static void pkm_kunit_signing_verify_unsupported_tier_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry keys[2] = {};
	struct pkm_kacs_kunit_signing_probe material = {};
	struct pkm_kacs_kunit_signing_verify_out out = {};

	pkm_kunit_signing_fill_probe(&material);
	pkm_kunit_signing_fill_key(&keys[0], 0x60, 1024U,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				&material, keys, ARRAY_SIZE(keys), 0, 1,
				&out),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, out.verified, 0U);
}


static void pkm_kunit_signing_verify_missing_terminator_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry keys[1] = {};
	struct pkm_kacs_kunit_signing_probe material = {};
	struct pkm_kacs_kunit_signing_verify_out out = {};

	pkm_kunit_signing_fill_probe(&material);
	pkm_kunit_signing_fill_key(&keys[0], 0x70,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				&material, keys, ARRAY_SIZE(keys), 0, 1,
				&out),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, out.verified, 0U);
}


static void pkm_kunit_signing_verify_terminator_stops_iteration(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry keys[3] = {};
	struct pkm_kacs_kunit_signing_probe material = {};
	struct pkm_kacs_kunit_signing_verify_out out = {};

	pkm_kunit_signing_fill_probe(&material);
	pkm_kunit_signing_fill_key(&keys[1], 0x80,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				&material, keys, ARRAY_SIZE(keys), 1, 1,
				&out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_type, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_trust, 0U);
}


static void pkm_kunit_builtin_signing_key_table_has_one_tcb_key(
	struct kunit *test)
{
	u32 usable_count = 0;
	u32 terminated = 0;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_builtin_signing_key_table_shape(
				&usable_count, &terminated),
			0);
	KUNIT_EXPECT_EQ(test, usable_count, 1U);
	KUNIT_EXPECT_EQ(test, terminated, 1U);
}

static struct kunit_case pkm_kunit_signing_cases[] = {
	KUNIT_CASE(pkm_kunit_boot_system_defaults),
	KUNIT_CASE(pkm_kunit_boot_anonymous_defaults),
	KUNIT_CASE(pkm_kunit_boot_session_registered),
	KUNIT_CASE(pkm_kunit_boot_allow_caps),
	KUNIT_CASE(pkm_kunit_blob_lifecycle_defaults),
	KUNIT_CASE(pkm_kunit_ed25519_crypto_rfc8032_vectors),
	KUNIT_CASE(pkm_kunit_ed25519_crypto_rejects_bad_inputs),
	KUNIT_CASE(pkm_kunit_signing_crypto_verify_sets_tcb_trust),
	KUNIT_CASE(pkm_kunit_signed_exec_pin_tracks_verified_material),
	KUNIT_CASE(pkm_kunit_signed_exec_pin_blocks_content_mutation),
	KUNIT_CASE(pkm_kunit_signed_exec_pin_blocks_unmanaged_mutation),
	KUNIT_CASE(pkm_kunit_signed_exec_pin_preserves_unpinned_facs),
	KUNIT_CASE(pkm_kunit_signed_exec_pin_blocks_path_and_sig_xattr),
	KUNIT_CASE(pkm_kunit_signing_xattr_hashes_non_elf),
	KUNIT_CASE(pkm_kunit_signing_short_file_uses_xattr),
	KUNIT_CASE(pkm_kunit_signing_elf_section_zeroes_signature_bytes),
	KUNIT_CASE(pkm_kunit_signing_elf_priority_blocks_xattr_fallback),
	KUNIT_CASE(pkm_kunit_signing_malformed_elf_metadata_blocks_xattr),
	KUNIT_CASE(pkm_kunit_signing_elf_without_section_uses_xattr),
	KUNIT_CASE(pkm_kunit_signing_invalid_xattr_unsigned),
	KUNIT_CASE(pkm_kunit_signing_reader_matches_buffer_for_elf),
	KUNIT_CASE(pkm_kunit_signing_reader_xattr_hashes_non_elf),
	KUNIT_CASE(pkm_kunit_signing_reader_missing_xattr_unsigned),
	KUNIT_CASE(pkm_kunit_signing_reader_invalid_xattr_unsigned),
	KUNIT_CASE(pkm_kunit_signing_reader_size_change_invalidates),
	KUNIT_CASE(pkm_kunit_signing_reader_read_failure_invalidates),
	KUNIT_CASE(pkm_kunit_signing_reader_malformed_elf_blocks_xattr),
	KUNIT_CASE(pkm_kunit_signing_verify_unsigned_has_no_trust),
	KUNIT_CASE(pkm_kunit_signing_verify_first_key_sets_tcb_trust),
	KUNIT_CASE(pkm_kunit_signing_verify_later_key_after_miss),
	KUNIT_CASE(pkm_kunit_signing_verify_no_matching_key_unsigned),
	KUNIT_CASE(pkm_kunit_signing_verify_unsupported_tier_fails_closed),
	KUNIT_CASE(pkm_kunit_signing_verify_missing_terminator_fails_closed),
	KUNIT_CASE(pkm_kunit_signing_verify_terminator_stops_iteration),
	KUNIT_CASE(pkm_kunit_builtin_signing_key_table_has_one_tcb_key),
	{}
};

static struct kunit_suite pkm_kunit_signing_suite = {
	.name = "pkm_kunit_signing",
	.test_cases = pkm_kunit_signing_cases,
};

kunit_test_suite(pkm_kunit_signing_suite);
