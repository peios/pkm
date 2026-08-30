// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"
#include "kunit_mldsa_vectors.h"
#include "firmware.h"
#include "signing.h"


static void pkm_kunit_boot_system_defaults(struct kunit *test)
{
	static const u8 system_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	static const u8 logon_sid[] = {
		1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 231, 3, 0, 0,
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
	KUNIT_EXPECT_EQ(test, snapshot.logon_session_id, 999ULL);
	KUNIT_EXPECT_EQ(test, snapshot.auth_id, 999ULL);
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
	/* Delegation: the top of the ratchet (PEI-524). */
	KUNIT_EXPECT_EQ(test, snapshot.impersonation_level, 3U);
	KUNIT_EXPECT_EQ(test, snapshot.mandatory_policy, 0x00000003U);
	KUNIT_EXPECT_EQ(test, snapshot.interactivity_scope, 0U);
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
	KUNIT_EXPECT_EQ(test, snapshot.logon_session_id, 998ULL);
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


static void pkm_kunit_boot_logon_session_registered(struct kunit *test)
{
	static const u8 system_sid[] = {
		1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0,
	};
	static const u8 logon_sid[] = {
		1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 231, 3, 0, 0,
	};
	static const char auth_pkg[] = "Negotiate";
	struct pkm_kacs_logon_session_snapshot snapshot = { };

	KUNIT_ASSERT_EQ(test, kacs_rust_kunit_logon_session_snapshot(999, &snapshot), 0);
	KUNIT_ASSERT_NOT_NULL(test, snapshot.session_ptr);
	KUNIT_EXPECT_EQ(test, snapshot.logon_session_id, 999ULL);
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


static void pkm_kunit_mldsa65_crypto_fips204_vectors(struct kunit *test)
{
	/*
	 * Both vectors are 32-byte messages, matching how KACS uses ML-DSA:
	 * the SHA-256 content hash is signed directly (psd-004 s6).
	 */
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_mldsa65_crypto_verify(
				pkm_kunit_mldsa65_pubkey,
				sizeof(pkm_kunit_mldsa65_pubkey),
				pkm_kunit_mldsa65_tcb_hash,
				sizeof(pkm_kunit_mldsa65_tcb_hash),
				pkm_kunit_mldsa65_tcb_sig,
				sizeof(pkm_kunit_mldsa65_tcb_sig)),
			0);
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_mldsa65_crypto_verify(
				pkm_kunit_mldsa65_pubkey,
				sizeof(pkm_kunit_mldsa65_pubkey),
				pkm_kunit_mldsa65_alt_hash,
				sizeof(pkm_kunit_mldsa65_alt_hash),
				pkm_kunit_mldsa65_alt_sig,
				sizeof(pkm_kunit_mldsa65_alt_sig)),
			0);

	/* A signature is bound to its message: cross-pairing must fail. */
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_mldsa65_crypto_verify(
				pkm_kunit_mldsa65_pubkey,
				sizeof(pkm_kunit_mldsa65_pubkey),
				pkm_kunit_mldsa65_alt_hash,
				sizeof(pkm_kunit_mldsa65_alt_hash),
				pkm_kunit_mldsa65_tcb_sig,
				sizeof(pkm_kunit_mldsa65_tcb_sig)),
			-EKEYREJECTED);
}


static void pkm_kunit_mldsa65_crypto_rejects_bad_inputs(struct kunit *test)
{
	struct crypto_sig *tfm;
	u8 *public_key;
	u8 *signature;
	u8 *msg;

	/*
	 * kunit_kzalloc rather than the stack: an ML-DSA-65 key and signature
	 * are 1952 and 3309 bytes, well past CONFIG_FRAME_WARN. Freed at
	 * teardown.
	 */
	public_key = kunit_kzalloc(test, PKM_KACS_SIGNING_PUBLIC_KEY_LEN,
				   GFP_KERNEL);
	signature = kunit_kzalloc(test, PKM_KACS_SIGNING_SIGNATURE_LEN,
				  GFP_KERNEL);
	msg = kunit_kzalloc(test, SHA256_DIGEST_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, public_key);
	KUNIT_ASSERT_NOT_NULL(test, signature);
	KUNIT_ASSERT_NOT_NULL(test, msg);

	memcpy(public_key, pkm_kunit_mldsa65_pubkey,
	       PKM_KACS_SIGNING_PUBLIC_KEY_LEN);
	memcpy(signature, pkm_kunit_mldsa65_tcb_sig,
	       PKM_KACS_SIGNING_SIGNATURE_LEN);
	memcpy(msg, pkm_kunit_mldsa65_tcb_hash, SHA256_DIGEST_SIZE);

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_mldsa65_crypto_verify(
				public_key, PKM_KACS_SIGNING_PUBLIC_KEY_LEN,
				msg, SHA256_DIGEST_SIZE, signature,
				PKM_KACS_SIGNING_SIGNATURE_LEN),
			0);

	msg[0] ^= 0x01;
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_mldsa65_crypto_verify(
				public_key, PKM_KACS_SIGNING_PUBLIC_KEY_LEN,
				msg, SHA256_DIGEST_SIZE, signature,
				PKM_KACS_SIGNING_SIGNATURE_LEN),
			-EKEYREJECTED);
	msg[0] ^= 0x01;

	signature[0] ^= 0x01;
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_mldsa65_crypto_verify(
				public_key, PKM_KACS_SIGNING_PUBLIC_KEY_LEN,
				msg, SHA256_DIGEST_SIZE, signature,
				PKM_KACS_SIGNING_SIGNATURE_LEN),
			-EKEYREJECTED);
	signature[0] ^= 0x01;

	public_key[0] ^= 0x01;
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_mldsa65_crypto_verify(
				public_key, PKM_KACS_SIGNING_PUBLIC_KEY_LEN,
				msg, SHA256_DIGEST_SIZE, signature,
				PKM_KACS_SIGNING_SIGNATURE_LEN),
			-EKEYREJECTED);
	public_key[0] ^= 0x01;

	KUNIT_EXPECT_EQ(test,
			pkm_kunit_mldsa65_crypto_verify(
				public_key, PKM_KACS_SIGNING_PUBLIC_KEY_LEN - 1,
				msg, SHA256_DIGEST_SIZE, signature,
				PKM_KACS_SIGNING_SIGNATURE_LEN),
			-EINVAL);
	/*
	 * A short signature is rejected deeper in, by mldsa_verify()'s own
	 * length check, which reports -EBADMSG -- unlike the key-length case
	 * above, which crypto_sig_set_pubkey() rejects with -EINVAL first.
	 */
	KUNIT_EXPECT_EQ(test,
			pkm_kunit_mldsa65_crypto_verify(
				public_key, PKM_KACS_SIGNING_PUBLIC_KEY_LEN,
				msg, SHA256_DIGEST_SIZE, signature,
				PKM_KACS_SIGNING_SIGNATURE_LEN - 1),
			-EBADMSG);

	/* Verifying before a key is set must fail rather than crash. */
	tfm = crypto_alloc_sig("mldsa65", 0, 0);
	KUNIT_ASSERT_FALSE(test, IS_ERR(tfm));
	KUNIT_EXPECT_EQ(test,
			crypto_sig_verify(tfm, signature,
					  PKM_KACS_SIGNING_SIGNATURE_LEN, msg,
					  SHA256_DIGEST_SIZE),
			-EINVAL);
	crypto_free_sig(tfm);
}


static void pkm_kunit_signing_crypto_verify_sets_tcb_trust(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry *keys;
	struct pkm_kacs_kunit_signing_probe *material;
	struct pkm_kacs_kunit_signing_verify_out out = {};

	/*
	 * Heap, not stack: an ML-DSA-65 probe is ~3.3 KiB and each key entry
	 * ~1.9 KiB, which together would blow past CONFIG_FRAME_WARN.
	 */
	keys = kunit_kzalloc(test, 2 * sizeof(*keys), GFP_KERNEL);
	material = kunit_kzalloc(test, sizeof(*material), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, keys);
	KUNIT_ASSERT_NOT_NULL(test, material);

	material->source = PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR;
	memcpy(material->hash, pkm_kunit_mldsa65_tcb_hash,
	       sizeof(material->hash));
	memcpy(material->signature, pkm_kunit_mldsa65_tcb_sig,
	       sizeof(material->signature));
	memcpy(keys[0].public_key, pkm_kunit_mldsa65_pubkey,
	       sizeof(keys[0].public_key));
	keys[0].pip_type = PKM_KUNIT_SIGNING_PIP_PROTECTED;
	keys[0].pip_trust = PKM_KUNIT_SIGNING_TRUST_TCB;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material_crypto(
				material, keys, 2, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 1U);
	KUNIT_EXPECT_EQ(test, out.pip_type,
			PKM_KUNIT_SIGNING_PIP_PROTECTED);
	KUNIT_EXPECT_EQ(test, out.pip_trust, PKM_KUNIT_SIGNING_TRUST_TCB);

	/* A single flipped hash bit must drop the material to untrusted. */
	material->hash[0] ^= 0x01;
	memset(&out, 0, sizeof(out));
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material_crypto(
				material, keys, 2, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_type, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_trust, 0U);
}


static void pkm_kunit_signed_exec_pin_tracks_verified_material(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe *material;
	u32 pinned = 0;
	material = kunit_kzalloc(test, sizeof(*material), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, material);

	pkm_kunit_signing_fill_tcb_vector_material(material);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_signed_exec_pin_from_signing_material(
				material, &pinned),
			0);
	KUNIT_EXPECT_EQ(test, pinned, 1U);

	material->signature[0] ^= 0x01;
	pinned = 1;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_signed_exec_pin_from_signing_material(
				material, &pinned),
			0);
	KUNIT_EXPECT_EQ(test, pinned, 0U);

	material->source = PKM_KACS_KUNIT_SIGNING_SOURCE_NONE;
	pinned = 1;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_signed_exec_pin_from_signing_material(
				material, &pinned),
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
	struct pkm_kacs_kunit_signing_probe *out;
	u8 *sig_blob;

	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);

	pkm_kunit_signing_fill_blob(sig_blob, 0x20);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file) - 1, sig_blob,
				PKM_KUNIT_SIGNING_BLOB_LEN, out),
			0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR);
	KUNIT_EXPECT_EQ(test,
			memcmp(out->signature, sig_blob + 1,
			       PKM_KUNIT_SIGNING_SIG_LEN),
			0);
	KUNIT_EXPECT_EQ(test, memcmp(out->hash, expected_hash,
				     sizeof(expected_hash)),
			0);
}


static void pkm_kunit_signing_short_file_uses_xattr(struct kunit *test)
{
	static const u8 file[] = { 0x7f, 'E', 'L' };
	struct pkm_kacs_kunit_signing_probe *out;
	u8 *sig_blob;

	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);

	pkm_kunit_signing_fill_blob(sig_blob, 0x30);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file), sig_blob, PKM_KUNIT_SIGNING_BLOB_LEN,
				out),
			0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR);
}


static void pkm_kunit_signing_elf_section_zeroes_signature_bytes(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe *out;
	u8 *expected_file;
	u8 expected_hash[32];
	u8 raw_hash[32];
	u8 *sig_blob;
	u8 *file;

	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	expected_file = kunit_kzalloc(test, PKM_KUNIT_ELF_LEN, GFP_KERNEL);
	file = kunit_kzalloc(test, PKM_KUNIT_ELF_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);
	KUNIT_ASSERT_NOT_NULL(test, expected_file);
	KUNIT_ASSERT_NOT_NULL(test, file);

	pkm_kunit_signing_fill_blob(sig_blob, 0x40);
	pkm_kunit_signing_build_elf(file, sig_blob, true, true);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, PKM_KUNIT_ELF_LEN, NULL, 0, out),
			0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_ELF);
	KUNIT_EXPECT_EQ(test,
			memcmp(out->signature, sig_blob + 1,
			       PKM_KUNIT_SIGNING_SIG_LEN),
			0);

	memcpy(expected_file, file, PKM_KUNIT_ELF_LEN);
	memset(expected_file + PKM_KUNIT_ELF_SIG_OFFSET, 0,
	       PKM_KUNIT_SIGNING_BLOB_LEN);
	sha256(expected_file, PKM_KUNIT_ELF_LEN, expected_hash);
	sha256(file, PKM_KUNIT_ELF_LEN, raw_hash);
	KUNIT_EXPECT_EQ(test, memcmp(out->hash, expected_hash,
				     sizeof(expected_hash)),
			0);
	KUNIT_EXPECT_NE(test, memcmp(out->hash, raw_hash, sizeof(raw_hash)), 0);
}


static void pkm_kunit_signing_elf_priority_blocks_xattr_fallback(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe *out;
	u8 *xattr_blob;
	u8 *sig_blob;
	u8 *file;

	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	xattr_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	file = kunit_kzalloc(test, PKM_KUNIT_ELF_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_ASSERT_NOT_NULL(test, xattr_blob);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);
	KUNIT_ASSERT_NOT_NULL(test, file);

	pkm_kunit_signing_fill_blob(sig_blob, 0x50);
	pkm_kunit_signing_fill_blob(xattr_blob, 0x60);
	pkm_kunit_signing_build_elf(file, sig_blob, true, false);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, PKM_KUNIT_ELF_LEN, xattr_blob,
				PKM_KUNIT_SIGNING_BLOB_LEN, out),
			0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_malformed_elf_metadata_blocks_xattr(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe *out;
	u8 *xattr_blob;
	u8 *sig_blob;
	u8 *file;
	Elf64_Shdr shstr = {};
	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	xattr_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	file = kunit_kzalloc(test, PKM_KUNIT_ELF_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_ASSERT_NOT_NULL(test, xattr_blob);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);
	KUNIT_ASSERT_NOT_NULL(test, file);

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
				file, PKM_KUNIT_ELF_LEN, xattr_blob,
				PKM_KUNIT_SIGNING_BLOB_LEN, out),
			0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_elf_without_section_uses_xattr(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe *out;
	u8 *xattr_blob;
	u8 *sig_blob;
	u8 expected_hash[32];
	u8 *file;

	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	xattr_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	file = kunit_kzalloc(test, PKM_KUNIT_ELF_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_ASSERT_NOT_NULL(test, xattr_blob);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);
	KUNIT_ASSERT_NOT_NULL(test, file);

	pkm_kunit_signing_fill_blob(sig_blob, 0x70);
	pkm_kunit_signing_fill_blob(xattr_blob, 0x80);
	pkm_kunit_signing_build_elf(file, sig_blob, false, false);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, PKM_KUNIT_ELF_LEN, xattr_blob,
				PKM_KUNIT_SIGNING_BLOB_LEN, out),
			0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR);
	KUNIT_EXPECT_EQ(test,
			memcmp(out->signature, xattr_blob + 1,
			       PKM_KUNIT_SIGNING_SIG_LEN),
			0);
	sha256(file, PKM_KUNIT_ELF_LEN, expected_hash);
	KUNIT_EXPECT_EQ(test, memcmp(out->hash, expected_hash,
				     sizeof(expected_hash)),
			0);
}


static void pkm_kunit_signing_invalid_xattr_unsigned(struct kunit *test)
{
	static const u8 file[] = "plain";
	struct pkm_kacs_kunit_signing_probe *out;
	u8 *sig_blob;

	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);

	pkm_kunit_signing_fill_blob(sig_blob, 0x90);
	sig_blob[0] = 0x02;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file) - 1, sig_blob,
				PKM_KUNIT_SIGNING_BLOB_LEN, out),
			0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);

	pkm_kunit_signing_fill_blob(sig_blob, 0x90);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, sizeof(file) - 1, sig_blob,
				PKM_KUNIT_SIGNING_BLOB_LEN - 1, out),
			0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_reader_matches_buffer_for_elf(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_reader_args args = {};
	struct pkm_kacs_kunit_signing_probe *reader_out;
	struct pkm_kacs_kunit_signing_probe *buffer_out;
	u8 *sig_blob;
	u8 *file;

	reader_out = kunit_kzalloc(test, sizeof(*reader_out), GFP_KERNEL);
	buffer_out = kunit_kzalloc(test, sizeof(*buffer_out), GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	file = kunit_kzalloc(test, PKM_KUNIT_ELF_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, reader_out);
	KUNIT_ASSERT_NOT_NULL(test, buffer_out);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);
	KUNIT_ASSERT_NOT_NULL(test, file);

	pkm_kunit_signing_fill_blob(sig_blob, 0xc0);
	pkm_kunit_signing_build_elf(file, sig_blob, true, true);
	args.file_bytes = file;
	args.file_len = PKM_KUNIT_ELF_LEN;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_material(
				file, PKM_KUNIT_ELF_LEN, NULL, 0, buffer_out),
			0);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args,
							    reader_out),
			0);
	KUNIT_EXPECT_EQ(test, reader_out->source, buffer_out->source);
	KUNIT_EXPECT_EQ(test,
			memcmp(reader_out->signature, buffer_out->signature,
			       sizeof(reader_out->signature)),
			0);
	KUNIT_EXPECT_EQ(test,
			memcmp(reader_out->hash, buffer_out->hash,
			       sizeof(reader_out->hash)),
			0);
}


static void pkm_kunit_signing_reader_xattr_hashes_non_elf(struct kunit *test)
{
	static const u8 file[] = "reader-file";
	struct pkm_kacs_kunit_signing_reader_args args = {};
	struct pkm_kacs_kunit_signing_probe *out;
	u8 expected_hash[32];
	u8 *sig_blob;

	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);

	pkm_kunit_signing_fill_blob(sig_blob, 0xd0);
	args.file_bytes = file;
	args.file_len = sizeof(file) - 1;
	args.xattr_sig = sig_blob;
	args.xattr_sig_len = PKM_KUNIT_SIGNING_BLOB_LEN;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, out), 0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_XATTR);
	KUNIT_EXPECT_EQ(test,
			memcmp(out->signature, sig_blob + 1,
			       PKM_KUNIT_SIGNING_SIG_LEN),
			0);
	sha256(file, sizeof(file) - 1, expected_hash);
	KUNIT_EXPECT_EQ(test,
			memcmp(out->hash, expected_hash, sizeof(expected_hash)),
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
	struct pkm_kacs_kunit_signing_probe *out;

	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, out), 0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_reader_invalid_xattr_unsigned(
	struct kunit *test)
{
	static const u8 file[] = "reader-invalid-xattr";
	struct pkm_kacs_kunit_signing_reader_args args = {};
	struct pkm_kacs_kunit_signing_probe *out;
	u8 *sig_blob;

	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);

	pkm_kunit_signing_fill_blob(sig_blob, 0xe0);
	args.file_bytes = file;
	args.file_len = sizeof(file) - 1;
	args.xattr_sig = sig_blob;
	args.xattr_sig_len = PKM_KUNIT_SIGNING_BLOB_LEN - 1;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, out), 0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);

	args.xattr_sig_len = PKM_KUNIT_SIGNING_BLOB_LEN;
	sig_blob[0] = 0x02;
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, out), 0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_reader_size_change_invalidates(
	struct kunit *test)
{
	static const u8 file[] = "size-change";
	struct pkm_kacs_kunit_signing_reader_args args = {};
	struct pkm_kacs_kunit_signing_probe *out;
	u8 *sig_blob;

	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);

	pkm_kunit_signing_fill_blob(sig_blob, 0xf0);
	args.file_bytes = file;
	args.file_len = sizeof(file) - 1;
	args.xattr_sig = sig_blob;
	args.xattr_sig_len = PKM_KUNIT_SIGNING_BLOB_LEN;
	args.use_final_file_len = 1;
	args.final_file_len = args.file_len + 1;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, out), 0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_reader_read_failure_invalidates(
	struct kunit *test)
{
	static const u8 file[] = "read-failure";
	struct pkm_kacs_kunit_signing_reader_args args = {};
	struct pkm_kacs_kunit_signing_probe *out;
	u8 *sig_blob;

	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);

	pkm_kunit_signing_fill_blob(sig_blob, 0x10);
	args.file_bytes = file;
	args.file_len = sizeof(file) - 1;
	args.xattr_sig = sig_blob;
	args.xattr_sig_len = PKM_KUNIT_SIGNING_BLOB_LEN;
	args.fail_reads = 1;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, out), 0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_reader_malformed_elf_blocks_xattr(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_reader_args args = {};
	struct pkm_kacs_kunit_signing_probe *out;
	u8 *xattr_blob;
	u8 *sig_blob;
	u8 *file;
	Elf64_Shdr shstr = {};
	out = kunit_kzalloc(test, sizeof(*out), GFP_KERNEL);
	xattr_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	sig_blob = kunit_kzalloc(test, PKM_KUNIT_SIGNING_BLOB_LEN, GFP_KERNEL);
	file = kunit_kzalloc(test, PKM_KUNIT_ELF_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, out);
	KUNIT_ASSERT_NOT_NULL(test, xattr_blob);
	KUNIT_ASSERT_NOT_NULL(test, sig_blob);
	KUNIT_ASSERT_NOT_NULL(test, file);

	pkm_kunit_signing_fill_blob(sig_blob, 0x20);
	pkm_kunit_signing_fill_blob(xattr_blob, 0x30);
	pkm_kunit_signing_build_elf(file, sig_blob, true, true);

	memcpy(&shstr, file + PKM_KUNIT_ELF_SHOFF + sizeof(Elf64_Shdr),
	       sizeof(shstr));
	shstr.sh_offset = PKM_KUNIT_ELF_LEN + 1;
	memcpy(file + PKM_KUNIT_ELF_SHOFF + sizeof(Elf64_Shdr), &shstr,
	       sizeof(shstr));

	args.file_bytes = file;
	args.file_len = PKM_KUNIT_ELF_LEN;
	args.xattr_sig = xattr_blob;
	args.xattr_sig_len = PKM_KUNIT_SIGNING_BLOB_LEN;

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_probe_signing_reader(&args, out), 0);
	KUNIT_EXPECT_EQ(test, out->source,
			PKM_KACS_KUNIT_SIGNING_SOURCE_NONE);
}


static void pkm_kunit_signing_verify_unsigned_has_no_trust(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_probe *material;
	struct pkm_kacs_kunit_signing_verify_out out = {};
	material = kunit_kzalloc(test, sizeof(*material), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, material);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				material, NULL, 0, 0, 0, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_type, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_trust, 0U);
}


static void pkm_kunit_signing_verify_first_key_sets_tcb_trust(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry *keys;
	struct pkm_kacs_kunit_signing_probe *material;
	struct pkm_kacs_kunit_signing_verify_out out = {};
	material = kunit_kzalloc(test, sizeof(*material), GFP_KERNEL);
	keys = kunit_kzalloc(test, 2 * sizeof(*keys), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, material);
	KUNIT_ASSERT_NOT_NULL(test, keys);

	pkm_kunit_signing_fill_probe(material);
	pkm_kunit_signing_fill_key(&keys[0], 0x10,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				material, keys, 2, 0, 1,
				&out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 1U);
	KUNIT_EXPECT_EQ(test, out.pip_type,
			PKM_KUNIT_SIGNING_PIP_PROTECTED);
	KUNIT_EXPECT_EQ(test, out.pip_trust, PKM_KUNIT_SIGNING_TRUST_TCB);
}


static void pkm_kunit_signing_unverifiable_is_not_unsigned(struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry *keys;
	struct pkm_kacs_kunit_signing_probe *material;
	struct pkm_kacs_kunit_signing_verify_out out = {};

	material = kunit_kzalloc(test, sizeof(*material), GFP_KERNEL);
	keys = kunit_kzalloc(test, 2 * sizeof(*keys), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, material);
	KUNIT_ASSERT_NOT_NULL(test, keys);

	pkm_kunit_signing_fill_probe(material);
	pkm_kunit_signing_fill_key(&keys[0], 0x10,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	/*
	 * The key matches, so without the tri-state this would verify. A
	 * verifier that cannot perform the check must not be able to produce
	 * either answer: it propagates its errno instead.
	 *
	 * This is the whole point of the change. "Could not verify" folded
	 * into "did not verify" made a missing ML-DSA transform look exactly
	 * like an unsigned binary, and an unsigned binary just runs with no
	 * integrity label -- so PIP would disappear system-wide with nothing
	 * to distinguish it from a working system that has nothing signed.
	 */
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_verify_signing_material_unavailable(
				material, keys, 2, -ENOENT),
			-ENOENT);

	/* The same table, verifiable, still reports the match. */
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				material, keys, 2, 0, 1, &out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 1U);

	/* A transient allocation failure is reported the same way. */
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_verify_signing_material_unavailable(
				material, keys, 2, -ENOMEM),
			-ENOMEM);
}


static void pkm_kunit_signing_crypto_transform_is_available(struct kunit *test)
{
	/*
	 * The boot-time announcement rests on this being answerable at all.
	 * If mldsa65 ever stops being reachable from a PKM kernel, every
	 * signed exec is refused, and this is the case that says so directly
	 * rather than through a hundred downstream failures.
	 */
	KUNIT_EXPECT_EQ(test, pkm_kacs_signing_crypto_probe(), 0);
}


static void pkm_kunit_signing_verify_later_key_after_miss(struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry *keys;
	struct pkm_kacs_kunit_signing_probe *material;
	struct pkm_kacs_kunit_signing_verify_out out = {};
	material = kunit_kzalloc(test, sizeof(*material), GFP_KERNEL);
	keys = kunit_kzalloc(test, 3 * sizeof(*keys), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, material);
	KUNIT_ASSERT_NOT_NULL(test, keys);

	pkm_kunit_signing_fill_probe(material);
	pkm_kunit_signing_fill_key(&keys[0], 0x20,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);
	pkm_kunit_signing_fill_key(&keys[1], 0x40,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				material, keys, 3, 1, 1,
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
	struct pkm_kacs_kunit_signing_key_entry *keys;
	struct pkm_kacs_kunit_signing_probe *material;
	struct pkm_kacs_kunit_signing_verify_out out = {};
	material = kunit_kzalloc(test, sizeof(*material), GFP_KERNEL);
	keys = kunit_kzalloc(test, 2 * sizeof(*keys), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, material);
	KUNIT_ASSERT_NOT_NULL(test, keys);

	pkm_kunit_signing_fill_probe(material);
	pkm_kunit_signing_fill_key(&keys[0], 0x50,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				material, keys, 2, 0, 0,
				&out),
			0);
	KUNIT_EXPECT_EQ(test, out.verified, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_type, 0U);
	KUNIT_EXPECT_EQ(test, out.pip_trust, 0U);
}


static void pkm_kunit_signing_verify_unsupported_tier_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry *keys;
	struct pkm_kacs_kunit_signing_probe *material;
	struct pkm_kacs_kunit_signing_verify_out out = {};
	material = kunit_kzalloc(test, sizeof(*material), GFP_KERNEL);
	keys = kunit_kzalloc(test, 2 * sizeof(*keys), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, material);
	KUNIT_ASSERT_NOT_NULL(test, keys);

	pkm_kunit_signing_fill_probe(material);
	pkm_kunit_signing_fill_key(&keys[0], 0x60, 1024U,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				material, keys, 2, 0, 1,
				&out),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, out.verified, 0U);
}


static void pkm_kunit_signing_verify_missing_terminator_fails_closed(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry *keys;
	struct pkm_kacs_kunit_signing_probe *material;
	struct pkm_kacs_kunit_signing_verify_out out = {};
	material = kunit_kzalloc(test, sizeof(*material), GFP_KERNEL);
	keys = kunit_kzalloc(test, 1 * sizeof(*keys), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, material);
	KUNIT_ASSERT_NOT_NULL(test, keys);

	pkm_kunit_signing_fill_probe(material);
	pkm_kunit_signing_fill_key(&keys[0], 0x70,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				material, keys, 1, 0, 1,
				&out),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, out.verified, 0U);
}


static void pkm_kunit_signing_verify_terminator_stops_iteration(
	struct kunit *test)
{
	struct pkm_kacs_kunit_signing_key_entry *keys;
	struct pkm_kacs_kunit_signing_probe *material;
	struct pkm_kacs_kunit_signing_verify_out out = {};
	material = kunit_kzalloc(test, sizeof(*material), GFP_KERNEL);
	keys = kunit_kzalloc(test, 3 * sizeof(*keys), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, material);
	KUNIT_ASSERT_NOT_NULL(test, keys);

	pkm_kunit_signing_fill_probe(material);
	pkm_kunit_signing_fill_key(&keys[1], 0x80,
				   PKM_KUNIT_SIGNING_PIP_PROTECTED,
				   PKM_KUNIT_SIGNING_TRUST_TCB);

	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_verify_signing_material(
				material, keys, 3, 1, 1,
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

/*
 * Firmware verdict (firmware.c, PEI-493): only a signature verified at the
 * PeiosTcb tier allows; every other outcome -- unsigned, no key, a lower
 * tier, and crucially "could not verify" -- refuses under enforce and is
 * reported but allowed under log. Table-driven so the two modes are
 * checked against the same reasons.
 */
static void pkm_kunit_firmware_verdict_requires_tcb(struct kunit *test)
{
	const struct pkm_kacs_signing_trust_result tcb = {
		.verified = 1, .pip_type = PKM_KUNIT_SIGNING_PIP_PROTECTED,
		.pip_trust = PKM_KUNIT_SIGNING_TRUST_TCB,
	};
	const struct pkm_kacs_signing_trust_result low = {
		.verified = 1, .pip_type = PKM_KUNIT_SIGNING_PIP_PROTECTED,
		.pip_trust = PKM_KUNIT_PIP_TRUST_TEST,
	};
	const struct pkm_kacs_signing_trust_result unverified = {};
	const struct {
		int probe_ret;
		u32 source;
		int verify_ret;
		const struct pkm_kacs_signing_trust_result *result;
		u8 reason;
	} cases[] = {
		{ 0, PKM_KACS_SIGNING_SOURCE_XATTR, 0, &tcb,
		  KACS_FW_ALLOWED },
		{ 0, PKM_KACS_SIGNING_SOURCE_ELF, 0, &tcb,
		  KACS_FW_ALLOWED },
		{ 0, PKM_KACS_SIGNING_SOURCE_NONE, 0, &unverified,
		  KACS_FW_UNSIGNED },
		{ 0, PKM_KACS_SIGNING_SOURCE_XATTR, 0, &unverified,
		  KACS_FW_NO_KEY_MATCH },
		{ 0, PKM_KACS_SIGNING_SOURCE_XATTR, 0, &low,
		  KACS_FW_BELOW_TCB },
		{ 0, PKM_KACS_SIGNING_SOURCE_XATTR, -ENOENT, &tcb,
		  KACS_FW_UNVERIFIABLE },
		{ 0, PKM_KACS_SIGNING_SOURCE_XATTR, 0, NULL,
		  KACS_FW_UNVERIFIABLE },
		{ -EIO, PKM_KACS_SIGNING_SOURCE_NONE, 0, &tcb,
		  KACS_FW_PROBE_FAILED },
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		int expect = cases[i].reason == KACS_FW_ALLOWED ? 0 : -EPERM;
		u8 reason = 0xff;

		KUNIT_EXPECT_EQ_MSG(test,
				    pkm_kacs_firmware_verdict(
					    cases[i].probe_ret, cases[i].source,
					    cases[i].verify_ret,
					    cases[i].result, true, &reason),
				    expect, "case %zu enforce", i);
		KUNIT_EXPECT_EQ_MSG(test, reason, cases[i].reason,
				    "case %zu enforce reason", i);

		reason = 0xff;
		KUNIT_EXPECT_EQ_MSG(test,
				    pkm_kacs_firmware_verdict(
					    cases[i].probe_ret, cases[i].source,
					    cases[i].verify_ret,
					    cases[i].result, false, &reason),
				    0, "case %zu log", i);
		KUNIT_EXPECT_EQ_MSG(test, reason, cases[i].reason,
				    "case %zu log reason", i);
	}

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_firmware_verdict(0, PKM_KACS_SIGNING_SOURCE_XATTR,
						  0, &tcb, true, NULL),
			-EINVAL);
}

static struct kunit_case pkm_kunit_signing_cases[] = {
	KUNIT_CASE(pkm_kunit_boot_system_defaults),
	KUNIT_CASE(pkm_kunit_boot_anonymous_defaults),
	KUNIT_CASE(pkm_kunit_boot_logon_session_registered),
	KUNIT_CASE(pkm_kunit_boot_allow_caps),
	KUNIT_CASE(pkm_kunit_blob_lifecycle_defaults),
	KUNIT_CASE(pkm_kunit_mldsa65_crypto_fips204_vectors),
	KUNIT_CASE(pkm_kunit_mldsa65_crypto_rejects_bad_inputs),
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
	KUNIT_CASE(pkm_kunit_signing_unverifiable_is_not_unsigned),
	KUNIT_CASE(pkm_kunit_signing_crypto_transform_is_available),
	KUNIT_CASE(pkm_kunit_signing_verify_later_key_after_miss),
	KUNIT_CASE(pkm_kunit_signing_verify_no_matching_key_unsigned),
	KUNIT_CASE(pkm_kunit_signing_verify_unsupported_tier_fails_closed),
	KUNIT_CASE(pkm_kunit_signing_verify_missing_terminator_fails_closed),
	KUNIT_CASE(pkm_kunit_signing_verify_terminator_stops_iteration),
	KUNIT_CASE(pkm_kunit_builtin_signing_key_table_has_one_tcb_key),
	KUNIT_CASE(pkm_kunit_firmware_verdict_requires_tcb),
	{}
};

static struct kunit_suite pkm_kunit_signing_suite = {
	.name = "pkm_kunit_signing",
	.test_cases = pkm_kunit_signing_cases,
};

kunit_test_suite(pkm_kunit_signing_suite);
