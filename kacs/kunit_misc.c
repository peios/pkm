// SPDX-License-Identifier: GPL-2.0-only

#include "kunit_common.h"
#include "lsm_internal.h"
#include "capability.h"
#include "socket.h"

#include <linux/in.h>
#include <linux/in6.h>
#include <pkm/net.h>
#include <linux/kacs_stratafs.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/user_namespace.h>
#include "cred_lifecycle.h"
#include "file_access.h"


static void pkm_kunit_probe_smoke(struct kunit *test)
{
	size_t probe;

	probe = kacs_rust_kunit_probe();
	KUNIT_ASSERT_GT(test, probe, (size_t)0);

	pr_info("pkm: kunit scaffold smoke passed\n");
}


static void pkm_kunit_live_capable_sys_boot_uses_shutdown_privilege(
	struct kunit *test)
{
	const void *token;
	struct pkm_kacs_boot_snapshot before = { };
	struct pkm_kacs_boot_snapshot after = { };

	token = pkm_kacs_current_effective_token_ptr();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_TRUE(test,
			  kacs_rust_kunit_token_snapshot(token, &before));

	KUNIT_EXPECT_TRUE(test, capable(CAP_SYS_BOOT));

	KUNIT_ASSERT_TRUE(test, kacs_rust_kunit_token_snapshot(token, &after));
	KUNIT_EXPECT_EQ(test,
			after.privileges_used,
			before.privileges_used |
				PKM_KUNIT_SE_SHUTDOWN_PRIVILEGE);
}


static void pkm_kunit_internal_file_access_sees_device_groups(
	struct kunit *test)
{
	struct pkm_kacs_token_fd_view with_device = { };
	struct pkm_kacs_token_fd_view without_device = { };
	const u8 *file_sd;
	size_t file_sd_len = 0;
	long with_fd;
	long without_fd;
	u32 granted = 0;

	with_fd = pkm_kunit_create_device_condition_token(true, &with_device);
	KUNIT_ASSERT_GE(test, with_fd, 0L);
	without_fd = pkm_kunit_create_device_condition_token(false,
							     &without_device);
	KUNIT_ASSERT_GE(test, without_fd, 0L);

	file_sd = kacs_rust_kunit_create_device_member_file_sd(
		with_device.token, pkm_kunit_everyone_sid,
		sizeof(pkm_kunit_everyone_sid), PKM_KUNIT_FILE_READ_DATA,
		&file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);

	KUNIT_EXPECT_EQ(test,
			kacs_rust_check_file_sd_with_intent(
				with_device.token, file_sd, file_sd_len,
				PKM_KUNIT_FILE_READ_DATA, 0, 0, 0, &granted),
			0);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_FILE_READ_DATA);

	granted = 0;
	KUNIT_EXPECT_EQ(test,
			kacs_rust_check_file_sd_with_intent(
				without_device.token, file_sd, file_sd_len,
				PKM_KUNIT_FILE_READ_DATA, 0, 0, 0, &granted),
			-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	pkm_kacs_free((void *)file_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)without_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)with_fd), 0);
}


static void pkm_kunit_internal_file_access_uses_restricted_device_groups(
	struct kunit *test)
{
	static const struct pkm_kunit_sid_attr_spec restricted_sids[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	static const struct pkm_kunit_sid_attr_spec restricted_match[] = {
		{
			.sid = pkm_kunit_everyone_sid,
			.sid_len = sizeof(pkm_kunit_everyone_sid),
			.attributes = PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	static const struct pkm_kunit_sid_attr_spec restricted_mismatch[] = {
		{
			.sid = pkm_kunit_authenticated_users_sid,
			.sid_len = sizeof(pkm_kunit_authenticated_users_sid),
			.attributes = PKM_KUNIT_SE_GROUP_ENABLED,
		},
	};
	struct pkm_kacs_token_fd_view matching = { };
	struct pkm_kacs_token_fd_view mismatching = { };
	const u8 *file_sd;
	size_t file_sd_len = 0;
	long matching_fd;
	long mismatching_fd;
	u32 granted = 0;

	matching_fd = pkm_kunit_create_condition_token_ex(
		true, false, false, restricted_sids, ARRAY_SIZE(restricted_sids),
		restricted_match,
		ARRAY_SIZE(restricted_match), &matching);
	KUNIT_ASSERT_GE(test, matching_fd, 0L);
	mismatching_fd = pkm_kunit_create_condition_token_ex(
		true, false, false, restricted_sids, ARRAY_SIZE(restricted_sids),
		restricted_mismatch,
		ARRAY_SIZE(restricted_mismatch), &mismatching);
	KUNIT_ASSERT_GE(test, mismatching_fd, 0L);

	file_sd = kacs_rust_kunit_create_device_member_file_sd(
		matching.token, pkm_kunit_everyone_sid,
		sizeof(pkm_kunit_everyone_sid), PKM_KUNIT_FILE_READ_DATA,
		&file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);

	KUNIT_EXPECT_EQ(test,
			kacs_rust_check_file_sd_with_intent(
				matching.token, file_sd, file_sd_len,
				PKM_KUNIT_FILE_READ_DATA, 0, 0, 0, &granted),
			0);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_FILE_READ_DATA);

	granted = 0;
	KUNIT_EXPECT_EQ(test,
			kacs_rust_check_file_sd_with_intent(
				mismatching.token, file_sd, file_sd_len,
				PKM_KUNIT_FILE_READ_DATA, 0, 0, 0, &granted),
			-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	pkm_kacs_free((void *)file_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)mismatching_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)matching_fd), 0);
}


static void pkm_kunit_internal_file_access_sees_token_claims(
	struct kunit *test)
{
	static const u8 claim_name[] = "KacsGate";
	struct pkm_kacs_token_fd_view with_user_claim = { };
	struct pkm_kacs_token_fd_view with_device_claim = { };
	struct pkm_kacs_token_fd_view without_claim = { };
	const u8 *file_sd;
	size_t file_sd_len = 0;
	long with_user_fd;
	long with_device_fd;
	long without_fd;
	u32 granted = 0;

	with_user_fd = pkm_kunit_create_condition_token(
		false, true, false, NULL, 0, &with_user_claim);
	KUNIT_ASSERT_GE(test, with_user_fd, 0L);
	with_device_fd = pkm_kunit_create_condition_token(
		false, false, true, NULL, 0, &with_device_claim);
	KUNIT_ASSERT_GE(test, with_device_fd, 0L);
	without_fd = pkm_kunit_create_condition_token(
		false, false, false, NULL, 0, &without_claim);
	KUNIT_ASSERT_GE(test, without_fd, 0L);

	file_sd = kacs_rust_kunit_create_claim_exists_file_sd(
		with_user_claim.token, PKM_KUNIT_COND_USER_CLAIM, claim_name,
		sizeof(claim_name) - 1U, PKM_KUNIT_FILE_READ_DATA,
		&file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);

	KUNIT_EXPECT_EQ(test,
			kacs_rust_check_file_sd_with_intent(
				with_user_claim.token, file_sd, file_sd_len,
				PKM_KUNIT_FILE_READ_DATA, 0, 0, 0, &granted),
			0);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_FILE_READ_DATA);

	granted = 0;
	KUNIT_EXPECT_EQ(test,
			kacs_rust_check_file_sd_with_intent(
				without_claim.token, file_sd, file_sd_len,
				PKM_KUNIT_FILE_READ_DATA, 0, 0, 0, &granted),
			-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);
	pkm_kacs_free((void *)file_sd);

	file_sd = kacs_rust_kunit_create_claim_exists_file_sd(
		with_device_claim.token, PKM_KUNIT_COND_DEVICE_CLAIM,
		claim_name, sizeof(claim_name) - 1U,
		PKM_KUNIT_FILE_READ_DATA, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);

	granted = 0;
	KUNIT_EXPECT_EQ(test,
			kacs_rust_check_file_sd_with_intent(
				with_device_claim.token, file_sd, file_sd_len,
				PKM_KUNIT_FILE_READ_DATA, 0, 0, 0, &granted),
			0);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_FILE_READ_DATA);

	granted = 0;
	KUNIT_EXPECT_EQ(test,
			kacs_rust_check_file_sd_with_intent(
				without_claim.token, file_sd, file_sd_len,
				PKM_KUNIT_FILE_READ_DATA, 0, 0, 0, &granted),
			-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	pkm_kacs_free((void *)file_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)without_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)with_device_fd), 0);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)with_user_fd), 0);
}


static void pkm_kunit_internal_file_access_sees_resource_claims(
	struct kunit *test)
{
	static const u8 claim_name[] = "Mandatory";
	struct pkm_kacs_token_fd_view subject = { };
	const u8 *file_sd;
	size_t file_sd_len = 0;
	long subject_fd;
	u32 granted = 0;

	subject_fd = pkm_kunit_create_condition_token(false, false, false,
						      NULL, 0, &subject);
	KUNIT_ASSERT_GE(test, subject_fd, 0L);

	file_sd = kacs_rust_kunit_create_resource_claim_exists_file_sd(
		subject.token, claim_name, sizeof(claim_name) - 1U,
		PKM_KUNIT_FILE_READ_DATA, &file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);

	KUNIT_EXPECT_EQ(test,
			kacs_rust_check_file_sd_with_intent(
				subject.token, file_sd, file_sd_len,
				PKM_KUNIT_FILE_READ_DATA, 0, 0, 0, &granted),
			0);
	KUNIT_EXPECT_EQ(test, granted, PKM_KUNIT_FILE_READ_DATA);
	pkm_kacs_free((void *)file_sd);

	file_sd = kacs_rust_kunit_create_claim_exists_file_sd(
		subject.token, PKM_KUNIT_COND_RESOURCE_CLAIM, claim_name,
		sizeof(claim_name) - 1U, PKM_KUNIT_FILE_READ_DATA,
		&file_sd_len);
	KUNIT_ASSERT_NOT_NULL(test, file_sd);

	granted = 0;
	KUNIT_EXPECT_EQ(test,
			kacs_rust_check_file_sd_with_intent(
				subject.token, file_sd, file_sd_len,
				PKM_KUNIT_FILE_READ_DATA, 0, 0, 0, &granted),
			-EACCES);
	KUNIT_EXPECT_EQ(test, granted, 0U);

	pkm_kacs_free((void *)file_sd);
	KUNIT_EXPECT_EQ(test, close_fd((unsigned int)subject_fd), 0);
}


static void pkm_kunit_lcs_private_credentials_accessors(struct kunit *test)
{
	static const u8 scopes[2][KACS_LCS_SCOPE_GUID_BYTES] = {
		{ 0x10, 0x11, 0x12, 0x13 },
		{ 0x20, 0x21, 0x22, 0x23 },
	};
	static const char layer[] = "role-service";
	u8 copied[KACS_LCS_SCOPE_GUID_BYTES] = { };
	const char *name = NULL;
	const void *token;
	u32 name_len = 0;

	token = kacs_rust_kunit_create_lcs_private_credential_token(
		scopes, ARRAY_SIZE(scopes), layer, strlen(layer));
	KUNIT_ASSERT_NOT_NULL(test, token);

	KUNIT_EXPECT_EQ(test, kacs_rust_token_lcs_scope_guid_count(token),
			(u32)ARRAY_SIZE(scopes));
	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_lcs_scope_guid(token, 1, copied),
			0);
	KUNIT_EXPECT_MEMEQ(test, copied, scopes[1], sizeof(copied));
	KUNIT_EXPECT_EQ(test,
			kacs_rust_token_lcs_scope_guid(token, 2, copied),
			-EINVAL);

	KUNIT_EXPECT_EQ(test,
			kacs_rust_token_lcs_private_layer_count(token), 1U);
	KUNIT_ASSERT_EQ(test,
			kacs_rust_token_lcs_private_layer(token, 0, &name,
							  &name_len),
			0);
	KUNIT_ASSERT_NOT_NULL(test, name);
	KUNIT_EXPECT_EQ(test, name_len, (u32)strlen(layer));
	KUNIT_EXPECT_MEMEQ(test, name, layer, strlen(layer));
	KUNIT_EXPECT_EQ(test,
			kacs_rust_token_lcs_private_layer(token, 1, &name,
							  &name_len),
			-EINVAL);

	kacs_rust_token_drop(token);
}


/*
 * Port reservations (<pkm/net.h>): the inet socket_bind path against the
 * compiled-in fallback, a published table, and a rejected table. The KUnit
 * context runs as SYSTEM, which is exactly who the fallback admits.
 */

struct pkm_kunit_port_fixture {
	struct sock sk;
	struct socket sock;
	void *blob;
};

static int pkm_kunit_port_fixture_init(struct kunit *test,
				       struct pkm_kunit_port_fixture *f,
				       u16 family, u16 protocol)
{
	memset(f, 0, sizeof(*f));
	f->blob = kzalloc(pkm_blob_sizes.lbs_sock +
				  sizeof(struct pkm_kacs_socket_security),
			  GFP_KERNEL);
	if (!f->blob)
		return -ENOMEM;
	f->sk.sk_security = f->blob;
	f->sk.sk_family = family;
	f->sk.sk_protocol = protocol;
	f->sock.sk = &f->sk;
	f->sock.type = protocol == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM;
	f->sock.state = SS_UNCONNECTED;
	return pkm_kacs_sk_alloc_security(&f->sk, family, GFP_KERNEL);
}

static void pkm_kunit_port_fixture_exit(struct pkm_kunit_port_fixture *f)
{
	pkm_kacs_sk_free_security(&f->sk);
	kfree(f->blob);
}

static int pkm_kunit_port_bind4(struct pkm_kunit_port_fixture *f, u16 port)
{
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};

	return pkm_kacs_socket_bind(&f->sock, (struct sockaddr *)&sin,
				    sizeof(sin));
}

static int pkm_kunit_port_bind6(struct pkm_kunit_port_fixture *f, u16 port)
{
	struct sockaddr_in6 sin6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
	};

	return pkm_kacs_socket_bind(&f->sock, (struct sockaddr *)&sin6,
				    sizeof(sin6));
}

/* Appends one (name, sd) value to a serialised table blob. */
static size_t pkm_kunit_port_blob_append(u8 *blob, size_t at, const char *name,
					 const u8 *sd, size_t sd_len)
{
	u16 name_len = strlen(name);
	u32 len32 = sd_len;

	memcpy(blob + at, &name_len, 2);
	at += 2;
	memcpy(blob + at, name, name_len);
	at += name_len;
	memcpy(blob + at, &len32, 4);
	at += 4;
	memcpy(blob + at, sd, sd_len);
	return at + sd_len;
}

/*
 * The fallback SD with its one ACE removed: owner/group SYSTEM, DACL present
 * and empty — grants nobody anything. 20 header + 12 + 12 + 8 ACL header.
 */
static size_t pkm_kunit_port_empty_dacl_sd(u8 *out, size_t cap)
{
	const u8 *fallback;
	size_t fallback_len;

	fallback = kacs_rust_port_fallback_sd(&fallback_len);
	if (!fallback || fallback_len < 52 || cap < 52)
		return 0;
	memcpy(out, fallback, 52);
	out[44 + 2] = 8;	/* acl size lo */
	out[44 + 3] = 0;
	out[44 + 4] = 0;	/* ace count lo */
	out[44 + 5] = 0;
	return 52;
}

static void pkm_kunit_port_fallback_admits_system_only_shape(struct kunit *test)
{
	struct pkm_kunit_port_fixture tcp, udp, six;
	const u8 *fallback;
	size_t fallback_len = 0;

	KUNIT_ASSERT_EQ(test, kacs_rust_port_table_reset(), 0);
	KUNIT_EXPECT_FALSE(test, kacs_rust_port_table_loaded());
	fallback = kacs_rust_port_fallback_sd(&fallback_len);
	KUNIT_ASSERT_NOT_NULL(test, fallback);
	KUNIT_EXPECT_EQ(test, fallback_len, (size_t)72);

	KUNIT_ASSERT_EQ(test, pkm_kunit_port_fixture_init(test, &tcp, AF_INET,
							  IPPROTO_TCP), 0);
	KUNIT_ASSERT_EQ(test, pkm_kunit_port_fixture_init(test, &udp, AF_INET,
							  IPPROTO_UDP), 0);
	KUNIT_ASSERT_EQ(test, pkm_kunit_port_fixture_init(test, &six, AF_INET6,
							  IPPROTO_TCP), 0);

	/* SYSTEM may claim anything under the fallback. */
	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind4(&tcp, 80), 0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind4(&tcp, 65535), 0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind4(&udp, 53), 0);
	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind6(&six, 443), 0);
	/* A permitted bind records the binder. */
	KUNIT_EXPECT_NOT_NULL(test, pkm_kacs_sock(&tcp.sk)->binder_token);
	/* Port 0 is never checked and records nothing. */
	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind4(&udp, 0), 0);

	pkm_kunit_port_fixture_exit(&tcp);
	pkm_kunit_port_fixture_exit(&udp);
	pkm_kunit_port_fixture_exit(&six);
}

static void pkm_kunit_port_published_table_decides(struct kunit *test)
{
	struct pkm_kunit_port_fixture tcp, udp, six;
	const u8 *fallback;
	size_t fallback_len = 0;
	u8 empty[64];
	size_t empty_len;
	u8 *blob;
	size_t at = 0;

	fallback = kacs_rust_port_fallback_sd(&fallback_len);
	KUNIT_ASSERT_NOT_NULL(test, fallback);
	empty_len = pkm_kunit_port_empty_dacl_sd(empty, sizeof(empty));
	KUNIT_ASSERT_EQ(test, empty_len, (size_t)52);

	blob = kzalloc(512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, blob);
	/* @ -> fallback (SYSTEM), tcp:80 -> nobody, udp:1-1023 -> nobody. */
	at = pkm_kunit_port_blob_append(blob, at, "@", fallback, fallback_len);
	at = pkm_kunit_port_blob_append(blob, at, "tcp:80", empty, empty_len);
	at = pkm_kunit_port_blob_append(blob, at, "udp:1-1023", empty,
					empty_len);
	KUNIT_ASSERT_EQ(test, kacs_rust_port_table_replace(blob, at), 0);
	KUNIT_EXPECT_TRUE(test, kacs_rust_port_table_loaded());

	KUNIT_ASSERT_EQ(test, pkm_kunit_port_fixture_init(test, &tcp, AF_INET,
							  IPPROTO_TCP), 0);
	KUNIT_ASSERT_EQ(test, pkm_kunit_port_fixture_init(test, &udp, AF_INET,
							  IPPROTO_UDP), 0);
	KUNIT_ASSERT_EQ(test, pkm_kunit_port_fixture_init(test, &six, AF_INET6,
							  IPPROTO_TCP), 0);

	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind4(&tcp, 80), -EACCES);
	KUNIT_EXPECT_NULL(test, pkm_kacs_sock(&tcp.sk)->binder_token);
	/* Same port, other family: the selector has no address family. */
	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind6(&six, 80), -EACCES);
	/* Same port, other protocol: only tcp:80 is reserved. */
	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind4(&udp, 80), -EACCES);
	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind4(&udp, 1024), 0);
	/* Neighbouring port falls to the default. */
	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind4(&tcp, 81), 0);
	KUNIT_EXPECT_NOT_NULL(test, pkm_kacs_sock(&tcp.sk)->binder_token);

	/* A malformed publish leaves the live table in place. */
	KUNIT_EXPECT_EQ(test, kacs_rust_port_table_replace(blob, at - 3),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, kacs_rust_port_table_replace(NULL, 0), -EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind4(&tcp, 80), -EACCES);

	/* No default value: rejected whole. */
	at = pkm_kunit_port_blob_append(blob, 0, "tcp:80", empty, empty_len);
	KUNIT_EXPECT_EQ(test, kacs_rust_port_table_replace(blob, at), -EINVAL);
	/* Equal-width overlap: rejected whole. */
	at = pkm_kunit_port_blob_append(blob, 0, "@", fallback, fallback_len);
	at = pkm_kunit_port_blob_append(blob, at, "tcp:80", empty, empty_len);
	at = pkm_kunit_port_blob_append(blob, at, "*:80", empty, empty_len);
	KUNIT_EXPECT_EQ(test, kacs_rust_port_table_replace(blob, at), -EINVAL);
	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind4(&tcp, 80), -EACCES);

	/* Reset: the fallback answers again, never merged. */
	KUNIT_ASSERT_EQ(test, kacs_rust_port_table_reset(), 0);
	KUNIT_EXPECT_FALSE(test, kacs_rust_port_table_loaded());
	KUNIT_EXPECT_EQ(test, pkm_kunit_port_bind4(&tcp, 80), 0);

	pkm_kunit_port_fixture_exit(&tcp);
	pkm_kunit_port_fixture_exit(&udp);
	pkm_kunit_port_fixture_exit(&six);
	kfree(blob);
}

static void pkm_kunit_net_bind_service_is_allow(struct kunit *test)
{
	/* The Linux privileged-port floor never refuses; the SD decides. */
	KUNIT_EXPECT_TRUE(test, capable(CAP_NET_BIND_SERVICE));
	KUNIT_EXPECT_NE(test,
			pkm_kacs_allow_cap_mask_u64() &
				(1ULL << CAP_NET_BIND_SERVICE),
			0ULL);
}


/*
 * Section 3.2: kernel-originated work running under the boot credential
 * evaluates as SYSTEM.  The KUnit runner is such work -- a kernel thread on
 * the boot credential -- and every evaluation it makes answers as SYSTEM.
 */
static void pkm_kunit_kernel_work_evaluates_as_system(struct kunit *test)
{
	const void *token = pkm_kacs_current_effective_token_ptr();
	const u8 *sid = NULL;
	size_t sid_len = 0;

	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_EXPECT_NE(test, current->flags & PF_KTHREAD, 0U);
	KUNIT_ASSERT_EQ(test, kacs_rust_token_user_sid(token, &sid, &sid_len), 0);
	KUNIT_EXPECT_EQ(test, sid_len, (size_t)sizeof(pkm_kunit_system_sid));
	if (sid_len == sizeof(pkm_kunit_system_sid))
		KUNIT_EXPECT_MEMEQ(test, sid, pkm_kunit_system_sid,
				   sizeof(pkm_kunit_system_sid));
	/* A privilege gate and the capability path both answer for SYSTEM. */
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_check_capability_for_token(token, CAP_SYS_TIME),
			0L);
	KUNIT_EXPECT_TRUE(test, capable(CAP_SYS_TIME));
}

/*
 * Section 3.2: the credential installed by override_creds() is authoritative.
 * The task is the same kernel thread throughout; only its subjective
 * credential changes, and every evaluation follows that credential -- not the
 * real one, and not the thread's worker flag.
 */
static void pkm_kunit_override_creds_credential_is_authoritative(
	struct kunit *test)
{
	const void *boot = pkm_kacs_current_effective_token_ptr();
	struct pkm_kacs_cred_security *sec;
	const struct cred *saved;
	struct cred *cred;
	const void *token;

	KUNIT_ASSERT_NOT_NULL(test, boot);
	KUNIT_ASSERT_TRUE(test, capable(CAP_SYS_BOOT));
	token = kacs_rust_kunit_create_adjustable_privileges_token();
	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_FALSE(test,
		kacs_rust_token_has_enabled_privilege(
			token, KACS_SE_SHUTDOWN_PRIVILEGE));
	cred = prepare_creds();
	if (!cred) {
		kacs_rust_token_drop(token);
		KUNIT_FAIL(test, "prepare_creds failed");
		return;
	}
	sec = pkm_kacs_cred(cred);
	if (sec->token)
		kacs_rust_token_drop(sec->token);
	sec->token = token;
	pkm_kacs_stamp_projected_ids(sec);

	saved = override_creds(cred);
	KUNIT_EXPECT_NE(test, current->flags & PF_KTHREAD, 0U);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(), token);
	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_primary_token_ptr(), boot);
	/* What the boot token could do, this credential cannot. */
	KUNIT_EXPECT_FALSE(test, capable(CAP_SYS_BOOT));
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_check_capability_for_token(
				pkm_kacs_current_effective_token_ptr(),
				CAP_SYS_BOOT),
			(long)-EPERM);
	revert_creds(saved);
	abort_creds(cred);

	KUNIT_EXPECT_PTR_EQ(test, pkm_kacs_current_effective_token_ptr(), boot);
	KUNIT_EXPECT_TRUE(test, capable(CAP_SYS_BOOT));
}

/*
 * Section 3.4: recording a privilege as used is part of the operation.  With
 * the recorder made to fail, every gate refuses the operation it was
 * admitting a moment before.
 */
static void pkm_kunit_privilege_use_record_failure_fails_the_gate(
	struct kunit *test)
{
	const void *token = pkm_kacs_current_effective_token_ptr();

	KUNIT_ASSERT_NOT_NULL(test, token);
	KUNIT_ASSERT_EQ(test,
			pkm_kacs_kunit_check_capability_for_subject(token,
								    CAP_SYS_TIME),
			0L);
	KUNIT_ASSERT_TRUE(test,
			  pkm_kacs_kunit_may_manage_volumes_for_subject(token));

	pkm_kacs_kunit_set_fail_mark_privileges_used(true);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capability_for_subject(token,
								    CAP_SYS_TIME),
			(long)-EPERM);
	KUNIT_EXPECT_FALSE(test,
			   pkm_kacs_kunit_may_manage_volumes_for_subject(token));
	KUNIT_EXPECT_FALSE(test, capable(CAP_SYS_TIME));
	pkm_kacs_kunit_set_fail_mark_privileges_used(false);

	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_check_capability_for_subject(token,
								    CAP_SYS_TIME),
			0L);
	KUNIT_EXPECT_TRUE(test,
			  pkm_kacs_kunit_may_manage_volumes_for_subject(token));
	KUNIT_EXPECT_TRUE(test, capable(CAP_SYS_TIME));
}

/*
 * Section 3.10: security_capable() reaches the KACS switchboard twice -- once
 * through the patched commoncap entry point and once through the KACS capable
 * hook -- so one consultation records the privilege as used twice.  A refused
 * capability records nothing on either path.
 */
static void pkm_kunit_security_capable_marks_privilege_use_twice(
	struct kunit *test)
{
	pkm_kacs_kunit_mark_privileges_used_calls(true);
	KUNIT_EXPECT_EQ(test,
			security_capable(current_cred(), &init_user_ns,
					 CAP_SYS_TIME, CAP_OPT_NONE), 0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_mark_privileges_used_calls(true),
			2U);
	KUNIT_EXPECT_NE(test,
			security_capable(current_cred(), &init_user_ns,
					 CAP_SETFCAP, CAP_OPT_NONE), 0);
	KUNIT_EXPECT_EQ(test, pkm_kacs_kunit_mark_privileges_used_calls(true),
			0U);
}

/*
 * Section 3.9.7 / 3.C: the two StrataFS emissions are best-effort.  An empty
 * or over-long operation string drops the refusal event silently, an over-long
 * path drops the copy-up event, and neither failure reaches the caller.  (The
 * other drop condition, an allocation failure, has no witness here.)
 */
static void pkm_kunit_stratafs_audit_emission_is_best_effort(struct kunit *test)
{
	static const char sentinel[] = "PKM_KUNIT_SENTINEL";
	struct pkm_kmes_kunit_snapshot snapshot = { };
	char *long_op;
	char *long_path;

	long_op = kunit_kzalloc(test, 65, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, long_op);
	memset(long_op, 'o', 64);
	long_path = kunit_kzalloc(test, PATH_MAX + 1, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, long_path);
	memset(long_path, 'p', PATH_MAX);

	/* The refusal payload has no shape for an empty or 64-byte operation. */
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_stratafs_refusal_payload(
				NULL, 0, "/f", "", 0, "lo", -EACCES, false),
			(size_t)0);
	KUNIT_EXPECT_EQ(test,
			pkm_kacs_kunit_stratafs_refusal_payload(
				NULL, 0, "/f", long_op, 0, "lo", -EACCES, false),
			(size_t)0);
	long_op[63] = '\0';
	KUNIT_EXPECT_GT(test,
			pkm_kacs_kunit_stratafs_refusal_payload(
				NULL, 0, "/f", long_op, 0, "lo", -EACCES, false),
			(size_t)0);
	long_op[63] = 'o';

	/* The emitters drop those silently: no event, no drop counted.  (A
	 * ring is only active once something has been written to it, so a
	 * sentinel goes first and the sequence is read against it.) */
	pkm_kunit_reset_kmes();
	pkm_kmes_emit_kernel(KMES_ORIGIN_KACS, sentinel, sizeof(sentinel) - 1,
			     sentinel, 1);
	pkm_kacs_stratafs_audit_mutation_refused("/f", long_op, 0, "lo",
						 -EACCES, false);
	pkm_kacs_stratafs_audit_mutation_refused("/f", "", 0, "lo", -EACCES,
						 false);
	pkm_kacs_stratafs_audit_copy_up(long_path, 1, "lo", 0, "up", 0);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 1ULL);
	KUNIT_EXPECT_EQ(test, snapshot.dropped_events, 0ULL);

	/* The same emitters with well-formed arguments do emit. */
	pkm_kacs_stratafs_audit_mutation_refused("/f", "write", 0, "lo",
						 -EACCES, false);
	pkm_kacs_stratafs_audit_copy_up("/f", 1, "lo", 0, "up", 0);
	KUNIT_ASSERT_EQ(test, pkm_kmes_kunit_snapshot_single_active(&snapshot),
			0);
	KUNIT_EXPECT_EQ(test, snapshot.last_sequence, 3ULL);
}

/*
 * Section 3.C: logon-session-destroyed is best-effort where the package name
 * is not valid UTF-8.  No live session can carry such a name -- creation
 * validates it -- so the encoder is probed directly: it refuses the payload,
 * and the emitter drops the event on that refusal.
 */
static void pkm_kunit_logon_session_destroyed_encoder_drops_non_utf8(
	struct kunit *test)
{
	static const u8 valid[] = "Peios";
	static const u8 invalid[] = { 'P', 0xff, 0xfe, 'x' };

	KUNIT_EXPECT_EQ(test,
			kacs_rust_kunit_encode_logon_session_destroyed_probe(
				valid, sizeof(valid) - 1), 0L);
	KUNIT_EXPECT_EQ(test,
			kacs_rust_kunit_encode_logon_session_destroyed_probe(
				invalid, sizeof(invalid)), (long)-EIO);
}

static struct kunit_case pkm_kunit_misc_cases[] = {
	KUNIT_CASE(pkm_kunit_port_fallback_admits_system_only_shape),
	KUNIT_CASE(pkm_kunit_port_published_table_decides),
	KUNIT_CASE(pkm_kunit_net_bind_service_is_allow),
	KUNIT_CASE(pkm_kunit_probe_smoke),
	KUNIT_CASE(pkm_kunit_live_capable_sys_boot_uses_shutdown_privilege),
	KUNIT_CASE(pkm_kunit_internal_file_access_sees_device_groups),
	KUNIT_CASE(pkm_kunit_internal_file_access_uses_restricted_device_groups),
	KUNIT_CASE(pkm_kunit_internal_file_access_sees_token_claims),
	KUNIT_CASE(pkm_kunit_internal_file_access_sees_resource_claims),
	KUNIT_CASE(pkm_kunit_lcs_private_credentials_accessors),
	KUNIT_CASE(pkm_kunit_kernel_work_evaluates_as_system),
	KUNIT_CASE(pkm_kunit_override_creds_credential_is_authoritative),
	KUNIT_CASE(pkm_kunit_privilege_use_record_failure_fails_the_gate),
	KUNIT_CASE(pkm_kunit_security_capable_marks_privilege_use_twice),
	KUNIT_CASE(pkm_kunit_stratafs_audit_emission_is_best_effort),
	KUNIT_CASE(pkm_kunit_logon_session_destroyed_encoder_drops_non_utf8),
	{}
};

static struct kunit_suite pkm_kunit_misc_suite = {
	.name = "pkm_kunit_misc",
	.test_cases = pkm_kunit_misc_cases,
};

kunit_test_suite(pkm_kunit_misc_suite);
