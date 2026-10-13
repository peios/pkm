// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/file.h>
#include <linux/seq_file.h>
#include <linux/shmem_fs.h>

#include "stratafs.h"
#include "dir_cache.h"

struct stratafs_kunit_identity_fixture {
	struct stratafs_sb_info sbi;
	struct super_block sb;
	struct file *files[2];
};

static void stratafs_kunit_identity_cleanup(void *data)
{
	struct stratafs_kunit_identity_fixture *fixture = data;
	unsigned int i;

	stratafs_free_identities(&fixture->sbi);
	for (i = 0; i < ARRAY_SIZE(fixture->files); i++)
		if (!IS_ERR_OR_NULL(fixture->files[i]))
			fput(fixture->files[i]);
}

static struct stratafs_kunit_identity_fixture *
stratafs_kunit_identity_fixture(struct kunit *test)
{
	struct stratafs_kunit_identity_fixture *fixture;
	unsigned int i;

	fixture = kunit_kzalloc(test, sizeof(*fixture), GFP_KERNEL);
	if (!fixture)
		return NULL;
	stratafs_init_identities(&fixture->sbi);
	fixture->sb.s_fs_info = &fixture->sbi;
	if (kunit_add_action_or_reset(test, stratafs_kunit_identity_cleanup,
				     fixture))
		return NULL;
	for (i = 0; i < ARRAY_SIZE(fixture->files); i++) {
		fixture->files[i] = shmem_kernel_file_setup("stratafs-identity",
							 0, EMPTY_VMA_FLAGS);
		if (IS_ERR(fixture->files[i]))
			return NULL;
	}
	return fixture;
}

static void stratafs_kunit_derived_identity_does_not_pin(struct kunit *test)
{
	struct stratafs_kunit_identity_fixture *fixture;
	struct kstat stat = { .result_mask = STATX_INO, .dev = 7, .ino = 42 };
	struct inode *provider;
	unsigned long first, again, other;
	int refs;

	fixture = stratafs_kunit_identity_fixture(test);
	KUNIT_ASSERT_NOT_NULL(test, fixture);
	provider = file_inode(fixture->files[0]);
	refs = atomic_read(&provider->i_count);
	KUNIT_ASSERT_EQ(test, stratafs_identity_number(&fixture->sb, provider,
						     &stat, &first), 0);
	KUNIT_ASSERT_EQ(test, stratafs_identity_number(&fixture->sb, provider,
						     &stat, &again), 0);
	KUNIT_EXPECT_EQ(test, first, again);
	KUNIT_EXPECT_EQ(test, atomic_read(&provider->i_count), refs);
	KUNIT_EXPECT_TRUE(test, xa_empty(&fixture->sbi.identities));

	/* A reloaded provider inode with the same on-disk identity agrees. */
	KUNIT_ASSERT_EQ(test, stratafs_identity_number(&fixture->sb,
		file_inode(fixture->files[1]), &stat, &again), 0);
	KUNIT_EXPECT_EQ(test, first, again);

	/* Btrfs subvolumes can share i_sb and i_ino but report different devs. */
	stat.dev++;
	KUNIT_ASSERT_EQ(test, stratafs_identity_number(&fixture->sb,
		file_inode(fixture->files[1]), &stat, &other), 0);
	KUNIT_EXPECT_NE(test, first, other);
	KUNIT_EXPECT_TRUE(test, xa_empty(&fixture->sbi.identities));
	KUNIT_EXPECT_EQ(test, atomic_read(&provider->i_count), refs);
}

static void stratafs_kunit_overflow_identity_pins_once(struct kunit *test)
{
	struct stratafs_kunit_identity_fixture *fixture;
	struct kstat stat = { .result_mask = STATX_INO, .dev = 7, .ino = U64_MAX };
	struct inode *provider;
	unsigned long first, again, other, synthetic;
	int refs;

	fixture = stratafs_kunit_identity_fixture(test);
	KUNIT_ASSERT_NOT_NULL(test, fixture);
	provider = file_inode(fixture->files[0]);
	refs = atomic_read(&provider->i_count);
	KUNIT_ASSERT_EQ(test, stratafs_identity_number(&fixture->sb, provider,
						     &stat, &first), 0);
	KUNIT_ASSERT_EQ(test, stratafs_identity_number(&fixture->sb, provider,
						     &stat, &again), 0);
	KUNIT_EXPECT_EQ(test, first, again);
	KUNIT_EXPECT_EQ(test, atomic_read(&provider->i_count), refs + 1);
	KUNIT_EXPECT_TRUE(test, !!(first & (1UL << (BITS_PER_LONG - 1))));
	KUNIT_ASSERT_EQ(test, stratafs_identity_number(&fixture->sb,
		file_inode(fixture->files[1]), &stat, &other), 0);
	KUNIT_EXPECT_NE(test, first, other);
	KUNIT_ASSERT_EQ(test, stratafs_alloc_ino(&fixture->sb, &synthetic), 0);
	KUNIT_EXPECT_NE(test, first, synthetic);
	KUNIT_EXPECT_NE(test, other, synthetic);

	/* Freeing the fallback map really releases its provider reference. */
	stratafs_free_identities(&fixture->sbi);
	stratafs_init_identities(&fixture->sbi);
	KUNIT_EXPECT_EQ(test, atomic_read(&provider->i_count), refs);
}

static void stratafs_kunit_missing_identity_and_exhaustion(struct kunit *test)
{
	struct stratafs_kunit_identity_fixture *fixture;
	struct kstat stat = { .dev = 7, .ino = 42 };
	unsigned long first, again, sentinel = 123;
	const unsigned long high = 1UL << (BITS_PER_LONG - 1);

	fixture = stratafs_kunit_identity_fixture(test);
	KUNIT_ASSERT_NOT_NULL(test, fixture);
	KUNIT_ASSERT_EQ(test, stratafs_identity_number(&fixture->sb,
		file_inode(fixture->files[0]), &stat, &first), 0);
	KUNIT_EXPECT_TRUE(test, !!(first & high));
	/* A previously assigned fallback must never change identity. */
	stat.result_mask = STATX_INO;
	KUNIT_ASSERT_EQ(test, stratafs_identity_number(&fixture->sb,
		file_inode(fixture->files[0]), &stat, &again), 0);
	KUNIT_EXPECT_EQ(test, first, again);

	atomic64_set(&fixture->sbi.next_ino, high - 2);
	KUNIT_ASSERT_EQ(test, stratafs_alloc_ino(&fixture->sb, &again), 0);
	KUNIT_EXPECT_EQ(test, again, ULONG_MAX);
	KUNIT_EXPECT_EQ(test, stratafs_alloc_ino(&fixture->sb, &sentinel),
			-EOVERFLOW);
	KUNIT_EXPECT_EQ(test, stratafs_alloc_ino(&fixture->sb, &sentinel),
			-EOVERFLOW);
	KUNIT_EXPECT_EQ(test, sentinel, 123UL);
	KUNIT_EXPECT_EQ(test, (u64)atomic64_read(&fixture->sbi.next_ino),
			(u64)high - 1);
}

static void stratafs_kunit_derived_identity_boundaries(struct kunit *test)
{
	const u64 limit = (1ULL << (BITS_PER_LONG - 2)) - 1;
	unsigned long nested;

	KUNIT_EXPECT_NE(test, stratafs_derive_ino(1, limit), 0UL);
	KUNIT_EXPECT_EQ(test, stratafs_derive_ino(1, limit + 1), 0UL);
	KUNIT_EXPECT_EQ(test, stratafs_derive_ino(1, U64_MAX), 0UL);
	KUNIT_EXPECT_EQ(test, stratafs_derive_ino(0, 42), 0UL);
	KUNIT_EXPECT_EQ(test, stratafs_derive_ino(1, 0), 0UL);
	KUNIT_EXPECT_EQ(test, stratafs_derive_ino(ULONG_MAX, 42), 0UL);
	nested = stratafs_derive_ino(1, stratafs_derive_ino(1, 42));
	KUNIT_EXPECT_NE(test, nested, 0UL);
	KUNIT_EXPECT_NE(test, nested, stratafs_derive_ino(1, 43));
}

static void stratafs_kunit_free_parsed(struct stratafs_sb_info *sbi)
{
	unsigned int i;

	for (i = 0; i < sbi->count; i++)
		kfree(sbi->strata[i].path);
	kfree(sbi->display_options);
}

static void stratafs_kunit_parse_valid(struct kunit *test)
{
	struct stratafs_sb_info sbi = {};

	KUNIT_ASSERT_EQ(test,
		stratafs_parse_strata(&sbi,
			"/system/retc:/lcl/etc+create:/usr/etc+ro"), 0);
	KUNIT_EXPECT_EQ(test, sbi.count, 3U);
	KUNIT_EXPECT_STREQ(test, sbi.strata[0].path, "/system/retc");
	KUNIT_EXPECT_EQ(test, sbi.strata[1].flags, STRATAFS_F_CREATE);
	KUNIT_EXPECT_EQ(test, sbi.strata[2].flags, STRATAFS_F_RO);
	KUNIT_EXPECT_EQ(test, stratafs_validate_configuration(&sbi), 0);
	KUNIT_EXPECT_EQ(test, sbi.create_index, 1);
	stratafs_kunit_free_parsed(&sbi);
}

static void stratafs_kunit_parse_escapes(struct kunit *test)
{
	struct stratafs_sb_info sbi = {};

	KUNIT_ASSERT_EQ(test,
		stratafs_parse_strata(&sbi, "/a\\:b:/c\\+d+am:/e\\,f+ro"), 0);
	KUNIT_EXPECT_STREQ(test, sbi.strata[0].path, "/a:b");
	KUNIT_EXPECT_STREQ(test, sbi.strata[1].path, "/c+d");
	KUNIT_EXPECT_STREQ(test, sbi.strata[2].path, "/e,f");
	stratafs_kunit_free_parsed(&sbi);
}

/*
 * §7.3: the mount table reports the stack "sufficient to reconstruct" it — the
 * same paths, in the same order, with the same flags.
 *
 * ->show_options used to emit display_options through seq_show_option(), which
 * octal-escapes ',', a backslash and whitespace. That is a second escaping layer on a
 * value that already carries §7.1's, so a stack containing an escaped separator
 * came back out unreconstructable: an escaped ':' reported with its backslash
 * itself octal-escaped, which the parser then rejects as a dangling escape;
 * an escaped ',' reported as something that reads back as a different path.
 *
 * Paths free of ':', '+', ',', a backslash and whitespace — the spec's own example
 * among them — round-tripped byte-identical, which is why this survived.
 *
 * This drives the real emission path through stratafs_show_strata() and feeds
 * what it wrote straight back into the parser.
 */
static void stratafs_kunit_mount_table_round_trip(struct kunit *test)
{
	static const char *const stacks[] = {
		/* The spec's own example: no separators, always worked. */
		"/system/retc:/lcl/etc+create:/usr/etc+ro",
		/* One escaped instance of each §7.1 separator. */
		"/a\\:b:/c\\+d+am:/e\\,f+ro",
		/* An escaped backslash in a path, and a space. */
		"/a\\\\b:/c d+create",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(stacks); i++) {
		struct stratafs_sb_info first = {};
		struct stratafs_sb_info second = {};
		struct seq_file m = {};
		const char *reported;
		unsigned int j;

		KUNIT_ASSERT_EQ_MSG(test,
			stratafs_parse_strata(&first, stacks[i]), 0,
			"parse of %s", stacks[i]);

		m.size = PAGE_SIZE;
		m.buf = kunit_kzalloc(test, m.size, GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, m.buf);

		stratafs_show_strata(&m, &first);
		KUNIT_ASSERT_LT_MSG(test, m.count, m.size,
				    "seq buffer overflowed for %s", stacks[i]);
		m.buf[m.count] = '\0';

		/* Skip the ",strata=" the mount table prefixes. */
		KUNIT_ASSERT_EQ_MSG(test,
			strncmp(m.buf, ",strata=", 8), 0,
			"reported %s", m.buf);
		reported = m.buf + 8;

		KUNIT_ASSERT_EQ_MSG(test,
			stratafs_parse_strata(&second, reported), 0,
			"reparse of reported %s", reported);

		KUNIT_EXPECT_EQ_MSG(test, second.count, first.count,
				    "stratum count for %s", stacks[i]);
		for (j = 0; j < first.count && j < second.count; j++) {
			KUNIT_EXPECT_STREQ_MSG(test, second.strata[j].path,
					       first.strata[j].path,
					       "path %u of %s", j, stacks[i]);
			KUNIT_EXPECT_EQ_MSG(test, second.strata[j].flags,
					    first.strata[j].flags,
					    "flags %u of %s", j, stacks[i]);
		}
		stratafs_kunit_free_parsed(&second);
		stratafs_kunit_free_parsed(&first);
	}
}

/*
 * §2.3: "A remount MUST NOT add, remove, reorder, or re-flag strata; an
 * attempt to do so MUST fail with EINVAL."
 *
 * ->reconfigure used to test the *presence* of strata=, not whether its value
 * differed.  A remount supplying a byte-identical stack does none of the four
 * forbidden things, and refusing it breaks option-string replay: `mount -o
 * remount` tools rebuild the whole option string from /proc/self/mountinfo,
 * so flipping a stratafs mount read-only meant replaying a strata= that
 * changed nothing.
 */
static void stratafs_kunit_remount_compares_the_stack(struct kunit *test)
{
	static const char *const stack = "/a\\:b:/c\\+d+am:/e\\,f+ro";
	static const char *const differing[] = {
		"/a\\:b:/c\\+d+am",                 /* a stratum removed */
		"/c\\+d+am:/a\\:b:/e\\,f+ro",       /* reordered */
		"/a\\:b:/c\\+d+ro:/e\\,f+ro",       /* re-flagged */
		"/a\\:b:/c\\+d+am:/e\\,f+ro:/g",    /* a stratum added */
	};
	struct stratafs_sb_info mounted = {};
	struct stratafs_sb_info same = {};
	unsigned int i;

	KUNIT_ASSERT_EQ(test, stratafs_parse_strata(&mounted, stack), 0);
	KUNIT_ASSERT_EQ(test, stratafs_parse_strata(&same, stack), 0);
	KUNIT_EXPECT_TRUE_MSG(test, stratafs_strata_unchanged(&same, &mounted),
			      "an identical stack must be accepted");
	stratafs_kunit_free_parsed(&same);

	for (i = 0; i < ARRAY_SIZE(differing); i++) {
		struct stratafs_sb_info other = {};

		KUNIT_ASSERT_EQ_MSG(test,
			stratafs_parse_strata(&other, differing[i]), 0,
			"parse of %s", differing[i]);
		KUNIT_EXPECT_FALSE_MSG(test,
			stratafs_strata_unchanged(&other, &mounted),
			"%s differs and must be refused", differing[i]);
		stratafs_kunit_free_parsed(&other);
	}
	stratafs_kunit_free_parsed(&mounted);
}

static void stratafs_kunit_parse_rejects_malformed(struct kunit *test)
{
	const char *const invalid[] = {
		"", "relative", ":/a", "/a:", "/a::/b", "/a+",
		"/a+unknown", "/a+ro+ro", "/a\\q", "/a\\", "/a,b",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(invalid); i++) {
		struct stratafs_sb_info sbi = {};

		KUNIT_EXPECT_EQ_MSG(test, stratafs_parse_strata(&sbi, invalid[i]),
				    -EINVAL, "accepted %s", invalid[i]);
	}
}

static void stratafs_kunit_routing(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		stratafs_rust_route_existing(2, false, 1, true, true, false),
		(int)STRATAFS_ROUTE_COPY_UP);
	KUNIT_EXPECT_EQ(test,
		stratafs_rust_route_existing(1, false, 2, true, true, false),
		(int)STRATAFS_ROUTE_READ_ONLY);
	KUNIT_EXPECT_EQ(test,
		stratafs_rust_route_existing(1, true, 0, true, true, false),
		(int)STRATAFS_ROUTE_IN_PLACE);
	KUNIT_EXPECT_EQ(test,
		stratafs_rust_route_existing(1, true, 0, true, true, true),
		(int)STRATAFS_ROUTE_READ_ONLY);
	KUNIT_EXPECT_EQ(test,
		stratafs_rust_route_existing(2, false, 1, true, false, false),
		(int)STRATAFS_ROUTE_READ_ONLY);
	KUNIT_EXPECT_EQ(test,
		stratafs_rust_route_existing(2, false, -1, false, true, false),
		(int)STRATAFS_ROUTE_READ_ONLY);
}

static void stratafs_kunit_live_mount_cookie(struct kunit *test)
{
	struct stratafs_sb_info sbi = {};
	u64 boot;
	u64 mount;

	KUNIT_ASSERT_EQ(test, stratafs_register_live_mount(&sbi), 0);
	boot = sbi.boot_cookie;
	mount = sbi.mount_cookie;
	KUNIT_EXPECT_NE(test, boot, 0ULL);
	KUNIT_EXPECT_NE(test, mount, 0ULL);
	KUNIT_EXPECT_TRUE(test, stratafs_stage_owner_live(boot, mount));
	KUNIT_EXPECT_FALSE(test, stratafs_stage_owner_live(boot ^ 1, mount));
	KUNIT_EXPECT_FALSE(test, stratafs_stage_owner_live(boot, mount ^ 1));
	stratafs_unregister_live_mount(&sbi);
	KUNIT_EXPECT_FALSE(test, stratafs_stage_owner_live(boot, mount));
}

/*
 * The reserved namespace, §9.1.
 *
 * Three rules that meet at one boundary: everything under
 * "system.stratafs.", the bare name "system.stratafs" without the dot, and
 * the staging attribute, which gets the same treatment despite lying outside
 * the namespace entirely.
 *
 * The bare name used to be unreserved and forwarded to the provider, because
 * the prefix constant carries its trailing dot. The obvious fix -- compare one
 * byte short -- over-reserves instead, capturing "system.stratafsfoo", so both
 * directions are pinned here.
 */
static void stratafs_kunit_reserved_xattr_names(struct kunit *test)
{
	static const char *const reserved[] = {
		"system.stratafs.origin",
		"system.stratafs.",
		"system.stratafs",
		STRATAFS_XATTR_STAGING,
	};
	static const char *const forwarded[] = {
		"system.stratafsfoo",
		"system.stratafs_other",
		"system.strataf",
		"user.system.stratafs",
		"security.capability",
		"",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(reserved); i++)
		KUNIT_EXPECT_TRUE_MSG(test, stratafs_reserved_xattr(reserved[i]),
				      "%s must be reserved", reserved[i]);

	for (i = 0; i < ARRAY_SIZE(forwarded); i++)
		KUNIT_EXPECT_FALSE_MSG(test,
				       stratafs_reserved_xattr(forwarded[i]),
				       "%s must reach the provider", forwarded[i]);
}

static void stratafs_kunit_cache_cleanup(void *data)
{
	stratafs_dir_cache_destroy(data);
}

static struct stratafs_dir_cache *stratafs_kunit_cache(struct kunit *test)
{
	struct stratafs_dir_cache *cache;

	cache = kunit_kzalloc(test, sizeof(*cache), GFP_KERNEL);
	if (!cache)
		return NULL;
	stratafs_dir_cache_init(cache);
	if (kunit_add_action_or_reset(test, stratafs_kunit_cache_cleanup, cache))
		return NULL;
	return cache;
}

static void stratafs_kunit_directory_empty(struct kunit *test)
{
	struct stratafs_dir_cache *cache = stratafs_kunit_cache(test);

	KUNIT_ASSERT_NOT_NULL(test, cache);
	KUNIT_EXPECT_FALSE(test, stratafs_dir_cache_contains(cache, "absent", 6));
	KUNIT_ASSERT_EQ(test, stratafs_dir_cache_seal(cache), 0);
	KUNIT_EXPECT_PTR_EQ(test, stratafs_dir_cache_at(cache, 2), NULL);
}

/* Exercise every resize, removal after rehash, and lower-provider fallback. */
static void stratafs_kunit_directory_index(struct kunit *test)
{
	struct stratafs_dir_cache *cache = stratafs_kunit_cache(test);
	struct stratafs_dir_entry *entry;
	char name[32];
	unsigned int i;

	KUNIT_ASSERT_NOT_NULL(test, cache);
	for (i = 0; i < 4096; i++) {
		int len = snprintf(name, sizeof(name), "entry-%u", i);

		KUNIT_EXPECT_FALSE(test, stratafs_dir_cache_contains(cache, name, len));
		KUNIT_ASSERT_EQ(test, stratafs_dir_cache_add(cache, name, len,
							    DT_REG, 0), 0);
	}
	for (i = 0; i < 4096; i++) {
		int len = snprintf(name, sizeof(name), "entry-%u", i);

		KUNIT_EXPECT_TRUE(test, stratafs_dir_cache_contains(cache, name, len));
	}
	/* Prefixes and extra bytes are distinct even with an identical prefix. */
	KUNIT_EXPECT_FALSE(test, stratafs_dir_cache_contains(cache, "entry-", 6));
	KUNIT_EXPECT_FALSE(test, stratafs_dir_cache_contains(cache, "entry-0x", 8));
	entry = list_first_entry(&cache->entries, struct stratafs_dir_entry, list);
	stratafs_dir_cache_remove(cache, entry);
	KUNIT_EXPECT_FALSE(test, stratafs_dir_cache_contains(cache, "entry-0", 7));
	KUNIT_ASSERT_EQ(test, stratafs_dir_cache_add(cache, "entry-0", 7,
						    DT_DIR, 1), 0);
	KUNIT_ASSERT_EQ(test, stratafs_dir_cache_seal(cache), 0);
	KUNIT_EXPECT_PTR_EQ(test, cache->buckets, NULL);
	KUNIT_EXPECT_EQ(test, cache->count, 4096U);
	/* A later provider's recovered name is last; all others keep their order. */
	for (i = 0; i < 4095; i++) {
		snprintf(name, sizeof(name), "entry-%u", i + 1);
		entry = stratafs_dir_cache_at(cache, i + 2);
		KUNIT_ASSERT_NOT_NULL(test, entry);
		KUNIT_EXPECT_STREQ(test, entry->name, name);
		KUNIT_EXPECT_EQ(test, entry->participant_index, 0U);
		KUNIT_EXPECT_EQ(test, entry->type, (unsigned int)DT_REG);
	}
	entry = stratafs_dir_cache_at(cache, 4097);
	KUNIT_ASSERT_NOT_NULL(test, entry);
	KUNIT_EXPECT_STREQ(test, entry->name, "entry-0");
	KUNIT_EXPECT_EQ(test, entry->participant_index, 1U);
	KUNIT_EXPECT_EQ(test, entry->type, (unsigned int)DT_DIR);
	/* Resume, rewind and very large seek positions never wrap to an entry. */
	KUNIT_EXPECT_STREQ(test, stratafs_dir_cache_at(cache, 2)->name, "entry-1");
	KUNIT_EXPECT_PTR_EQ(test, stratafs_dir_cache_at(cache, -1), NULL);
	KUNIT_EXPECT_PTR_EQ(test, stratafs_dir_cache_at(cache, 0), NULL);
	KUNIT_EXPECT_PTR_EQ(test, stratafs_dir_cache_at(cache, 1), NULL);
	KUNIT_EXPECT_PTR_EQ(test, stratafs_dir_cache_at(cache, 4098), NULL);
	KUNIT_EXPECT_PTR_EQ(test, stratafs_dir_cache_at(cache, (1LL << 32) + 2), NULL);
	KUNIT_EXPECT_PTR_EQ(test, stratafs_dir_cache_at(cache, LLONG_MAX), NULL);
}

static struct kunit_case stratafs_kunit_cases[] = {
	KUNIT_CASE(stratafs_kunit_directory_empty),
	KUNIT_CASE(stratafs_kunit_directory_index),
	KUNIT_CASE(stratafs_kunit_parse_valid),
	KUNIT_CASE(stratafs_kunit_parse_escapes),
	KUNIT_CASE(stratafs_kunit_mount_table_round_trip),
	KUNIT_CASE(stratafs_kunit_remount_compares_the_stack),
	KUNIT_CASE(stratafs_kunit_parse_rejects_malformed),
	KUNIT_CASE(stratafs_kunit_routing),
	KUNIT_CASE(stratafs_kunit_live_mount_cookie),
	KUNIT_CASE(stratafs_kunit_reserved_xattr_names),
	KUNIT_CASE(stratafs_kunit_derived_identity_does_not_pin),
	KUNIT_CASE(stratafs_kunit_overflow_identity_pins_once),
	KUNIT_CASE(stratafs_kunit_missing_identity_and_exhaustion),
	KUNIT_CASE(stratafs_kunit_derived_identity_boundaries),
	{}
};

static struct kunit_suite stratafs_kunit_suite = {
	.name = "stratafs",
	.test_cases = stratafs_kunit_cases,
};

kunit_test_suite(stratafs_kunit_suite);
