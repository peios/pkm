// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>

#include "stratafs.h"

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

static struct kunit_case stratafs_kunit_cases[] = {
	KUNIT_CASE(stratafs_kunit_parse_valid),
	KUNIT_CASE(stratafs_kunit_parse_escapes),
	KUNIT_CASE(stratafs_kunit_parse_rejects_malformed),
	KUNIT_CASE(stratafs_kunit_routing),
	KUNIT_CASE(stratafs_kunit_live_mount_cookie),
	{}
};

static struct kunit_suite stratafs_kunit_suite = {
	.name = "stratafs",
	.test_cases = stratafs_kunit_cases,
};

kunit_test_suite(stratafs_kunit_suite);
