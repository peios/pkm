/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef STRATAFS_DIR_CACHE_H
#define STRATAFS_DIR_CACHE_H

#include <linux/list.h>
#include <linux/siphash.h>

struct stratafs_dir_entry {
	struct list_head list;
	struct hlist_node hash_node;
	u64 hash;
	char *name;
	unsigned int len;
	unsigned int type;
	unsigned int participant_index;
	unsigned long ino;
};

/* Private to the opener until sealed; immutable after publication of the fd. */
struct stratafs_dir_cache {
	struct list_head entries;
	struct hlist_head *buckets;
	struct stratafs_dir_entry **positions;
	siphash_key_t key;
	unsigned int bucket_count;
	unsigned int count;
};

void stratafs_dir_cache_init(struct stratafs_dir_cache *cache);
bool stratafs_dir_cache_contains(struct stratafs_dir_cache *cache,
				 const char *name, unsigned int len);
/* The caller has already excluded duplicates and internal staging names. */
int stratafs_dir_cache_add(struct stratafs_dir_cache *cache, const char *name,
			  unsigned int len, unsigned int type,
			  unsigned int participant_index);
void stratafs_dir_cache_remove(struct stratafs_dir_cache *cache,
			       struct stratafs_dir_entry *entry);
int stratafs_dir_cache_seal(struct stratafs_dir_cache *cache);
struct stratafs_dir_entry *
stratafs_dir_cache_at(struct stratafs_dir_cache *cache, loff_t position);
void stratafs_dir_cache_destroy(struct stratafs_dir_cache *cache);

#endif
