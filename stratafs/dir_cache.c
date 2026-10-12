// SPDX-License-Identifier: GPL-2.0-only

#include <linux/random.h>
#include <linux/slab.h>

#include "dir_cache.h"

void stratafs_dir_cache_init(struct stratafs_dir_cache *cache)
{
	INIT_LIST_HEAD(&cache->entries);
	get_random_bytes(&cache->key, sizeof(cache->key));
}

bool stratafs_dir_cache_contains(struct stratafs_dir_cache *cache,
				 const char *name, unsigned int len)
{
	struct stratafs_dir_entry *entry;
	u64 hash;

	if (!cache->bucket_count)
		return false;
	hash = siphash(name, len, &cache->key);
	hlist_for_each_entry(entry,
		&cache->buckets[hash & (cache->bucket_count - 1)], hash_node)
		if (entry->hash == hash && entry->len == len &&
		    !memcmp(entry->name, name, len))
			return true;
	return false;
}

/*
 * Capture is single-threaded. Grow synchronously at load factor one, retaining
 * list order independently of bucket order. A fresh per-open key prevents
 * names chosen by a provider from targeting a predictable bucket layout.
 */
static int stratafs_dir_cache_grow(struct stratafs_dir_cache *cache)
{
	struct hlist_head *buckets;
	struct stratafs_dir_entry *entry;
	unsigned int count;

	if (cache->count < cache->bucket_count)
		return 0;
	if (cache->bucket_count > UINT_MAX / 2)
		return -EOVERFLOW;
	count = cache->bucket_count ? cache->bucket_count * 2 : 16;
	buckets = kvcalloc(count, sizeof(*buckets), GFP_KERNEL);
	if (!buckets)
		return -ENOMEM;
	list_for_each_entry(entry, &cache->entries, list)
		hlist_add_head(&entry->hash_node,
			       &buckets[entry->hash & (count - 1)]);
	kvfree(cache->buckets);
	cache->buckets = buckets;
	cache->bucket_count = count;
	return 0;
}

int stratafs_dir_cache_add(struct stratafs_dir_cache *cache, const char *name,
			  unsigned int len, unsigned int type,
			  unsigned int participant_index)
{
	struct stratafs_dir_entry *entry;
	int ret;

	ret = stratafs_dir_cache_grow(cache);
	if (ret)
		return ret;
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->name = kmemdup_nul(name, len, GFP_KERNEL);
	if (!entry->name) {
		kfree(entry);
		return -ENOMEM;
	}
	entry->len = len;
	entry->type = type;
	entry->participant_index = participant_index;
	entry->hash = siphash(name, len, &cache->key);
	hlist_add_head(&entry->hash_node,
		       &cache->buckets[entry->hash & (cache->bucket_count - 1)]);
	list_add_tail(&entry->list, &cache->entries);
	cache->count++;
	return 0;
}

void stratafs_dir_cache_remove(struct stratafs_dir_cache *cache,
			       struct stratafs_dir_entry *entry)
{
	hlist_del(&entry->hash_node);
	list_del(&entry->list);
	kfree(entry->name);
	kfree(entry);
	cache->count--;
}

int stratafs_dir_cache_seal(struct stratafs_dir_cache *cache)
{
	struct stratafs_dir_entry *entry;
	unsigned int i = 0;

	if (cache->count) {
		cache->positions = kvcalloc(cache->count,
					   sizeof(*cache->positions), GFP_KERNEL);
		if (!cache->positions)
			return -ENOMEM;
		list_for_each_entry(entry, &cache->entries, list)
			cache->positions[i++] = entry;
	}
	/* No lookup or mutation occurs after capture, so discard the side index. */
	kvfree(cache->buckets);
	cache->buckets = NULL;
	cache->bucket_count = 0;
	return 0;
}

struct stratafs_dir_entry *
stratafs_dir_cache_at(struct stratafs_dir_cache *cache, loff_t position)
{
	/* Dot entries occupy positions 0 and 1. Do not narrow a large seek. */
	if (position < 2 || position - 2 >= cache->count)
		return NULL;
	return cache->positions[position - 2];
}

void stratafs_dir_cache_destroy(struct stratafs_dir_cache *cache)
{
	struct stratafs_dir_entry *entry, *next;

	list_for_each_entry_safe(entry, next, &cache->entries, list) {
		list_del(&entry->list);
		kfree(entry->name);
		kfree(entry);
	}
	kvfree(cache->buckets);
	kvfree(cache->positions);
	cache->buckets = NULL;
	cache->positions = NULL;
	cache->bucket_count = 0;
	cache->count = 0;
}
