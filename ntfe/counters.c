// SPDX-License-Identifier: GPL-2.0-only
/*
 * The counter store (machinery slice, ratified PEI-598): streams and
 * views.
 *
 * COUNT(Name[, Amount]) emits into a named machine-scoped stream; every
 * `Counter.Name([window][, keyspec])` condition is a view over it. Views
 * are compile-time constants (rules are their only source), so at
 * publication the forests hand over the complete view set and the store
 * materializes exactly that: one keyed table per (stream, key-spec), each
 * cell carrying a cumulative total plus one sliding ring per window the
 * table is viewed through. A COUNT increments every table of its stream
 * (amplification bounded by what policy authors wrote — the trusted side).
 *
 * Keys come from the wire (a SrcAddr-keyed table's keyspace is chosen by
 * whoever sends packets), so tables are hard-capped at
 * PEIOS_NTFE_COUNTER_MAX_KEYS cells: when full, idle cells are reaped, and
 * if none are idle the new key is refused and confessed. Never silent
 * eviction.
 *
 * Windows are approximated by 8 buckets of window/8 seconds, advanced
 * lazily on access (no timers): each bucket remembers which period it
 * belongs to, and a read sums the buckets still inside the window.
 *
 * The store outlives generations. Re-publication keeps tables whose
 * views did not change, creates new ones, migrates cells whose window set
 * changed (totals and matching rings copied), and frees tables no forest
 * views any more.
 *
 * Locking: the table list and each table's cell list are RCU-read on the
 * packet path; per-table spinlocks (_bh: the publisher runs in process
 * context) serialize cell insertion and increments; publication holds a
 * mutex.
 */

#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/util_macros.h>

#include <pkm/ntfe.h>

#include "ntfe.h"

#define NTFE_COUNTER_BUCKETS	8
#define NTFE_COUNTER_HASH_BITS	10
#define NTFE_COUNTER_HASH	(1U << NTFE_COUNTER_HASH_BITS)
/* A cell with no activity for this long past its longest window is idle. */
#define NTFE_COUNTER_IDLE_FLOOR_SECS	60

struct ntfe_counter_key {
	u8 family;			/* 4 / 6 / 0 (address facts unused) */
	u8 _pad[3];
	s32 ifindex;			/* 0 when the interface fact is unused */
	u8 src[16];
	u8 dst[16];
};

struct ntfe_counter_ring {
	u64 period[NTFE_COUNTER_BUCKETS];	/* which period each bucket holds */
	u64 count[NTFE_COUNTER_BUCKETS];
};

struct ntfe_counter_cell {
	struct hlist_node node;
	struct rcu_head rcu;
	struct ntfe_counter_key key;
	u64 total;
	u64 last_secs;
	struct ntfe_counter_ring rings[];	/* one per table window */
};

struct ntfe_counter_table {
	struct list_head list;
	struct rcu_head rcu;
	char name[PEIOS_NTFE_VIEW_NAME_LEN];
	u64 hash;
	u8 keyspec;
	u32 n_windows;
	u32 windows[PEIOS_NTFE_COUNTER_MAX_WINDOWS];	/* seconds */
	spinlock_t lock;
	u32 n_cells;
	struct hlist_head heads[NTFE_COUNTER_HASH];
};

static LIST_HEAD(ntfe_counter_tables);
static DEFINE_MUTEX(ntfe_counter_publish_lock);
static atomic64_t ntfe_counter_cells_total;

static u64 ntfe_now_secs(void)
{
	return (u64)ktime_get_real_seconds();
}

static u32 ntfe_bucket_secs(u32 window_secs)
{
	return max_t(u32, 1, window_secs / NTFE_COUNTER_BUCKETS);
}

/* Builds the cell key for `keyspec` from the packet; false = a keyed fact
 * is absent (absent-fact law: no cell for this packet).
 */
static bool ntfe_counter_key_of(const struct peios_ntfe_snapshot *snap,
			       u8 keyspec, struct ntfe_counter_key *key)
{
	memset(key, 0, sizeof(*key));
	if (keyspec & (PEIOS_NTFE_KEY_SRC_ADDR | PEIOS_NTFE_KEY_DST_ADDR)) {
		if (!snap->addr_family)
			return false;
		key->family = snap->addr_family;
		if (keyspec & PEIOS_NTFE_KEY_SRC_ADDR)
			memcpy(key->src, snap->src_addr, 16);
		if (keyspec & PEIOS_NTFE_KEY_DST_ADDR)
			memcpy(key->dst, snap->dst_addr, 16);
	}
	if (keyspec & PEIOS_NTFE_KEY_INTERFACE) {
		if (snap->ifindex <= 0)
			return false;
		key->ifindex = snap->ifindex;
	}
	return true;
}

static u32 ntfe_counter_bucket(const struct ntfe_counter_key *key)
{
	return jhash(key, sizeof(*key), 0x504e5043) & (NTFE_COUNTER_HASH - 1);
}

static struct ntfe_counter_table *ntfe_table_find(u64 hash, u8 keyspec)
{
	struct ntfe_counter_table *t;

	list_for_each_entry_rcu(t, &ntfe_counter_tables, list) {
		if (t->hash == hash && t->keyspec == keyspec)
			return t;
	}
	return NULL;
}

static struct ntfe_counter_cell *
ntfe_cell_find(struct ntfe_counter_table *t, const struct ntfe_counter_key *key)
{
	struct ntfe_counter_cell *c;

	hlist_for_each_entry_rcu(c, &t->heads[ntfe_counter_bucket(key)], node) {
		if (!memcmp(&c->key, key, sizeof(*key)))
			return c;
	}
	return NULL;
}

static int ntfe_window_index(const struct ntfe_counter_table *t, u32 window)
{
	u32 i;

	for (i = 0; i < t->n_windows; i++)
		if (t->windows[i] == window)
			return i;
	return -1;
}

static u64 ntfe_ring_sum(const struct ntfe_counter_ring *r, u32 window_secs,
			u64 now)
{
	u64 cur = now / ntfe_bucket_secs(window_secs);
	u64 sum = 0;
	u32 i;

	for (i = 0; i < NTFE_COUNTER_BUCKETS; i++) {
		u64 p = READ_ONCE(r->period[i]);

		if (p <= cur && cur - p < NTFE_COUNTER_BUCKETS)
			sum += READ_ONCE(r->count[i]);
	}
	return sum;
}

static void ntfe_ring_add(struct ntfe_counter_ring *r, u32 window_secs,
			 u64 now, u64 amount)
{
	u64 cur = now / ntfe_bucket_secs(window_secs);
	u32 slot = cur % NTFE_COUNTER_BUCKETS;

	if (r->period[slot] != cur) {
		WRITE_ONCE(r->count[slot], 0);
		WRITE_ONCE(r->period[slot], cur);
	}
	WRITE_ONCE(r->count[slot], r->count[slot] + amount);
}

int peios_ntfe_counter_read(const struct peios_ntfe_snapshot *snap, u64 hash,
			   u8 keyspec, u32 window_secs, u64 *value_out)
{
	struct ntfe_counter_table *t;
	struct ntfe_counter_cell *c;
	struct ntfe_counter_key key;
	int w;

	if (!ntfe_counter_key_of(snap, keyspec, &key))
		return 0;
	t = ntfe_table_find(hash, keyspec);
	if (!t)
		return 0;
	c = ntfe_cell_find(t, &key);
	if (!c)
		return 0;
	if (!window_secs) {
		*value_out = READ_ONCE(c->total);
		return 1;
	}
	w = ntfe_window_index(t, window_secs);
	if (w < 0)
		return 0;
	*value_out = ntfe_ring_sum(&c->rings[w], window_secs, ntfe_now_secs());
	return 1;
}

static u32 ntfe_table_longest_window(const struct ntfe_counter_table *t)
{
	u32 longest = 0, i;

	for (i = 0; i < t->n_windows; i++)
		longest = max(longest, t->windows[i]);
	return longest;
}

/* Under the table lock: frees cells idle past the table's horizon. */
static void ntfe_table_reap(struct ntfe_counter_table *t, u64 now)
{
	u64 horizon = max_t(u64, ntfe_table_longest_window(t),
			    NTFE_COUNTER_IDLE_FLOOR_SECS);
	struct ntfe_counter_cell *c;
	struct hlist_node *tmp;
	u32 b;

	for (b = 0; b < NTFE_COUNTER_HASH; b++) {
		hlist_for_each_entry_safe(c, tmp, &t->heads[b], node) {
			if (now > c->last_secs && now - c->last_secs > horizon) {
				hlist_del_rcu(&c->node);
				kfree_rcu(c, rcu);
				t->n_cells--;
				atomic64_dec(&ntfe_counter_cells_total);
			}
		}
	}
}

static struct ntfe_counter_cell *ntfe_cell_alloc(u32 n_windows, gfp_t gfp)
{
	struct ntfe_counter_cell *c;

	return kzalloc(struct_size(c, rings, n_windows), gfp);
}

/* Under the table lock: the cell for `key`, created if absent; NULL when
 * the table is at its cap with nothing idle, or allocation failed.
 */
static struct ntfe_counter_cell *
ntfe_cell_get(struct ntfe_counter_table *t, const struct ntfe_counter_key *key,
	     u64 now)
{
	struct ntfe_counter_cell *c = ntfe_cell_find(t, key);

	if (c)
		return c;
	if (t->n_cells >= PEIOS_NTFE_COUNTER_MAX_KEYS) {
		ntfe_table_reap(t, now);
		if (t->n_cells >= PEIOS_NTFE_COUNTER_MAX_KEYS)
			return NULL;
	}
	c = ntfe_cell_alloc(t->n_windows, GFP_ATOMIC);
	if (!c)
		return NULL;
	c->key = *key;
	hlist_add_head_rcu(&c->node, &t->heads[ntfe_counter_bucket(key)]);
	t->n_cells++;
	atomic64_inc(&ntfe_counter_cells_total);
	return c;
}

void peios_ntfe_counter_add(const struct peios_ntfe_snapshot *snap, u64 hash,
			   u64 amount)
{
	struct ntfe_counter_table *t;
	u64 now = ntfe_now_secs();
	bool any = false;

	if (!amount) {
		/* COUNT(x, Length) with no length fact: a no-op, counted. */
		atomic64_inc(&peios_ntfe_stats.count_key_absent);
		return;
	}
	list_for_each_entry_rcu(t, &ntfe_counter_tables, list) {
		struct ntfe_counter_cell *c;
		struct ntfe_counter_key key;
		u32 w;

		if (t->hash != hash)
			continue;
		if (!ntfe_counter_key_of(snap, t->keyspec, &key)) {
			atomic64_inc(&peios_ntfe_stats.count_key_absent);
			continue;
		}
		spin_lock_bh(&t->lock);
		c = ntfe_cell_get(t, &key, now);
		if (!c) {
			spin_unlock_bh(&t->lock);
			atomic64_inc(&peios_ntfe_stats.count_refused);
			continue;
		}
		WRITE_ONCE(c->total, c->total + amount);
		c->last_secs = now;
		for (w = 0; w < t->n_windows; w++)
			ntfe_ring_add(&c->rings[w], t->windows[w], now, amount);
		spin_unlock_bh(&t->lock);
		any = true;
	}
	if (any)
		atomic64_inc(&peios_ntfe_stats.count_writes);
}

/* --- publication ---------------------------------------------------- */

struct ntfe_table_spec {
	char name[PEIOS_NTFE_VIEW_NAME_LEN];
	u64 hash;
	u8 keyspec;
	u32 n_windows;
	u32 windows[PEIOS_NTFE_COUNTER_MAX_WINDOWS];
};

static bool ntfe_windows_equal(const struct ntfe_counter_table *t,
			      const struct ntfe_table_spec *s)
{
	u32 i;

	if (t->n_windows != s->n_windows)
		return false;
	for (i = 0; i < s->n_windows; i++)
		if (ntfe_window_index(t, s->windows[i]) < 0)
			return false;
	return true;
}

static void ntfe_table_free_rcu(struct rcu_head *head)
{
	struct ntfe_counter_table *t =
		container_of(head, struct ntfe_counter_table, rcu);
	struct ntfe_counter_cell *c;
	struct hlist_node *tmp;
	u32 b;

	/* After grace: no reader holds the table or its cells. */
	for (b = 0; b < NTFE_COUNTER_HASH; b++) {
		hlist_for_each_entry_safe(c, tmp, &t->heads[b], node) {
			hlist_del(&c->node);
			kfree(c);
			atomic64_dec(&ntfe_counter_cells_total);
		}
	}
	kfree(t);
}

/* Under the publish mutex: a table's window set changed, so every cell
 * needs rings in the new layout. Totals and rings for windows both sets
 * share carry over; new windows start empty and converge.
 */
static int ntfe_table_migrate(struct ntfe_counter_table *t,
			     const struct ntfe_table_spec *s)
{
	u32 b, i;

	spin_lock_bh(&t->lock);
	for (b = 0; b < NTFE_COUNTER_HASH; b++) {
		struct ntfe_counter_cell *c, *fresh;
		struct hlist_node *tmp;

		hlist_for_each_entry_safe(c, tmp, &t->heads[b], node) {
			fresh = ntfe_cell_alloc(s->n_windows, GFP_ATOMIC);
			if (!fresh) {
				spin_unlock_bh(&t->lock);
				return -ENOMEM;
			}
			fresh->key = c->key;
			fresh->total = c->total;
			fresh->last_secs = c->last_secs;
			for (i = 0; i < s->n_windows; i++) {
				int old = ntfe_window_index(t, s->windows[i]);

				if (old >= 0)
					fresh->rings[i] = c->rings[old];
			}
			hlist_replace_rcu(&c->node, &fresh->node);
			kfree_rcu(c, rcu);
		}
	}
	t->n_windows = s->n_windows;
	memcpy(t->windows, s->windows, sizeof(t->windows));
	spin_unlock_bh(&t->lock);
	return 0;
}

static struct ntfe_counter_table *
ntfe_table_create(const struct ntfe_table_spec *s)
{
	struct ntfe_counter_table *t;
	u32 b;

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return NULL;
	memcpy(t->name, s->name, sizeof(t->name));
	t->hash = s->hash;
	t->keyspec = s->keyspec;
	t->n_windows = s->n_windows;
	memcpy(t->windows, s->windows, sizeof(t->windows));
	spin_lock_init(&t->lock);
	for (b = 0; b < NTFE_COUNTER_HASH; b++)
		INIT_HLIST_HEAD(&t->heads[b]);
	return t;
}

int peios_ntfe_counters_publish(const struct peios_ntfe_view *views, u32 count)
{
	struct ntfe_table_spec *specs;
	struct ntfe_counter_table *t, *tmp;
	u32 n_specs = 0, i, j;
	int ret = 0;

	specs = kcalloc(max_t(u32, count, 1), sizeof(*specs), GFP_KERNEL);
	if (!specs)
		return -ENOMEM;

	/* Fold the views into (stream, keyspec) specs with window sets. */
	for (i = 0; i < count; i++) {
		struct ntfe_table_spec *s = NULL;

		for (j = 0; j < n_specs; j++) {
			if (specs[j].hash == views[i].hash &&
			    specs[j].keyspec == views[i].keyspec) {
				s = &specs[j];
				break;
			}
		}
		if (!s) {
			s = &specs[n_specs++];
			memcpy(s->name, views[i].name, sizeof(s->name));
			s->name[sizeof(s->name) - 1] = '\0';
			s->hash = views[i].hash;
			s->keyspec = views[i].keyspec;
		}
		if (!views[i].window_secs)
			continue;	/* the total is always kept */
		for (j = 0; j < s->n_windows; j++)
			if (s->windows[j] == views[i].window_secs)
				break;
		if (j < s->n_windows)
			continue;
		if (s->n_windows >= PEIOS_NTFE_COUNTER_MAX_WINDOWS) {
			ret = -E2BIG;
			goto out;
		}
		s->windows[s->n_windows++] = views[i].window_secs;
	}

	mutex_lock(&ntfe_counter_publish_lock);
	/* Keep / migrate / create. */
	for (i = 0; i < n_specs; i++) {
		struct ntfe_table_spec *s = &specs[i];

		/* The mutex serializes removals; the read lock keeps the
		 * RCU list walk honest under lockdep.
		 */
		rcu_read_lock();
		t = ntfe_table_find(s->hash, s->keyspec);
		rcu_read_unlock();
		if (t) {
			if (!ntfe_windows_equal(t, s)) {
				ret = ntfe_table_migrate(t, s);
				if (ret)
					break;
			}
			continue;
		}
		t = ntfe_table_create(s);
		if (!t) {
			ret = -ENOMEM;
			break;
		}
		list_add_tail_rcu(&t->list, &ntfe_counter_tables);
	}
	/* Retire tables no forest views any more. */
	if (!ret) {
		list_for_each_entry_safe(t, tmp, &ntfe_counter_tables, list) {
			bool wanted = false;

			for (i = 0; i < n_specs; i++) {
				if (specs[i].hash == t->hash &&
				    specs[i].keyspec == t->keyspec) {
					wanted = true;
					break;
				}
			}
			if (!wanted) {
				list_del_rcu(&t->list);
				call_rcu(&t->rcu, ntfe_table_free_rcu);
			}
		}
	}
	mutex_unlock(&ntfe_counter_publish_lock);
out:
	kfree(specs);
	return ret;
}

u64 peios_ntfe_counters_cells(void)
{
	return atomic64_read(&ntfe_counter_cells_total);
}

/* --- the viewer's read: dump every cell of every table ------------------ */

long peios_ntfe_counters_dump(struct peios_ntfe_counters_query *query)
{
	struct peios_ntfe_counter_rec __user *urec =
		u64_to_user_ptr(query->buf);
	u32 max = query->buf_len / sizeof(struct peios_ntfe_counter_rec);
	struct peios_ntfe_counter_rec *rec;
	struct ntfe_counter_table *t;
	u32 written = 0, total = 0;
	u64 now = ntfe_now_secs();
	long ret = 0;

	rec = peios_ntfe_kunit_alloc_should_fail() ? NULL :
		kzalloc(sizeof(*rec), GFP_KERNEL);
	if (!rec)
		return -ENOMEM;

	rcu_read_lock();
	list_for_each_entry_rcu(t, &ntfe_counter_tables, list) {
		u32 b, w;

		for (b = 0; b < NTFE_COUNTER_HASH; b++) {
			struct ntfe_counter_cell *c;

			hlist_for_each_entry_rcu(c, &t->heads[b], node) {
				total++;
				if (written >= max)
					continue;
				memset(rec, 0, sizeof(*rec));
				memcpy(rec->name, t->name, sizeof(rec->name));
				rec->hash = t->hash;
				rec->keyspec = t->keyspec;
				rec->family = c->key.family;
				rec->ifindex = c->key.ifindex;
				memcpy(rec->src_addr, c->key.src, 16);
				memcpy(rec->dst_addr, c->key.dst, 16);
				rec->total = READ_ONCE(c->total);
				rec->last_secs = c->last_secs;
				rec->n_windows = t->n_windows;
				for (w = 0; w < t->n_windows; w++) {
					rec->window_secs[w] = t->windows[w];
					rec->window_value[w] = ntfe_ring_sum(
						&c->rings[w], t->windows[w],
						now);
				}
				rcu_read_unlock();
				if (copy_to_user(&urec[written], rec,
						 sizeof(*rec))) {
					ret = -EFAULT;
					goto out;
				}
				written++;
				rcu_read_lock();
				/* The list may have changed under us; the
				 * dump is a snapshot at best-effort accuracy
				 * (counters are approximate by design).
				 */
			}
		}
	}
	rcu_read_unlock();
out:
	query->count = written;
	query->total = total;
	kfree(rec);
	return ret;
}
