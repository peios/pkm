// SPDX-License-Identifier: GPL-2.0-only
/*
 * Bounded slow-track KMES runtime substrate.
 *
 * Slices 38 and 39 implement:
 * - the internal kernel emission path;
 * - PKM-owned per-CPU buffers;
 * - the first public consumer attach/mmap surface.
 *
 * Slice 40 adds the public userspace emit surface.
 *
 * Slice 41 adds generation-stable ring objects and bounded swap helpers.
 */

#include <linux/anon_inodes.h>
#include <linux/cpumask.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/plist.h>
#include <linux/preempt.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "../../../kernel/futex/futex.h"
#include "../kacs/token_runtime.h"
#include "kmes.h"

#define PKM_KMES_DEFAULT_BUFFER_CAPACITY (4U * 1024U * 1024U)
#define PKM_KMES_DEFAULT_MAX_EVENT_SIZE 65536U
#define PKM_KMES_DEFAULT_MAX_NESTING_DEPTH 32U
#define PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS 10000U
#define PKM_KMES_MIN_BUFFER_CAPACITY 65536ULL
#define PKM_KMES_MAX_BUFFER_CAPACITY 268435456ULL
#define PKM_KMES_MIN_MAX_EVENT_SIZE 1024U
#define PKM_KMES_MAX_MAX_EVENT_SIZE 4194304U
#define PKM_KMES_MIN_MAX_NESTING_DEPTH 4U
#define PKM_KMES_MAX_MAX_NESTING_DEPTH 256U
#define PKM_KMES_MIN_MAX_EMIT_RATE_PER_PROCESS 100U
#define PKM_KMES_MAX_MAX_EMIT_RATE_PER_PROCESS 1000000U
#define PKM_KMES_MAX_KERNEL_TYPE_LEN ((size_t)U16_MAX)
#define PKM_KMES_EARLY_DMESG_TYPE_PREFIX 64U
#define PKM_KMES_PRIVILEGE_SE_TCB (1ULL << 7)
#define PKM_KMES_PRIVILEGE_SE_SECURITY (1ULL << 8)
#define PKM_KMES_PRIVILEGE_SE_AUDIT (1ULL << 21)

struct pkm_kmes_cpu_state {
	refcount_t refs;
	u16 cpu_id;
	u64 generation;
	u64 capacity;
	u64 sequence;
	u64 write_pos;
	u64 tail_pos;
	u64 dropped_events;
	u32 futex_counter;
	struct file *producer_file;
	struct page *producer_meta_page;
	u8 *producer_page;
	u8 *producer_shared_page;
	u8 *consumer_page;
	u8 *data;
};

struct pkm_kmes_cpu_slot {
	u16 cpu_id;
	struct pkm_kmes_cpu_state *live;
};

struct pkm_kmes_fd {
	struct pkm_kmes_cpu_state *ring;
};

struct pkm_kmes_process_view {
	u64 pid;
	const u8 *name;
	size_t name_len;
	const u8 *path;
	size_t path_len;
};

struct pkm_kmes_staged_event {
	u8 *bytes;
	const u8 *event_type;
	const u8 *payload;
	u16 event_type_len;
	u32 payload_len;
	u32 header_size;
	u32 event_size;
};

static struct pkm_kmes_cpu_slot *pkm_kmes_cpus;
static unsigned int pkm_kmes_cpu_slots;
static unsigned int pkm_kmes_cpu_count;
static bool pkm_kmes_ready;
static u64 pkm_kmes_active_buffer_capacity =
	PKM_KMES_DEFAULT_BUFFER_CAPACITY;
static u32 pkm_kmes_active_max_event_size =
	PKM_KMES_DEFAULT_MAX_EVENT_SIZE;
static u32 pkm_kmes_active_max_nesting_depth =
	PKM_KMES_DEFAULT_MAX_NESTING_DEPTH;
static u32 pkm_kmes_active_max_emit_rate_per_process =
	PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS;
static DEFINE_MUTEX(pkm_kmes_topology_lock);
static const u8 pkm_kmes_ring_magic[8] = {
	0x4b, 0x4d, 0x45, 0x53, 0x52, 0x49, 0x4e, 0x47,
};

static long pkm_kmes_swap_capacity_locked(u64 new_capacity);

extern int kacs_rust_kmes_validate_staged_event(const u8 *event_type_ptr,
						size_t event_type_len,
						const u8 *payload_ptr,
						size_t payload_len,
						u32 max_nesting_depth);

#ifdef CONFIG_SECURITY_PKM_KUNIT
struct pkm_kmes_kunit_process_override {
	bool enabled;
	u64 pid;
	char name[TASK_COMM_LEN];
	size_t name_len;
	char path[PATH_MAX];
	size_t path_len;
};

static struct pkm_kmes_kunit_process_override pkm_kmes_override;
static bool pkm_kmes_kunit_fail_next_ring_alloc;
#endif

static size_t pkm_kmes_mapping_size(u64 capacity)
{
	return (size_t)(KMES_METADATA_TOTAL_SIZE + (2 * capacity));
}

static void pkm_kmes_meta_store_u16(u8 *page, size_t offset, u16 value)
{
	*(__le16 *)(page + offset) = cpu_to_le16(value);
}

static void pkm_kmes_meta_store_u32(u8 *page, size_t offset, u32 value)
{
	*(__le32 *)(page + offset) = cpu_to_le32(value);
}

static void pkm_kmes_meta_store_u64(u8 *page, size_t offset, u64 value)
{
	*(__le64 *)(page + offset) = cpu_to_le64(value);
}

static u16 pkm_kmes_meta_load_u16(const u8 *page, size_t offset)
{
	return le16_to_cpu(*(__le16 *)(page + offset));
}

static u32 pkm_kmes_meta_load_u32(const u8 *page, size_t offset)
{
	return le32_to_cpu(*(__le32 *)(page + offset));
}

static u64 pkm_kmes_meta_load_u64(const u8 *page, size_t offset)
{
	return le64_to_cpu(*(__le64 *)(page + offset));
}

static void pkm_kmes_ring_get(struct pkm_kmes_cpu_state *cpu)
{
	refcount_inc(&cpu->refs);
}

static void pkm_kmes_release_producer_page(struct pkm_kmes_cpu_state *cpu)
{
	if (cpu->producer_shared_page)
		vunmap(cpu->producer_shared_page);
	cpu->producer_shared_page = NULL;

	if (cpu->producer_meta_page)
		put_page(cpu->producer_meta_page);
	cpu->producer_meta_page = NULL;

	if (cpu->producer_file)
		fput(cpu->producer_file);
	cpu->producer_file = NULL;

	if (cpu->producer_page)
		free_page((unsigned long)cpu->producer_page);
	cpu->producer_page = NULL;
}

static void pkm_kmes_ring_free(struct pkm_kmes_cpu_state *cpu)
{
	if (!cpu)
		return;

	pkm_kmes_release_producer_page(cpu);
	if (cpu->consumer_page)
		free_page((unsigned long)cpu->consumer_page);
	vfree(cpu->data);
	kfree(cpu);
}

static void pkm_kmes_ring_put(struct pkm_kmes_cpu_state *cpu)
{
	if (!cpu)
		return;
	if (refcount_dec_and_test(&cpu->refs))
		pkm_kmes_ring_free(cpu);
}

static void pkm_kmes_store_tail_pos(struct pkm_kmes_cpu_state *cpu, u64 value)
{
	cpu->tail_pos = value;
	smp_store_release((__le64 *)(cpu->producer_page +
				     KMES_PRODUCER_TAIL_POS_OFFSET),
			  cpu_to_le64(value));
	if (cpu->producer_shared_page) {
		smp_store_release((__le64 *)(cpu->producer_shared_page +
					     KMES_PRODUCER_TAIL_POS_OFFSET),
				  cpu_to_le64(value));
	}
}

static void pkm_kmes_store_write_pos(struct pkm_kmes_cpu_state *cpu, u64 value)
{
	cpu->write_pos = value;
	smp_store_release((__le64 *)(cpu->producer_page +
				     KMES_PRODUCER_WRITE_POS_OFFSET),
			  cpu_to_le64(value));
	if (cpu->producer_shared_page) {
		smp_store_release((__le64 *)(cpu->producer_shared_page +
					     KMES_PRODUCER_WRITE_POS_OFFSET),
				  cpu_to_le64(value));
	}
}

static void pkm_kmes_store_futex_counter(struct pkm_kmes_cpu_state *cpu,
					 u32 value)
{
	cpu->futex_counter = value;
	smp_store_release((__le32 *)(cpu->producer_page +
				     KMES_PRODUCER_FUTEX_COUNTER_OFFSET),
			  cpu_to_le32(value));
	if (cpu->producer_shared_page) {
		smp_store_release((__le32 *)(cpu->producer_shared_page +
					     KMES_PRODUCER_FUTEX_COUNTER_OFFSET),
				  cpu_to_le32(value));
	}
}

static void pkm_kmes_store_generation(struct pkm_kmes_cpu_state *cpu, u64 value)
{
	cpu->generation = value;
	smp_store_release((__le64 *)(cpu->producer_page +
				     KMES_PRODUCER_GENERATION_OFFSET),
			  cpu_to_le64(value));
	if (cpu->producer_shared_page) {
		smp_store_release((__le64 *)(cpu->producer_shared_page +
					     KMES_PRODUCER_GENERATION_OFFSET),
				  cpu_to_le64(value));
	}
}

static bool pkm_kmes_need_wake(const struct pkm_kmes_cpu_state *cpu)
{
	return READ_ONCE(*(u8 *)(cpu->consumer_page +
				 KMES_CONSUMER_NEED_WAKE_OFFSET)) != 0;
}

static bool pkm_kmes_buffer_capacity_valid(u64 capacity)
{
	if (capacity < PKM_KMES_MIN_BUFFER_CAPACITY ||
	    capacity > PKM_KMES_MAX_BUFFER_CAPACITY)
		return false;
	if (capacity & (capacity - 1))
		return false;
	return true;
}

static bool pkm_kmes_runtime_config_valid(
	const struct pkm_kmes_runtime_config *config)
{
	if (!config)
		return false;
	if (!pkm_kmes_buffer_capacity_valid(config->buffer_capacity))
		return false;
	if (config->max_event_size < PKM_KMES_MIN_MAX_EVENT_SIZE ||
	    config->max_event_size > PKM_KMES_MAX_MAX_EVENT_SIZE)
		return false;
	if (config->max_nesting_depth < PKM_KMES_MIN_MAX_NESTING_DEPTH ||
	    config->max_nesting_depth > PKM_KMES_MAX_MAX_NESTING_DEPTH)
		return false;
	if (config->max_emit_rate_per_process <
		    PKM_KMES_MIN_MAX_EMIT_RATE_PER_PROCESS ||
	    config->max_emit_rate_per_process >
		    PKM_KMES_MAX_MAX_EMIT_RATE_PER_PROCESS)
		return false;
	return true;
}

static void pkm_kmes_runtime_config_defaults(
	struct pkm_kmes_runtime_config *config)
{
	config->buffer_capacity = PKM_KMES_DEFAULT_BUFFER_CAPACITY;
	config->max_event_size = PKM_KMES_DEFAULT_MAX_EVENT_SIZE;
	config->max_nesting_depth = PKM_KMES_DEFAULT_MAX_NESTING_DEPTH;
	config->max_emit_rate_per_process =
		PKM_KMES_DEFAULT_MAX_EMIT_RATE_PER_PROCESS;
}

static void pkm_kmes_runtime_config_store_locked(
	const struct pkm_kmes_runtime_config *config)
{
	WRITE_ONCE(pkm_kmes_active_buffer_capacity, config->buffer_capacity);
	WRITE_ONCE(pkm_kmes_active_max_event_size, config->max_event_size);
	WRITE_ONCE(pkm_kmes_active_max_nesting_depth,
		   config->max_nesting_depth);
	WRITE_ONCE(pkm_kmes_active_max_emit_rate_per_process,
		   config->max_emit_rate_per_process);
}

static void pkm_kmes_futex_wake(struct pkm_kmes_cpu_state *cpu)
{
	union futex_key key = { };
	struct futex_hash_bucket *hb;
	struct futex_q *q;
	struct futex_q *next;
	u64 i_seq;
	DEFINE_WAKE_Q(wake_q);

	if (!cpu || !cpu->producer_file || !cpu->producer_meta_page)
		return;

	i_seq = atomic64_read(&file_inode(cpu->producer_file)->i_sequence);
	if (!i_seq)
		return;

	/* Shared futex waiters key off the producer page's backing inode sequence. */
	key.shared.i_seq = i_seq;
	key.shared.pgoff = 0;
	key.shared.offset = KMES_PRODUCER_FUTEX_COUNTER_OFFSET |
			    FUT_OFF_INODE;

	hb = futex_hash(&key);
	if (!futex_hb_waiters_pending(hb))
		return;

	spin_lock(&hb->lock);
	plist_for_each_entry_safe(q, next, &hb->chain, list) {
		if (!futex_match(&q->key, &key))
			continue;
		futex_wake_mark(&wake_q, q);
	}
	spin_unlock(&hb->lock);
	wake_up_q(&wake_q);
}

static bool pkm_kmes_note_wake(struct pkm_kmes_cpu_state *cpu)
{
	if (!pkm_kmes_need_wake(cpu))
		return false;

	pkm_kmes_store_futex_counter(cpu, cpu->futex_counter + 1);
	return true;
}

static void pkm_kmes_init_metadata_pages(struct pkm_kmes_cpu_state *cpu)
{
	memcpy(cpu->producer_page + KMES_PRODUCER_MAGIC_OFFSET,
	       pkm_kmes_ring_magic, sizeof(pkm_kmes_ring_magic));
	if (cpu->producer_shared_page) {
		memcpy(cpu->producer_shared_page + KMES_PRODUCER_MAGIC_OFFSET,
		       pkm_kmes_ring_magic, sizeof(pkm_kmes_ring_magic));
	}
	pkm_kmes_meta_store_u32(cpu->producer_page,
				KMES_PRODUCER_VERSION_OFFSET,
				KMES_RING_VERSION);
	if (cpu->producer_shared_page) {
		pkm_kmes_meta_store_u32(cpu->producer_shared_page,
					KMES_PRODUCER_VERSION_OFFSET,
					KMES_RING_VERSION);
	}
	pkm_kmes_meta_store_u16(cpu->producer_page,
				KMES_PRODUCER_CPU_ID_OFFSET, cpu->cpu_id);
	if (cpu->producer_shared_page) {
		pkm_kmes_meta_store_u16(cpu->producer_shared_page,
					KMES_PRODUCER_CPU_ID_OFFSET,
					cpu->cpu_id);
	}
	pkm_kmes_meta_store_u64(cpu->producer_page,
				KMES_PRODUCER_CAPACITY_OFFSET,
				cpu->capacity);
	if (cpu->producer_shared_page) {
		pkm_kmes_meta_store_u64(cpu->producer_shared_page,
					KMES_PRODUCER_CAPACITY_OFFSET,
					cpu->capacity);
	}
	pkm_kmes_meta_store_u64(cpu->producer_page,
				KMES_PRODUCER_DATA_OFFSET_OFFSET,
				KMES_METADATA_TOTAL_SIZE);
	if (cpu->producer_shared_page) {
		pkm_kmes_meta_store_u64(cpu->producer_shared_page,
					KMES_PRODUCER_DATA_OFFSET_OFFSET,
					KMES_METADATA_TOTAL_SIZE);
	}
	pkm_kmes_store_generation(cpu, cpu->generation);
	pkm_kmes_store_write_pos(cpu, cpu->write_pos);
	pkm_kmes_store_tail_pos(cpu, cpu->tail_pos);
	pkm_kmes_store_futex_counter(cpu, cpu->futex_counter);
}

static struct pkm_kmes_cpu_state *pkm_kmes_ring_alloc(u16 cpu_id, u64 generation,
						       u64 capacity)
{
	struct pkm_kmes_cpu_state *cpu;

#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (READ_ONCE(pkm_kmes_kunit_fail_next_ring_alloc)) {
		WRITE_ONCE(pkm_kmes_kunit_fail_next_ring_alloc, false);
		return ERR_PTR(-ENOMEM);
	}
#endif

	cpu = kzalloc(sizeof(*cpu), GFP_KERNEL);
	if (!cpu)
		return ERR_PTR(-ENOMEM);

	refcount_set(&cpu->refs, 1);
	cpu->cpu_id = cpu_id;
	cpu->generation = generation;
	cpu->capacity = capacity;
	cpu->producer_page = (u8 *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	cpu->consumer_page = (u8 *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	cpu->data = vzalloc(capacity);
	if (!cpu->producer_page || !cpu->consumer_page || !cpu->data) {
		pkm_kmes_ring_free(cpu);
		return ERR_PTR(-ENOMEM);
	}

	pkm_kmes_init_metadata_pages(cpu);
	return cpu;
}

static void pkm_kmes_write_u16_at(u8 *data, u64 capacity, u64 pos, u16 value)
{
	data[(pos + 0) & (capacity - 1)] = (u8)(value & 0xff);
	data[(pos + 1) & (capacity - 1)] = (u8)((value >> 8) & 0xff);
}

static void pkm_kmes_write_u32_at(u8 *data, u64 capacity, u64 pos, u32 value)
{
	data[(pos + 0) & (capacity - 1)] = (u8)(value & 0xff);
	data[(pos + 1) & (capacity - 1)] = (u8)((value >> 8) & 0xff);
	data[(pos + 2) & (capacity - 1)] = (u8)((value >> 16) & 0xff);
	data[(pos + 3) & (capacity - 1)] = (u8)((value >> 24) & 0xff);
}

static void pkm_kmes_write_u64_at(u8 *data, u64 capacity, u64 pos, u64 value)
{
	data[(pos + 0) & (capacity - 1)] = (u8)(value & 0xff);
	data[(pos + 1) & (capacity - 1)] = (u8)((value >> 8) & 0xff);
	data[(pos + 2) & (capacity - 1)] = (u8)((value >> 16) & 0xff);
	data[(pos + 3) & (capacity - 1)] = (u8)((value >> 24) & 0xff);
	data[(pos + 4) & (capacity - 1)] = (u8)((value >> 32) & 0xff);
	data[(pos + 5) & (capacity - 1)] = (u8)((value >> 40) & 0xff);
	data[(pos + 6) & (capacity - 1)] = (u8)((value >> 48) & 0xff);
	data[(pos + 7) & (capacity - 1)] = (u8)((value >> 56) & 0xff);
}

static u16 pkm_kmes_read_u16_at(const u8 *data, u64 capacity, u64 pos)
{
	return (u16)data[(pos + 0) & (capacity - 1)] |
	       ((u16)data[(pos + 1) & (capacity - 1)] << 8);
}

static u32 pkm_kmes_read_u32_at(const u8 *data, u64 capacity, u64 pos)
{
	return (u32)data[(pos + 0) & (capacity - 1)] |
	       ((u32)data[(pos + 1) & (capacity - 1)] << 8) |
	       ((u32)data[(pos + 2) & (capacity - 1)] << 16) |
	       ((u32)data[(pos + 3) & (capacity - 1)] << 24);
}

static u64 pkm_kmes_read_u64_at(const u8 *data, u64 capacity, u64 pos)
{
	return (u64)data[(pos + 0) & (capacity - 1)] |
	       ((u64)data[(pos + 1) & (capacity - 1)] << 8) |
	       ((u64)data[(pos + 2) & (capacity - 1)] << 16) |
	       ((u64)data[(pos + 3) & (capacity - 1)] << 24) |
	       ((u64)data[(pos + 4) & (capacity - 1)] << 32) |
	       ((u64)data[(pos + 5) & (capacity - 1)] << 40) |
	       ((u64)data[(pos + 6) & (capacity - 1)] << 48) |
	       ((u64)data[(pos + 7) & (capacity - 1)] << 56);
}

static void pkm_kmes_write_bytes_at(u8 *data, u64 capacity, u64 pos,
				    const void *src, size_t len)
{
	size_t offset;
	size_t first_len;

	if (!len)
		return;

	offset = (size_t)(pos & (capacity - 1));
	first_len = min_t(size_t, len, (size_t)capacity - offset);
	memcpy(data + offset, src, first_len);
	if (first_len < len)
		memcpy(data, (const u8 *)src + first_len, len - first_len);
}

static void pkm_kmes_copy_bytes_from_ring(const u8 *data, u64 capacity, u64 pos,
					  void *dst, size_t len)
{
	size_t offset;
	size_t first_len;

	if (!len)
		return;

	offset = (size_t)(pos & (capacity - 1));
	first_len = min_t(size_t, len, (size_t)capacity - offset);
	memcpy(dst, data + offset, first_len);
	if (first_len < len)
		memcpy((u8 *)dst + first_len, data, len - first_len);
}

static bool pkm_kmes_ring_bytes_equal(const u8 *data, u64 capacity, u64 pos,
				      const void *expected, size_t len)
{
	size_t offset;
	size_t first_len;

	if (!len)
		return true;

	offset = (size_t)(pos & (capacity - 1));
	first_len = min_t(size_t, len, (size_t)capacity - offset);
	if (memcmp(data + offset, expected, first_len))
		return false;
	if (first_len < len &&
	    memcmp(data, (const u8 *)expected + first_len, len - first_len))
		return false;

	return true;
}

static void pkm_kmes_drop_event(struct pkm_kmes_cpu_state *cpu)
{
	cpu->dropped_events++;
}

static void pkm_kmes_reserve_space_local(struct pkm_kmes_cpu_state *cpu,
					 u64 *tail_io, u64 write_pos,
					 size_t event_size)
{
	u64 next_tail = *tail_io;
	u64 used = write_pos - next_tail;

	while (used + event_size > cpu->capacity) {
		u32 overwritten_size =
			pkm_kmes_read_u32_at(cpu->data, cpu->capacity, next_tail);

		if (overwritten_size == 0 ||
		    overwritten_size > cpu->capacity ||
		    overwritten_size > write_pos - next_tail) {
			next_tail = write_pos;
			break;
		}

		next_tail += overwritten_size;
		used = write_pos - next_tail;
	}

	*tail_io = next_tail;
}

static void pkm_kmes_reserve_space(struct pkm_kmes_cpu_state *cpu,
				   size_t event_size)
{
	u64 next_tail = cpu->tail_pos;
	u64 used = cpu->write_pos - next_tail;

	while (used + event_size > cpu->capacity) {
		u32 overwritten_size =
			pkm_kmes_read_u32_at(cpu->data, cpu->capacity, next_tail);

		if (overwritten_size == 0 ||
		    overwritten_size > cpu->capacity ||
		    overwritten_size > cpu->write_pos - next_tail) {
			next_tail = cpu->write_pos;
			break;
		}

		next_tail += overwritten_size;
		used = cpu->write_pos - next_tail;
	}

	pkm_kmes_store_tail_pos(cpu, next_tail);
}

static void pkm_kmes_write_event_at(struct pkm_kmes_cpu_state *cpu, u64 pos,
				    u8 origin_class, const kacs_uuid_t *eff_guid,
				    const kacs_uuid_t *true_guid,
				    const kacs_uuid_t *proc_guid,
				    const void *event_type,
				    size_t event_type_len, const void *payload,
				    size_t payload_len, u64 timestamp,
				    u64 sequence)
{
	u32 header_size = KMES_EVENT_HEADER_BASE_SIZE + (u32)event_type_len;
	u32 event_size = header_size + (u32)payload_len;

	pkm_kmes_write_u32_at(cpu->data, cpu->capacity, pos, event_size);
	pos += sizeof(u32);
	pkm_kmes_write_u32_at(cpu->data, cpu->capacity, pos, header_size);
	pos += sizeof(u32);
	pkm_kmes_write_u64_at(cpu->data, cpu->capacity, pos, timestamp);
	pos += sizeof(u64);
	pkm_kmes_write_u64_at(cpu->data, cpu->capacity, pos, sequence);
	pos += sizeof(u64);
	pkm_kmes_write_u16_at(cpu->data, cpu->capacity, pos, cpu->cpu_id);
	pos += sizeof(u16);
	pkm_kmes_write_bytes_at(cpu->data, cpu->capacity, pos, &origin_class, 1);
	pos += 1;
	pkm_kmes_write_bytes_at(cpu->data, cpu->capacity, pos, eff_guid->bytes,
				KMES_EVENT_GUID_SIZE);
	pos += KMES_EVENT_GUID_SIZE;
	pkm_kmes_write_bytes_at(cpu->data, cpu->capacity, pos, true_guid->bytes,
				KMES_EVENT_GUID_SIZE);
	pos += KMES_EVENT_GUID_SIZE;
	pkm_kmes_write_bytes_at(cpu->data, cpu->capacity, pos, proc_guid->bytes,
				KMES_EVENT_GUID_SIZE);
	pos += KMES_EVENT_GUID_SIZE;
	pkm_kmes_write_u16_at(cpu->data, cpu->capacity, pos,
			      (u16)event_type_len);
	pos += sizeof(u16);
	pkm_kmes_write_bytes_at(cpu->data, cpu->capacity, pos, event_type,
				event_type_len);
	pos += event_type_len;
	pkm_kmes_write_bytes_at(cpu->data, cpu->capacity, pos, payload,
				payload_len);
}

static void pkm_kmes_write_event(struct pkm_kmes_cpu_state *cpu, u8 origin_class,
				 const kacs_uuid_t *eff_guid,
				 const kacs_uuid_t *true_guid,
				 const kacs_uuid_t *proc_guid,
				 const void *event_type, size_t event_type_len,
				 const void *payload, size_t payload_len,
				 u64 timestamp, u64 sequence,
				 bool *wake_needed_out)
{
	u32 event_size = KMES_EVENT_HEADER_BASE_SIZE + (u32)event_type_len +
			 (u32)payload_len;

	pkm_kmes_write_event_at(cpu, cpu->write_pos, origin_class, eff_guid,
				true_guid, proc_guid, event_type,
				event_type_len, payload, payload_len, timestamp,
				sequence);

	pkm_kmes_store_write_pos(cpu, cpu->write_pos + event_size);
	if (wake_needed_out)
		*wake_needed_out = pkm_kmes_note_wake(cpu);
}

static void pkm_kmes_log_early_event(unsigned int cpu_id, u64 sequence,
				     u8 origin_class, const void *event_type,
				     size_t event_type_len, size_t payload_len,
				     size_t event_size)
{
	size_t type_prefix_len;

	if (system_state >= SYSTEM_RUNNING)
		return;

	type_prefix_len = min(event_type_len,
			      (size_t)PKM_KMES_EARLY_DMESG_TYPE_PREFIX);
	pr_info("pkm-kmes: early event cpu=%u seq=%llu origin=%u event_size=%zu type_len=%zu payload_len=%zu type=\"%.*s\"%s\n",
		cpu_id, (unsigned long long)sequence, origin_class, event_size,
		event_type_len, payload_len, (int)type_prefix_len,
		(const char *)event_type,
		event_type_len > type_prefix_len ? "..." : "");
}

static int pkm_kmes_runtime_capacity(u64 *capacity_out)
{
	unsigned int cpu;

	if (!capacity_out)
		return -EINVAL;
	if (!pkm_kmes_ready || !pkm_kmes_cpus || pkm_kmes_cpu_count == 0)
		return -ENOMEM;

	for (cpu = 0; cpu < pkm_kmes_cpu_slots; cpu++) {
		struct pkm_kmes_cpu_state *ring =
			READ_ONCE(pkm_kmes_cpus[cpu].live);

		if (!ring || !ring->data)
			continue;
		*capacity_out = ring->capacity;
		return 0;
	}

	return -ENOMEM;
}

int pkm_kmes_runtime_config_snapshot(struct pkm_kmes_runtime_config *out)
{
	if (!out)
		return -EINVAL;

	out->buffer_capacity = READ_ONCE(pkm_kmes_active_buffer_capacity);
	out->max_event_size = READ_ONCE(pkm_kmes_active_max_event_size);
	out->max_nesting_depth = READ_ONCE(pkm_kmes_active_max_nesting_depth);
	out->max_emit_rate_per_process =
		READ_ONCE(pkm_kmes_active_max_emit_rate_per_process);
	return 0;
}

u32 pkm_kmes_runtime_max_emit_rate_per_process(void)
{
	return READ_ONCE(pkm_kmes_active_max_emit_rate_per_process);
}

long pkm_kmes_runtime_config_apply(
	const struct pkm_kmes_runtime_config *config)
{
	u64 current_capacity = 0;
	u32 old_rate;
	long ret;

	if (!pkm_kmes_runtime_config_valid(config))
		return -EINVAL;

	mutex_lock(&pkm_kmes_topology_lock);
	old_rate = READ_ONCE(pkm_kmes_active_max_emit_rate_per_process);
	ret = pkm_kmes_runtime_capacity(&current_capacity);
	if (ret)
		goto out;

	if (config->buffer_capacity != current_capacity) {
		ret = pkm_kmes_swap_capacity_locked(config->buffer_capacity);
		if (ret)
			goto out;
	}

	pkm_kmes_runtime_config_store_locked(config);
	if (config->max_emit_rate_per_process != old_rate)
		pkm_kmes_rate_buckets_reconfigure(
			config->max_emit_rate_per_process);
	ret = 0;

out:
	mutex_unlock(&pkm_kmes_topology_lock);
	return ret;
}

static long pkm_kmes_require_audit(const void *token, bool *tcb_exempt_out)
{
	if (!tcb_exempt_out)
		return -EINVAL;
	if (!token)
		return -EPERM;
	if (!kacs_rust_token_has_enabled_privilege(token,
						   PKM_KMES_PRIVILEGE_SE_AUDIT))
		return -EPERM;
	if (!kacs_rust_token_mark_privileges_used(token,
						  PKM_KMES_PRIVILEGE_SE_AUDIT))
		return -EPERM;

	if (kacs_rust_token_has_enabled_privilege(token,
						  PKM_KMES_PRIVILEGE_SE_TCB)) {
		if (!kacs_rust_token_mark_privileges_used(
			    token, PKM_KMES_PRIVILEGE_SE_TCB))
			return -EPERM;
		*tcb_exempt_out = true;
	} else {
		*tcb_exempt_out = false;
	}

	return 0;
}

static long pkm_kmes_declared_event_size(u16 event_type_len, u32 payload_len,
					 u32 *header_size_out,
					 u32 *event_size_out)
{
	size_t header_size;
	size_t event_size;

	if (check_add_overflow((size_t)KMES_EVENT_HEADER_BASE_SIZE,
			       (size_t)event_type_len, &header_size))
		return -EINVAL;
	if (check_add_overflow(header_size, (size_t)payload_len, &event_size))
		return -EINVAL;
	if (header_size > U32_MAX || event_size > U32_MAX)
		return -EINVAL;

	*header_size_out = (u32)header_size;
	*event_size_out = (u32)event_size;
	return 0;
}

static long pkm_kmes_validate_declared_size(u64 ring_capacity,
					    u32 max_event_size,
					    u16 event_type_len,
					    u32 payload_len,
					    struct pkm_kmes_staged_event *out)
{
	u32 header_size;
	u32 event_size;
	long ret;

	if (!out)
		return -EINVAL;

	ret = pkm_kmes_declared_event_size(event_type_len, payload_len,
					   &header_size, &event_size);
	if (ret)
		return ret;
	if (event_size > max_event_size)
		return -ENOSPC;
	if ((u64)event_size > ring_capacity / 2)
		return -ENOSPC;

	out->event_type_len = event_type_len;
	out->payload_len = payload_len;
	out->header_size = header_size;
	out->event_size = event_size;
	return 0;
}

static long pkm_kmes_copy_bytes(void *dst, const void *src, size_t len,
				bool from_user)
{
	if (!len)
		return 0;
	if (!src)
		return -EFAULT;
	if (from_user) {
		if (copy_from_user(dst, (const void __user *)src, len))
			return -EFAULT;
	} else {
		memcpy(dst, src, len);
	}

	return 0;
}

static void pkm_kmes_staged_event_reset(struct pkm_kmes_staged_event *event)
{
	if (!event)
		return;

	kvfree(event->bytes);
	memset(event, 0, sizeof(*event));
}

static long pkm_kmes_stage_event(u64 ring_capacity, u32 max_event_size,
				 u32 max_nesting_depth,
				 const void *event_type,
				 u16 event_type_len,
				 const void *payload,
				 u32 payload_len,
				 bool from_user,
				 struct pkm_kmes_staged_event *out)
{
	size_t staged_len;
	u8 *bytes;
	long ret;

	if (!out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	ret = pkm_kmes_validate_declared_size(ring_capacity, max_event_size,
					      event_type_len,
					      payload_len, out);
	if (ret)
		return ret;

	staged_len = (size_t)event_type_len + (size_t)payload_len;
	bytes = kvmalloc(staged_len ? staged_len : 1, GFP_KERNEL);
	if (!bytes)
		return -ENOMEM;

	ret = pkm_kmes_copy_bytes(bytes, event_type, event_type_len, from_user);
	if (ret)
		goto fail;
	ret = pkm_kmes_copy_bytes(bytes + event_type_len, payload, payload_len,
				  from_user);
	if (ret)
		goto fail;
	ret = kacs_rust_kmes_validate_staged_event(
		bytes, event_type_len, bytes + event_type_len, payload_len,
		max_nesting_depth);
	if (ret)
		goto fail;

	out->bytes = bytes;
	out->event_type = bytes;
	out->payload = bytes + event_type_len;
	return 0;

fail:
	kvfree(bytes);
	memset(out, 0, sizeof(*out));
	return ret;
}

static long pkm_kmes_emit_staged_events(const struct pkm_kmes_staged_event *events,
					u32 count, u8 origin_class)
{
	struct pkm_kmes_cpu_slot *slot = NULL;
	struct pkm_kmes_cpu_state *cpu = NULL;
	u64 timestamp;
	u64 write_pos;
	u64 tail_pos;
	u64 sequence;
	u64 first_sequence;
	unsigned int cpu_id;
	kacs_uuid_t eff_guid;
	kacs_uuid_t true_guid;
	kacs_uuid_t proc_guid;
	u32 index;
	bool wake_needed = false;

	if (!count)
		return 0;
	if (!events || !pkm_kmes_ready || !pkm_kmes_cpus)
		return -ENOMEM;

	preempt_disable();

	cpu_id = smp_processor_id();
	if (cpu_id >= pkm_kmes_cpu_slots) {
		preempt_enable();
		return -ENOMEM;
	}

	slot = &pkm_kmes_cpus[cpu_id];
	cpu = READ_ONCE(slot->live);
	if (!cpu || !cpu->data) {
		preempt_enable();
		return -ENOMEM;
	}
	if (cpu->cpu_id != cpu_id) {
		preempt_enable();
		return -EINVAL;
	}

	for (index = 0; index < count; index++) {
		if (events[index].event_size > cpu->capacity / 2) {
			preempt_enable();
			return -ENOSPC;
		}
	}

	timestamp = ktime_get_real_ns();
	/*
	 * Identity stamps are captured once and shared by every event in the
	 * batch: the batch runs preempt-disabled on one CPU, so the emitting
	 * thread's identity cannot change mid-batch. The three KACS accessors
	 * are preempt-safe (RCU reads of current's creds plus a 16-byte copy)
	 * and yield the null GUID when no identity is available.
	 */
	eff_guid = kacs_effective_token_guid();
	true_guid = kacs_primary_token_guid();
	proc_guid = kacs_process_guid();
	write_pos = cpu->write_pos;
	tail_pos = cpu->tail_pos;
	sequence = cpu->sequence;
	first_sequence = sequence + 1;

	for (index = 0; index < count; index++) {
		pkm_kmes_reserve_space_local(cpu, &tail_pos, write_pos,
					     events[index].event_size);
		sequence++;
		pkm_kmes_write_event_at(cpu, write_pos, origin_class, &eff_guid,
					&true_guid, &proc_guid,
					events[index].event_type,
					events[index].event_type_len,
					events[index].payload,
					events[index].payload_len, timestamp,
					sequence);
		write_pos += events[index].event_size;
	}

	cpu->sequence = sequence;
	pkm_kmes_store_tail_pos(cpu, tail_pos);
	pkm_kmes_store_write_pos(cpu, write_pos);
	wake_needed = pkm_kmes_note_wake(cpu);

	preempt_enable();
	for (index = 0; index < count; index++) {
		pkm_kmes_log_early_event(cpu_id, first_sequence + index,
					 origin_class, events[index].event_type,
					 events[index].event_type_len,
					 events[index].payload_len,
					 events[index].event_size);
	}
	if (wake_needed)
		pkm_kmes_futex_wake(cpu);

	return 0;
}

static long pkm_kmes_emit_one_for_token(const void *token, const void *event_type,
					u16 event_type_len, const void *payload,
					u32 payload_len, bool from_user)
{
	struct pkm_kmes_staged_event event = { };
	struct pkm_kmes_runtime_config config = { };
	u64 ring_capacity = 0;
	bool tcb_exempt;
	bool reserved = false;
	long ret;

	ret = pkm_kmes_require_audit(token, &tcb_exempt);
	if (ret)
		return ret;

	if (!tcb_exempt) {
		ret = pkm_kmes_current_process_rate_reserve(1);
		if (ret)
			return ret;
		reserved = true;
	}

	if (event_type_len == 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = pkm_kmes_runtime_capacity(&ring_capacity);
	if (ret)
		goto out;
	ret = pkm_kmes_runtime_config_snapshot(&config);
	if (ret)
		goto out;

	ret = pkm_kmes_stage_event(ring_capacity, config.max_event_size,
				   config.max_nesting_depth, event_type,
				   event_type_len,
				   payload, payload_len, from_user, &event);
	if (ret)
		goto out;

	ret = pkm_kmes_emit_staged_events(&event, 1, KMES_ORIGIN_USERSPACE);
	if (ret)
		goto out;

	reserved = false;
	ret = 0;

out:
	pkm_kmes_staged_event_reset(&event);
	if (reserved)
		pkm_kmes_current_process_rate_refund(1);
	return ret;
}

static long pkm_kmes_copy_entry_array_user(
	const struct kmes_emit_entry __user *entries, u32 count,
	struct kmes_emit_entry **out_entries)
{
	size_t bytes = (size_t)count * sizeof(*entries);
	struct kmes_emit_entry *copy;

	if (!out_entries)
		return -EINVAL;
	*out_entries = NULL;
	if (!entries)
		return -EFAULT;

	copy = memdup_user(entries, bytes);
	if (IS_ERR(copy))
		return PTR_ERR(copy);

	*out_entries = copy;
	return 0;
}

static long pkm_kmes_copy_entry_array_kernel(const struct kmes_emit_entry *entries,
					     u32 count,
					     struct kmes_emit_entry **out_entries)
{
	size_t bytes = (size_t)count * sizeof(*entries);
	struct kmes_emit_entry *copy;

	if (!out_entries)
		return -EINVAL;
	*out_entries = NULL;
	if (!entries)
		return -EINVAL;

	copy = kmemdup(entries, bytes, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;

	*out_entries = copy;
	return 0;
}

static long pkm_kmes_stage_batch_events(const struct kmes_emit_entry *entries,
					u32 count, bool from_user,
					struct pkm_kmes_staged_event *staged,
					u32 *validated_out)
{
	u64 ring_capacity = 0;
	struct pkm_kmes_runtime_config config = { };
	u32 validated = 0;
	long ret;

	if (!entries || !staged || !validated_out)
		return -EINVAL;

	ret = pkm_kmes_runtime_capacity(&ring_capacity);
	if (ret)
		return ret;
	ret = pkm_kmes_runtime_config_snapshot(&config);
	if (ret)
		return ret;

	for (validated = 0; validated < count; validated++) {
		ret = pkm_kmes_stage_event(ring_capacity, config.max_event_size,
					   config.max_nesting_depth,
					   (const void *)(uintptr_t)entries[validated].event_type,
					   entries[validated].event_type_len,
					   (const void *)(uintptr_t)entries[validated].payload,
					   entries[validated].payload_len,
					   from_user, &staged[validated]);
		if (ret)
			break;
	}

	*validated_out = validated;
	return validated == count ? 0 : ret;
}

static void pkm_kmes_free_staged_events(struct pkm_kmes_staged_event *events,
					u32 count)
{
	u32 index;

	if (!events)
		return;

	for (index = 0; index < count; index++)
		pkm_kmes_staged_event_reset(&events[index]);
	kvfree(events);
}

static long pkm_kmes_store_emitted_out(void *emitted_out, bool to_user,
				       u32 value)
{
	if (to_user) {
		if (!emitted_out || put_user(value, (u32 __user *)emitted_out))
			return -EFAULT;
		return 0;
	}

	if (!emitted_out)
		return -EINVAL;
	*(u32 *)emitted_out = value;
	return 0;
}

static long pkm_kmes_emit_batch_common(const void *token,
				       const struct kmes_emit_entry *entries,
				       u32 count, bool entries_from_user,
				       void *emitted_out, bool emitted_out_user)
{
	struct kmes_emit_entry *entry_copy = NULL;
	struct pkm_kmes_staged_event *staged = NULL;
	bool tcb_exempt;
	u32 emitted = 0;
	u32 validated = 0;
	u32 refund = 0;
	long ret;

	ret = pkm_kmes_require_audit(token, &tcb_exempt);
	if (ret)
		return ret;
	if (count == 0 || count > KMES_BATCH_MAX_ENTRIES)
		return -EINVAL;

	if (!tcb_exempt) {
		ret = pkm_kmes_current_process_rate_reserve(count);
		if (ret)
			return ret;
	}
	ret = pkm_kmes_store_emitted_out(emitted_out, emitted_out_user, 0);
	if (ret)
		goto out;

	if (entries_from_user)
		ret = pkm_kmes_copy_entry_array_user(
			(const struct kmes_emit_entry __user *)entries, count,
			&entry_copy);
	else
		ret = pkm_kmes_copy_entry_array_kernel(entries, count,
						       &entry_copy);
	if (ret)
		goto out;

	staged = kvcalloc(count, sizeof(*staged), GFP_KERNEL);
	if (!staged) {
		ret = -ENOMEM;
		goto out;
	}

	ret = pkm_kmes_stage_batch_events(entry_copy, count, entries_from_user,
					  staged, &validated);
	if (validated > 0) {
		long emit_ret = pkm_kmes_emit_staged_events(
			staged, validated, KMES_ORIGIN_USERSPACE);

		if (emit_ret) {
			ret = emit_ret;
			goto out;
		}
		emitted = validated;
	}

	if (ret == 0)
		emitted = count;
	{
		long store_ret =
			pkm_kmes_store_emitted_out(emitted_out, emitted_out_user,
						   emitted);

		if (store_ret)
			ret = store_ret;
	}

out:
	if (!tcb_exempt) {
		refund = count - emitted;
		if (refund)
			pkm_kmes_current_process_rate_refund(refund);
	}
	pkm_kmes_free_staged_events(staged, count);
	kfree(entry_copy);
	return ret;
}

long pkm_kmes_emit_user_for_token(const void *token,
				  const void __user *event_type,
				  u16 event_type_len,
				  const void __user *payload,
				  u32 payload_len)
{
	return pkm_kmes_emit_one_for_token(token, event_type, event_type_len,
					   payload, payload_len, true);
}

long pkm_kmes_emit_batch_user_for_token(
	const void *token, const struct kmes_emit_entry __user *entries,
	u32 count, u32 __user *emitted_out)
{
	return pkm_kmes_emit_batch_common(
		token, (const struct kmes_emit_entry *)entries, count, true,
		(void *)emitted_out, true);
}

SYSCALL_DEFINE4(kmes_emit, const char __user *, event_type, u16,
		event_type_len, const void __user *, payload, u32, payload_len)
{
	return pkm_kmes_emit_user_for_token(
		pkm_kacs_current_effective_token_ptr(), event_type,
		event_type_len, payload, payload_len);
}

SYSCALL_DEFINE3(kmes_emit_batch, const struct kmes_emit_entry __user *,
		entries, u32, count, u32 __user *, emitted_out)
{
	return pkm_kmes_emit_batch_user_for_token(
		pkm_kacs_current_effective_token_ptr(), entries, count,
		emitted_out);
}

static int pkm_kmes_load_live_process_view(struct pkm_kmes_process_view *view,
					   char *name_buf, size_t name_buf_len,
					   char *path_buf, size_t path_buf_len)
{
	struct file *exe_file;
	char *resolved;
	ssize_t copied;

	if (!view || !name_buf || !path_buf)
		return -EINVAL;

	copied = strscpy(name_buf, current->comm, name_buf_len);
	if (copied < 0)
		return copied;

	view->name = (const u8 *)name_buf;
	view->name_len = (size_t)copied;
	view->pid = (u64)task_tgid_vnr(current);

	exe_file = get_task_exe_file(current);
	if (!exe_file)
		return -EIO;

	resolved = d_path(&exe_file->f_path, path_buf, path_buf_len);
	fput(exe_file);
	if (IS_ERR(resolved))
		return PTR_ERR(resolved);

	view->path = (const u8 *)resolved;
	view->path_len = strnlen(resolved, path_buf + path_buf_len - resolved);
	return 0;
}

static long pkm_kmes_require_security(const void *token)
{
	if (!token)
		return -EPERM;
	if (!kacs_rust_token_has_enabled_privilege(token,
						   PKM_KMES_PRIVILEGE_SE_SECURITY))
		return -EPERM;
	if (!kacs_rust_token_mark_privileges_used(token,
						  PKM_KMES_PRIVILEGE_SE_SECURITY))
		return -EPERM;

	return 0;
}

static int pkm_kmes_alloc_producer_page(struct pkm_kmes_cpu_state *cpu)
{
	struct file *producer_file;
	struct page *producer_meta_page;
	u8 *producer_shared_page;

	/* The producer metadata page must be page-backed so shared futex wait works. */
	producer_file = shmem_file_setup("pkm-kmes-producer", PAGE_SIZE, EMPTY_VMA_FLAGS);
	if (IS_ERR(producer_file))
		return PTR_ERR(producer_file);

	producer_meta_page = shmem_read_mapping_page_gfp(
		producer_file->f_mapping, 0, GFP_KERNEL);
	if (IS_ERR(producer_meta_page)) {
		int ret = PTR_ERR(producer_meta_page);

		fput(producer_file);
		return ret;
	}

	producer_shared_page = vmap(&producer_meta_page, 1, VM_MAP, PAGE_KERNEL);
	if (!producer_shared_page) {
		put_page(producer_meta_page);
		fput(producer_file);
		return -ENOMEM;
	}

	memcpy(producer_shared_page, cpu->producer_page, PAGE_SIZE);
	cpu->producer_file = producer_file;
	cpu->producer_meta_page = producer_meta_page;
	cpu->producer_shared_page = producer_shared_page;
	return 0;
}

static int pkm_kmes_fd_release(struct inode *inode, struct file *file)
{
	struct pkm_kmes_fd *kfd = file->private_data;

	if (kfd && kfd->ring)
		pkm_kmes_ring_put(kfd->ring);
	kfree(kfd);
	return 0;
}

static int pkm_kmes_map_page_range(struct vm_area_struct *vma,
				   unsigned long addr, struct page *page,
				   pgprot_t prot)
{
	pgprot_t saved_prot = vma->vm_page_prot;
	int ret;

	vma->vm_page_prot = prot;
	ret = vm_insert_page(vma, addr, page);
	vma->vm_page_prot = saved_prot;
	return ret;
}

static int pkm_kmes_map_vmalloc_page_range(struct vm_area_struct *vma,
					   unsigned long addr,
					   const void *page_addr,
					   pgprot_t prot)
{
	struct page *page = vmalloc_to_page(page_addr);

	if (!page)
		return -ENOMEM;

	return pkm_kmes_map_page_range(vma, addr, page, prot);
}

static int pkm_kmes_fd_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct pkm_kmes_fd *kfd = file->private_data;
	struct pkm_kmes_cpu_state *cpu;
	unsigned long addr;
	size_t mapping_len;
	u64 page_offset;
	pgprot_t rw_prot;
	pgprot_t ro_prot;
	int ret;

	if (!kfd || !kfd->ring)
		return -EINVAL;
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;
	if (vma->vm_pgoff != 0)
		return -EINVAL;

	cpu = kfd->ring;
	mapping_len = pkm_kmes_mapping_size(cpu->capacity);
	if ((size_t)(vma->vm_end - vma->vm_start) != mapping_len)
		return -EINVAL;

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_MIXEDMAP);
	rw_prot = vma->vm_page_prot;
	ro_prot = vm_get_page_prot(vma->vm_flags & ~VM_WRITE);

	addr = vma->vm_start;
	ret = pkm_kmes_map_page_range(vma, addr, cpu->producer_meta_page,
					 ro_prot);
	if (ret)
		return ret;
	addr += PAGE_SIZE;
	ret = pkm_kmes_map_page_range(vma, addr, virt_to_page(cpu->consumer_page),
				      rw_prot);
	if (ret)
		return ret;
	addr += PAGE_SIZE;

	for (page_offset = 0; page_offset < cpu->capacity;
	     page_offset += PAGE_SIZE) {
		ret = pkm_kmes_map_vmalloc_page_range(vma, addr + page_offset,
						      cpu->data + page_offset,
						      ro_prot);
		if (ret)
			return ret;
	}
	for (page_offset = 0; page_offset < cpu->capacity;
	     page_offset += PAGE_SIZE) {
		ret = pkm_kmes_map_vmalloc_page_range(
			vma, addr + cpu->capacity + page_offset,
			cpu->data + page_offset, ro_prot);
		if (ret)
			return ret;
	}

	return 0;
}

static const struct file_operations pkm_kmes_fops = {
	.mmap = pkm_kmes_fd_mmap,
	.release = pkm_kmes_fd_release,
};

static int pkm_kmes_consumer_fd_create(struct pkm_kmes_cpu_state *cpu)
{
	struct pkm_kmes_fd *kfd;
	int fd;

	if (!cpu || !cpu->producer_page || !cpu->consumer_page || !cpu->data)
		return -ENOMEM;
	if (!cpu->producer_file || !cpu->producer_meta_page ||
	    !cpu->producer_shared_page) {
		fd = pkm_kmes_alloc_producer_page(cpu);
		if (fd < 0)
			return fd;
		pkm_kmes_init_metadata_pages(cpu);
	}

	kfd = kmalloc(sizeof(*kfd), GFP_KERNEL);
	if (!kfd)
		return -ENOMEM;

	pkm_kmes_ring_get(cpu);
	kfd->ring = cpu;
	fd = anon_inode_getfd("kmes-cpu", &pkm_kmes_fops, kfd,
			      O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		pkm_kmes_ring_put(cpu);
		kfree(kfd);
	}

	return fd;
}

static long pkm_kmes_attach_core(u32 cpu_id, int *fd_out, u64 *capacity_out)
{
	struct pkm_kmes_cpu_state *ring;
	int fd;

	if (!fd_out || !capacity_out)
		return -EINVAL;
	if (!pkm_kmes_ready || !pkm_kmes_cpus || pkm_kmes_cpu_count == 0)
		return -ENOMEM;
	if (cpu_id >= pkm_kmes_cpu_count)
		return -EINVAL;

	mutex_lock(&pkm_kmes_topology_lock);
	ring = pkm_kmes_cpus[cpu_id].live;
	if (!ring || !ring->data) {
		mutex_unlock(&pkm_kmes_topology_lock);
		return -EINVAL;
	}
	fd = pkm_kmes_consumer_fd_create(ring);
	if (fd < 0) {
		mutex_unlock(&pkm_kmes_topology_lock);
		return fd;
	}
	*capacity_out = ring->capacity;
	mutex_unlock(&pkm_kmes_topology_lock);

	*fd_out = fd;
	return 0;
}

long pkm_kmes_attach_user_for_token(const void *token, u32 cpu_id,
				    u64 __user *capacity)
{
	u64 cpu_capacity = 0;
	int fd = -1;
	long ret;

	ret = pkm_kmes_require_security(token);
	if (ret)
		return ret;
	if (!capacity)
		return -EFAULT;

	ret = pkm_kmes_attach_core(cpu_id, &fd, &cpu_capacity);
	if (ret)
		return ret;

	if (copy_to_user(capacity, &cpu_capacity, sizeof(cpu_capacity))) {
		close_fd((unsigned int)fd);
		return -EFAULT;
	}

	return fd;
}

SYSCALL_DEFINE2(kmes_attach, unsigned int, cpu_id, u64 __user *, capacity)
{
	return pkm_kmes_attach_user_for_token(
		pkm_kacs_current_effective_token_ptr(), cpu_id, capacity);
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static bool pkm_kmes_kunit_override_enabled(void)
{
	return READ_ONCE(pkm_kmes_override.enabled);
}

static int pkm_kmes_load_override_process_view(struct pkm_kmes_process_view *view)
{
	if (!view || !pkm_kmes_kunit_override_enabled())
		return -EINVAL;

	view->pid = READ_ONCE(pkm_kmes_override.pid);
	view->name = (const u8 *)pkm_kmes_override.name;
	view->name_len = READ_ONCE(pkm_kmes_override.name_len);
	view->path = (const u8 *)pkm_kmes_override.path;
	view->path_len = READ_ONCE(pkm_kmes_override.path_len);
	return 0;
}
#endif

static int pkm_kmes_fill_process_view(struct pkm_kmes_process_view *view,
				      char *name_buf, size_t name_buf_len,
				      char *path_buf, size_t path_buf_len)
{
#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (pkm_kmes_kunit_override_enabled())
		return pkm_kmes_load_override_process_view(view);
#endif

	return pkm_kmes_load_live_process_view(view, name_buf, name_buf_len,
					       path_buf, path_buf_len);
}

int pkm_kmes_init(void)
{
	unsigned int cpu;
	struct pkm_kmes_cpu_slot *cpus;

	if (pkm_kmes_ready)
		return 0;

	pkm_kmes_cpu_slots = nr_cpu_ids;
	pkm_kmes_cpu_count = 0;
	cpus = kcalloc(pkm_kmes_cpu_slots, sizeof(*cpus), GFP_KERNEL);
	if (!cpus)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		cpus[cpu].cpu_id = (u16)cpu;
		cpus[cpu].live = pkm_kmes_ring_alloc(
			(u16)cpu, 1, PKM_KMES_DEFAULT_BUFFER_CAPACITY);
		if (IS_ERR(cpus[cpu].live))
			goto fail;
		pkm_kmes_cpu_count++;
	}

	pkm_kmes_cpus = cpus;
	pkm_kmes_ready = true;
	return 0;

fail:
	for_each_possible_cpu(cpu) {
		if (!IS_ERR_OR_NULL(cpus[cpu].live))
			pkm_kmes_ring_put(cpus[cpu].live);
	}
	pkm_kmes_cpu_count = 0;
	kfree(cpus);
	return -ENOMEM;
}

void pkm_kmes_emit_kernel(u8 origin_class, const void *event_type,
			  size_t event_type_len, const void *payload,
			  size_t payload_len)
{
	struct pkm_kmes_cpu_state *cpu = NULL;
	size_t header_size;
	size_t event_size;
	u64 timestamp;
	u64 sequence;
	unsigned int cpu_id;
	kacs_uuid_t eff_guid;
	kacs_uuid_t true_guid;
	kacs_uuid_t proc_guid;
	bool wake_needed = false;
	bool emitted = false;

	if (!pkm_kmes_ready)
		return;

	preempt_disable();

	cpu_id = smp_processor_id();
	if (cpu_id >= pkm_kmes_cpu_slots)
		goto out;

	cpu = READ_ONCE(pkm_kmes_cpus[cpu_id].live);
	if (!cpu || !cpu->data)
		goto out;
	timestamp = ktime_get_real_ns();
	sequence = ++cpu->sequence;

	/*
	 * Identity stamps reflect the thread at ring-write time. The three
	 * KACS accessors are preempt-safe (RCU reads of current's creds plus a
	 * 16-byte copy); they return the null GUID for kernel emission with no
	 * process context or before KACS init.
	 */
	eff_guid = kacs_effective_token_guid();
	true_guid = kacs_primary_token_guid();
	proc_guid = kacs_process_guid();

	if (event_type_len == 0 || event_type_len > PKM_KMES_MAX_KERNEL_TYPE_LEN)
		goto drop;
	if (check_add_overflow(KMES_EVENT_HEADER_BASE_SIZE, event_type_len,
			       &header_size))
		goto drop;
	if (check_add_overflow(header_size, payload_len, &event_size))
		goto drop;
	if (event_size > U32_MAX || event_size > cpu->capacity / 2)
		goto drop;
	if (cpu->cpu_id != cpu_id)
		goto drop;

	pkm_kmes_reserve_space(cpu, event_size);
	pkm_kmes_write_event(cpu, origin_class, &eff_guid, &true_guid,
			     &proc_guid, event_type, event_type_len,
			     payload, payload_len, timestamp, sequence,
			     &wake_needed);
	emitted = true;
	goto out;

drop:
	pkm_kmes_drop_event(cpu);
out:
	preempt_enable();
	if (emitted)
		pkm_kmes_log_early_event(cpu_id, sequence, origin_class,
					 event_type, event_type_len, payload_len,
					 event_size);
	if (wake_needed)
		pkm_kmes_futex_wake(cpu);
}

int pkm_kmes_current_process_info(u64 *pid_out, u8 *name_out,
				  size_t name_out_len, size_t *name_len_out,
				  u8 *path_out, size_t path_out_len,
				  size_t *path_len_out)
{
	struct pkm_kmes_process_view view = { };
	char name_buf[TASK_COMM_LEN];
	char *path_buf;
	int ret;

	if (!pid_out || !name_len_out || !path_len_out)
		return -EINVAL;
	if ((!name_out && name_out_len) || (!path_out && path_out_len))
		return -EINVAL;

	path_buf = __getname();
	if (!path_buf)
		return -ENOMEM;

	ret = pkm_kmes_fill_process_view(&view, name_buf, sizeof(name_buf),
					 path_buf, PATH_MAX);
	if (ret) {
		__putname(path_buf);
		return ret;
	}

	*pid_out = view.pid;
	*name_len_out = view.name_len;
	*path_len_out = view.path_len;

	if (name_out && name_out_len < view.name_len) {
		__putname(path_buf);
		return -ERANGE;
	}
	if (path_out && path_out_len < view.path_len) {
		__putname(path_buf);
		return -ERANGE;
	}

	if (name_out && view.name_len)
		memcpy(name_out, view.name, view.name_len);
	if (path_out && view.path_len)
		memcpy(path_out, view.path, view.path_len);

	__putname(path_buf);
	return 0;
}

struct pkm_kmes_swap_ctx {
	struct pkm_kmes_cpu_state **new_rings;
	struct pkm_kmes_cpu_state **wake_rings;
	int ret;
};

static bool pkm_kmes_capacity_valid(u64 capacity)
{
	return pkm_kmes_buffer_capacity_valid(capacity);
}

static int pkm_kmes_prepare_swap_ring(struct pkm_kmes_cpu_state *old,
				      struct pkm_kmes_cpu_state *new)
{
	u64 source_tail;
	u64 source_write;
	u64 copy_start;
	u64 dest_write = 0;

	if (!old || !new)
		return -EINVAL;
	if (old->cpu_id != new->cpu_id)
		return -EINVAL;

	source_tail = old->tail_pos;
	source_write = old->write_pos;
	copy_start = source_tail;

	if (source_write < source_tail || source_write - source_tail > old->capacity)
		return -EIO;

	while (copy_start < source_write) {
		u32 event_size =
			pkm_kmes_read_u32_at(old->data, old->capacity, copy_start);

		if (event_size == 0 || event_size > old->capacity ||
		    event_size > source_write - copy_start)
			return -EIO;
		if (event_size > new->capacity ||
		    source_write - copy_start > new->capacity) {
			copy_start += event_size;
			continue;
		}
		break;
	}

	while (copy_start < source_write) {
		u32 event_size =
			pkm_kmes_read_u32_at(old->data, old->capacity, copy_start);

		if (event_size == 0 || event_size > old->capacity ||
		    event_size > new->capacity ||
		    event_size > source_write - copy_start ||
		    dest_write + event_size > new->capacity)
			return -EIO;

		pkm_kmes_copy_bytes_from_ring(old->data, old->capacity, copy_start,
					      new->data + dest_write, event_size);
		dest_write += event_size;
		copy_start += event_size;
	}

	new->sequence = old->sequence;
	new->dropped_events = old->dropped_events;
	pkm_kmes_store_tail_pos(new, 0);
	pkm_kmes_store_write_pos(new, dest_write);
	return 0;
}

static int pkm_kmes_swap_stop_machine(void *data)
{
	struct pkm_kmes_swap_ctx *ctx = data;
	unsigned int cpu;

	if (!ctx)
		return 0;

	for_each_possible_cpu(cpu) {
		struct pkm_kmes_cpu_state *old = pkm_kmes_cpus[cpu].live;
		struct pkm_kmes_cpu_state *new = ctx->new_rings[cpu];

		if (!old || !new)
			continue;

		ctx->ret = pkm_kmes_prepare_swap_ring(old, new);
		if (ctx->ret)
			return 0;
	}

	for_each_possible_cpu(cpu) {
		struct pkm_kmes_cpu_state *old = pkm_kmes_cpus[cpu].live;
		struct pkm_kmes_cpu_state *new = ctx->new_rings[cpu];

		if (!old || !new)
			continue;

		WRITE_ONCE(pkm_kmes_cpus[cpu].live, new);
		pkm_kmes_store_generation(old, new->generation);
		if (pkm_kmes_note_wake(old)) {
			pkm_kmes_ring_get(old);
			ctx->wake_rings[cpu] = old;
		}
		pkm_kmes_ring_put(old);
	}

	return 0;
}

static long pkm_kmes_swap_capacity_locked(u64 new_capacity)
{
	struct pkm_kmes_cpu_state **new_rings = NULL;
	struct pkm_kmes_cpu_state **wake_rings = NULL;
	u64 current_capacity = 0;
	unsigned int cpu;
	long ret = 0;
	struct pkm_kmes_swap_ctx ctx = { };

	if (!pkm_kmes_ready || !pkm_kmes_cpus || pkm_kmes_cpu_count == 0)
		return -ENOMEM;
	if (!pkm_kmes_capacity_valid(new_capacity))
		return -EINVAL;

	ret = pkm_kmes_runtime_capacity(&current_capacity);
	if (ret)
		return ret;
	if (new_capacity == current_capacity)
		return 0;

	new_rings = kcalloc(pkm_kmes_cpu_slots, sizeof(*new_rings), GFP_KERNEL);
	wake_rings = kcalloc(pkm_kmes_cpu_slots, sizeof(*wake_rings), GFP_KERNEL);
	if (!new_rings || !wake_rings) {
		ret = -ENOMEM;
		goto out;
	}

	for_each_possible_cpu(cpu) {
		struct pkm_kmes_cpu_state *old = pkm_kmes_cpus[cpu].live;

		if (!old)
			continue;

		new_rings[cpu] = pkm_kmes_ring_alloc(old->cpu_id,
						     old->generation + 1,
						     new_capacity);
		if (IS_ERR(new_rings[cpu])) {
			ret = PTR_ERR(new_rings[cpu]);
			new_rings[cpu] = NULL;
			goto out;
		}
	}

	ctx.new_rings = new_rings;
	ctx.wake_rings = wake_rings;
	ret = stop_machine(pkm_kmes_swap_stop_machine, &ctx, NULL);
	if (ret)
		goto out;
	if (ctx.ret) {
		ret = ctx.ret;
		goto out;
	}

	for (cpu = 0; cpu < pkm_kmes_cpu_slots; cpu++) {
		if (!wake_rings[cpu])
			continue;
		pkm_kmes_futex_wake(wake_rings[cpu]);
		pkm_kmes_ring_put(wake_rings[cpu]);
		wake_rings[cpu] = NULL;
	}

	kfree(wake_rings);
	kfree(new_rings);
	return 0;

out:
	if (wake_rings) {
		for (cpu = 0; cpu < pkm_kmes_cpu_slots; cpu++) {
			if (wake_rings[cpu])
				pkm_kmes_ring_put(wake_rings[cpu]);
		}
	}
	if (new_rings) {
		for (cpu = 0; cpu < pkm_kmes_cpu_slots; cpu++) {
			if (!new_rings[cpu])
				continue;
			if (pkm_kmes_cpus[cpu].live != new_rings[cpu])
				pkm_kmes_ring_put(new_rings[cpu]);
		}
	}
	kfree(wake_rings);
	kfree(new_rings);
	return ret;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static int pkm_kmes_find_single_active_cpu(struct pkm_kmes_cpu_state **out_cpu)
{
	struct pkm_kmes_cpu_state *active = NULL;
	unsigned int cpu;

	if (!out_cpu)
		return -EINVAL;

	for_each_possible_cpu(cpu) {
		struct pkm_kmes_cpu_state *candidate = pkm_kmes_cpus[cpu].live;

		if (!candidate || !candidate->data)
			continue;
		if (candidate->sequence == 0 && candidate->write_pos == 0 &&
		    candidate->tail_pos == 0 && candidate->dropped_events == 0)
			continue;
		if (active)
			return -E2BIG;
		active = candidate;
	}

	if (!active)
		return -ENOENT;

	*out_cpu = active;
	return 0;
}

void pkm_kmes_kunit_reset_all(void)
{
	unsigned int cpu;
	u64 current_capacity = 0;
	struct pkm_kmes_runtime_config defaults = { };

	WRITE_ONCE(pkm_kmes_kunit_fail_next_ring_alloc, false);
	pkm_kmes_runtime_config_defaults(&defaults);
	mutex_lock(&pkm_kmes_topology_lock);
	pkm_kmes_runtime_config_store_locked(&defaults);
	mutex_unlock(&pkm_kmes_topology_lock);
	pkm_kmes_rate_buckets_reconfigure(defaults.max_emit_rate_per_process);

	if (!pkm_kmes_ready)
		return;
	if (pkm_kmes_runtime_capacity(&current_capacity) == 0 &&
	    current_capacity != PKM_KMES_DEFAULT_BUFFER_CAPACITY) {
		mutex_lock(&pkm_kmes_topology_lock);
		(void)pkm_kmes_swap_capacity_locked(
			PKM_KMES_DEFAULT_BUFFER_CAPACITY);
		mutex_unlock(&pkm_kmes_topology_lock);
	}

	for_each_possible_cpu(cpu) {
		struct pkm_kmes_cpu_state *state = pkm_kmes_cpus[cpu].live;

		if (!state || !state->data)
			continue;

		memset(state->data, 0, state->capacity);
		memset(state->producer_page, 0, PAGE_SIZE);
		memset(state->consumer_page, 0, PAGE_SIZE);
		state->generation = 1;
		state->sequence = 0;
		state->write_pos = 0;
		state->tail_pos = 0;
		state->dropped_events = 0;
		state->futex_counter = 0;
		pkm_kmes_init_metadata_pages(state);
	}
}

int pkm_kmes_kunit_snapshot_single_active(struct pkm_kmes_kunit_snapshot *out)
{
	struct pkm_kmes_cpu_state *cpu;
	int ret;

	if (!out)
		return -EINVAL;
	if (!pkm_kmes_ready)
		return -ENODEV;

	ret = pkm_kmes_find_single_active_cpu(&cpu);
	if (ret)
		return ret;

	out->cpu_id = cpu->cpu_id;
	out->_reserved = 0;
	out->capacity = cpu->capacity;
	out->write_pos = cpu->write_pos;
	out->tail_pos = cpu->tail_pos;
	out->last_sequence = cpu->sequence;
	out->dropped_events = cpu->dropped_events;
	return 0;
}

int pkm_kmes_kunit_copy_single_buffer(u8 *out, size_t out_len,
				      size_t *written_out,
				      struct pkm_kmes_kunit_snapshot *out_snapshot)
{
	struct pkm_kmes_cpu_state *cpu;
	size_t live_len;
	int ret;

	if (!out || !written_out)
		return -EINVAL;
	if (!pkm_kmes_ready)
		return -ENODEV;

	ret = pkm_kmes_find_single_active_cpu(&cpu);
	if (ret)
		return ret;

	live_len = (size_t)(cpu->write_pos - cpu->tail_pos);
	if (live_len > cpu->capacity || live_len > out_len)
		return -ERANGE;

	pkm_kmes_copy_bytes_from_ring(cpu->data, cpu->capacity, cpu->tail_pos, out,
				      live_len);
	*written_out = live_len;

	if (out_snapshot) {
		out_snapshot->cpu_id = cpu->cpu_id;
		out_snapshot->_reserved = 0;
		out_snapshot->capacity = cpu->capacity;
		out_snapshot->write_pos = cpu->write_pos;
		out_snapshot->tail_pos = cpu->tail_pos;
		out_snapshot->last_sequence = cpu->sequence;
		out_snapshot->dropped_events = cpu->dropped_events;
	}

	return 0;
}

int pkm_kmes_kunit_copy_latest_matching_event(
	u8 origin_class, const void *event_type, size_t event_type_len, u8 *out,
	size_t out_len, size_t *written_out,
	struct pkm_kmes_kunit_snapshot *out_snapshot)
{
	struct pkm_kmes_cpu_state *best_cpu = NULL;
	u64 best_pos = 0;
	u64 best_timestamp = 0;
	u32 best_event_size = 0;
	bool found = false;
	unsigned int cpu_id;

	if (!event_type || event_type_len > U16_MAX || !out || !written_out)
		return -EINVAL;
	if (!pkm_kmes_ready)
		return -ENODEV;

	for_each_possible_cpu(cpu_id) {
		struct pkm_kmes_cpu_state *cpu = pkm_kmes_cpus[cpu_id].live;
		u64 pos;
		u64 write_pos;
		u64 live_len;

		if (!cpu || !cpu->data)
			continue;

		pos = cpu->tail_pos;
		write_pos = cpu->write_pos;
		live_len = write_pos - pos;
		if (live_len > cpu->capacity)
			return -ERANGE;

		while (pos < write_pos) {
			u64 remaining = write_pos - pos;
			u32 event_size;
			u32 header_size;
			u16 type_len;
			u64 timestamp;
			u8 current_origin;

			if (remaining < KMES_EVENT_HEADER_BASE_SIZE)
				return -EIO;

			event_size = pkm_kmes_read_u32_at(
				cpu->data, cpu->capacity,
				pos + KMES_EVENT_SIZE_OFFSET);
			header_size = pkm_kmes_read_u32_at(
				cpu->data, cpu->capacity,
				pos + KMES_EVENT_HEADER_SIZE_OFFSET);
			type_len = pkm_kmes_read_u16_at(
				cpu->data, cpu->capacity,
				pos + KMES_EVENT_TYPE_LEN_OFFSET);

			if (event_size < KMES_EVENT_HEADER_BASE_SIZE ||
			    event_size > remaining ||
			    event_size > cpu->capacity ||
			    header_size <
				    KMES_EVENT_HEADER_BASE_SIZE + type_len ||
			    header_size > event_size)
				return -EIO;

			current_origin = cpu->data[
				(pos + KMES_EVENT_ORIGIN_CLASS_OFFSET) &
				(cpu->capacity - 1)];
			timestamp = pkm_kmes_read_u64_at(
				cpu->data, cpu->capacity,
				pos + KMES_EVENT_TIMESTAMP_NS_OFFSET);

			if (current_origin == origin_class &&
			    type_len == event_type_len &&
			    pkm_kmes_ring_bytes_equal(
				    cpu->data, cpu->capacity,
				    pos + KMES_EVENT_HEADER_BASE_SIZE,
				    event_type, event_type_len) &&
			    (!found || timestamp >= best_timestamp)) {
				best_cpu = cpu;
				best_pos = pos;
				best_timestamp = timestamp;
				best_event_size = event_size;
				found = true;
			}

			pos += event_size;
		}
	}

	if (!found)
		return -ENOENT;
	if ((size_t)best_event_size > out_len)
		return -ERANGE;

	pkm_kmes_copy_bytes_from_ring(best_cpu->data, best_cpu->capacity,
				      best_pos, out, best_event_size);
	*written_out = best_event_size;

	if (out_snapshot) {
		out_snapshot->cpu_id = best_cpu->cpu_id;
		out_snapshot->_reserved = 0;
		out_snapshot->capacity = best_cpu->capacity;
		out_snapshot->write_pos = best_cpu->write_pos;
		out_snapshot->tail_pos = best_cpu->tail_pos;
		out_snapshot->last_sequence = best_cpu->sequence;
		out_snapshot->dropped_events = best_cpu->dropped_events;
	}

	return 0;
}

u16 pkm_kmes_kunit_current_cpu_id(void)
{
	u16 cpu_id;

	preempt_disable();
	cpu_id = (u16)smp_processor_id();
	preempt_enable();
	return cpu_id;
}

int pkm_kmes_kunit_swap_capacity(u64 new_capacity)
{
	long ret;

	mutex_lock(&pkm_kmes_topology_lock);
	ret = pkm_kmes_swap_capacity_locked(new_capacity);
	mutex_unlock(&pkm_kmes_topology_lock);
	return (int)ret;
}

void pkm_kmes_kunit_fail_next_swap_alloc(void)
{
	WRITE_ONCE(pkm_kmes_kunit_fail_next_ring_alloc, true);
}

long pkm_kmes_kunit_attach_for_token(const void *token, u32 cpu_id,
				     int *fd_out, u64 *capacity)
{
	long ret;

	if (!fd_out || !capacity)
		return -EINVAL;

	ret = pkm_kmes_require_security(token);
	if (ret)
		return ret;

	return pkm_kmes_attach_core(cpu_id, fd_out, capacity);
}

long pkm_kmes_kunit_attach_user_for_token(const void *token, u32 cpu_id,
					  u64 __user *capacity)
{
	return pkm_kmes_attach_user_for_token(token, cpu_id, capacity);
}

static int pkm_kmes_fd_lookup(int fd, struct pkm_kmes_cpu_state **out_cpu)
{
	struct fd f;
	struct pkm_kmes_fd *kfd;

	if (!out_cpu)
		return -EINVAL;

	*out_cpu = NULL;
	f = fdget(fd);
	if (!fd_file(f))
		return -EBADF;
	if (fd_file(f)->f_op != &pkm_kmes_fops) {
		fdput(f);
		return -EINVAL;
	}

	kfd = fd_file(f)->private_data;
	if (!kfd || !kfd->ring) {
		fdput(f);
		return -EINVAL;
	}

	*out_cpu = kfd->ring;
	fdput(f);
	return 0;
}

static const u8 *pkm_kmes_visible_producer_page(
	const struct pkm_kmes_cpu_state *cpu)
{
	if (cpu->producer_shared_page)
		return cpu->producer_shared_page;
	return cpu->producer_page;
}

static int pkm_kmes_copy_fd_view_from_cpu(const struct pkm_kmes_cpu_state *cpu,
					  u64 offset, u8 *out, size_t out_len)
{
	u64 end;
	u64 mapping_size;
	const u8 *producer_page;
	size_t remaining = out_len;

	if (!cpu || !out)
		return -EINVAL;
	producer_page = pkm_kmes_visible_producer_page(cpu);
	mapping_size = pkm_kmes_mapping_size(cpu->capacity);
	if (check_add_overflow(offset, (u64)out_len, &end) ||
	    end > mapping_size)
		return -ERANGE;

	while (remaining) {
		size_t chunk;

		if (offset < PAGE_SIZE) {
			chunk = min_t(size_t, remaining, PAGE_SIZE - (size_t)offset);
			memcpy(out, producer_page + offset, chunk);
		} else if (offset < KMES_METADATA_TOTAL_SIZE) {
			u64 local = offset - PAGE_SIZE;

			chunk = min_t(size_t, remaining,
				      PAGE_SIZE - (size_t)local);
			memcpy(out, cpu->consumer_page + local, chunk);
		} else {
			u64 local = offset - KMES_METADATA_TOTAL_SIZE;
			u64 mirror = local >= cpu->capacity ? local - cpu->capacity :
							      local;

			chunk = min_t(size_t, remaining,
				      (size_t)(cpu->capacity - mirror));
			memcpy(out, cpu->data + mirror, chunk);
		}

		offset += chunk;
		out += chunk;
		remaining -= chunk;
	}

	return 0;
}

int pkm_kmes_kunit_fd_snapshot(int fd, struct pkm_kmes_kunit_fd_snapshot *out)
{
	struct pkm_kmes_cpu_state *cpu;
	int ret;

	if (!out)
		return -EINVAL;

	ret = pkm_kmes_fd_lookup(fd, &cpu);
	if (ret)
		return ret;

	out->cpu_id = pkm_kmes_meta_load_u16(pkm_kmes_visible_producer_page(cpu),
					     KMES_PRODUCER_CPU_ID_OFFSET);
	out->_reserved = 0;
	out->capacity = pkm_kmes_meta_load_u64(pkm_kmes_visible_producer_page(cpu),
					       KMES_PRODUCER_CAPACITY_OFFSET);
	out->generation = pkm_kmes_meta_load_u64(
		pkm_kmes_visible_producer_page(cpu),
		KMES_PRODUCER_GENERATION_OFFSET);
	out->write_pos = pkm_kmes_meta_load_u64(
		pkm_kmes_visible_producer_page(cpu),
		KMES_PRODUCER_WRITE_POS_OFFSET);
	out->tail_pos = pkm_kmes_meta_load_u64(
		pkm_kmes_visible_producer_page(cpu),
		KMES_PRODUCER_TAIL_POS_OFFSET);
	out->futex_counter = pkm_kmes_meta_load_u32(
		pkm_kmes_visible_producer_page(cpu),
		KMES_PRODUCER_FUTEX_COUNTER_OFFSET);
	out->need_wake = READ_ONCE(*(u8 *)(cpu->consumer_page +
					   KMES_CONSUMER_NEED_WAKE_OFFSET));
	memset(out->_padding, 0, sizeof(out->_padding));
	out->mapping_size = pkm_kmes_mapping_size(cpu->capacity);
	return 0;
}

int pkm_kmes_kunit_copy_fd_view(int fd, u64 offset, u8 *out, size_t out_len)
{
	struct pkm_kmes_cpu_state *cpu;
	int ret;

	ret = pkm_kmes_fd_lookup(fd, &cpu);
	if (ret)
		return ret;

	return pkm_kmes_copy_fd_view_from_cpu(cpu, offset, out, out_len);
}

int pkm_kmes_kunit_set_fd_need_wake(int fd, u8 value)
{
	struct pkm_kmes_cpu_state *cpu;
	int ret;

	ret = pkm_kmes_fd_lookup(fd, &cpu);
	if (ret)
		return ret;

	WRITE_ONCE(*(u8 *)(cpu->consumer_page + KMES_CONSUMER_NEED_WAKE_OFFSET),
		   value);
	return 0;
}

int pkm_kmes_kunit_set_process_override(u64 pid, const char *name,
					const char *path)
{
	size_t name_len;
	size_t path_len;

	if (!name || !path)
		return -EINVAL;

	name_len = strnlen(name, TASK_COMM_LEN);
	path_len = strnlen(path, PATH_MAX);
	if (name_len == TASK_COMM_LEN || path_len == PATH_MAX)
		return -EINVAL;

	memset(&pkm_kmes_override, 0, sizeof(pkm_kmes_override));
	pkm_kmes_override.pid = pid;
	memcpy(pkm_kmes_override.name, name, name_len);
	memcpy(pkm_kmes_override.path, path, path_len);
	pkm_kmes_override.name_len = name_len;
	pkm_kmes_override.path_len = path_len;
	WRITE_ONCE(pkm_kmes_override.enabled, true);
	return 0;
}

void pkm_kmes_kunit_clear_process_override(void)
{
	memset(&pkm_kmes_override, 0, sizeof(pkm_kmes_override));
}

long pkm_kmes_kunit_emit_for_token(const void *token, const void *event_type,
				   u16 event_type_len, const void *payload,
				   u32 payload_len)
{
	return pkm_kmes_emit_one_for_token(token, event_type, event_type_len,
					   payload, payload_len, false);
}

long pkm_kmes_kunit_emit_batch_for_token(const void *token,
					 const struct kmes_emit_entry *entries,
					 u32 count, u32 *emitted_out)
{
	return pkm_kmes_emit_batch_common(token, entries, count, false,
					 emitted_out, false);
}

int pkm_kmes_kunit_runtime_config_snapshot(
	struct pkm_kmes_runtime_config *out)
{
	return pkm_kmes_runtime_config_snapshot(out);
}

long pkm_kmes_kunit_runtime_config_apply(
	const struct pkm_kmes_runtime_config *config)
{
	return pkm_kmes_runtime_config_apply(config);
}
#endif
