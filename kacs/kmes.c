// SPDX-License-Identifier: GPL-2.0-only
/*
 * Bounded slow-track KMES kernel emission core.
 *
 * Slice 38 implements only the internal kernel emission path and a PKM-owned
 * per-CPU ring buffer substrate. Consumer-facing attach/mmap exposure,
 * registry-backed configuration, and boot-buffer swap-over are deferred.
 */

#include <linux/cpumask.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/overflow.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/vmalloc.h>

#include "kmes.h"

#define PKM_KMES_EVENT_HEADER_BASE_SIZE 29U
#define PKM_KMES_DEFAULT_BUFFER_CAPACITY (4U * 1024U * 1024U)
#define PKM_KMES_MAX_KERNEL_TYPE_LEN ((size_t)U16_MAX)

struct pkm_kmes_cpu_state {
	u16 cpu_id;
	u64 capacity;
	u64 sequence;
	u64 write_pos;
	u64 tail_pos;
	u64 dropped_events;
	u8 *data;
};

struct pkm_kmes_process_view {
	u64 pid;
	const u8 *name;
	size_t name_len;
	const u8 *path;
	size_t path_len;
};

static struct pkm_kmes_cpu_state *pkm_kmes_cpus;
static unsigned int pkm_kmes_cpu_slots;
static bool pkm_kmes_ready;

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
#endif

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

static u32 pkm_kmes_read_u32_at(const u8 *data, u64 capacity, u64 pos)
{
	return (u32)data[(pos + 0) & (capacity - 1)] |
	       ((u32)data[(pos + 1) & (capacity - 1)] << 8) |
	       ((u32)data[(pos + 2) & (capacity - 1)] << 16) |
	       ((u32)data[(pos + 3) & (capacity - 1)] << 24);
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

static void pkm_kmes_drop_event(struct pkm_kmes_cpu_state *cpu)
{
	cpu->dropped_events++;
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

	smp_store_release(&cpu->tail_pos, next_tail);
}

static void pkm_kmes_write_event(struct pkm_kmes_cpu_state *cpu, u8 origin_class,
				 const void *event_type, size_t event_type_len,
				 const void *payload, size_t payload_len,
				 u64 timestamp, u64 sequence)
{
	u64 pos = cpu->write_pos;
	u32 header_size = PKM_KMES_EVENT_HEADER_BASE_SIZE + (u32)event_type_len;
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
	pkm_kmes_write_u16_at(cpu->data, cpu->capacity, pos,
			      (u16)event_type_len);
	pos += sizeof(u16);
	pkm_kmes_write_bytes_at(cpu->data, cpu->capacity, pos, event_type,
				event_type_len);
	pos += event_type_len;
	pkm_kmes_write_bytes_at(cpu->data, cpu->capacity, pos, payload,
				payload_len);

	smp_store_release(&cpu->write_pos, cpu->write_pos + event_size);
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
	struct pkm_kmes_cpu_state *cpus;

	if (pkm_kmes_ready)
		return 0;

	pkm_kmes_cpu_slots = nr_cpu_ids;
	cpus = kcalloc(pkm_kmes_cpu_slots, sizeof(*cpus), GFP_KERNEL);
	if (!cpus)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		cpus[cpu].cpu_id = (u16)cpu;
		cpus[cpu].capacity = PKM_KMES_DEFAULT_BUFFER_CAPACITY;
		cpus[cpu].data = vzalloc(PKM_KMES_DEFAULT_BUFFER_CAPACITY);
		if (!cpus[cpu].data)
			goto fail;
	}

	pkm_kmes_cpus = cpus;
	pkm_kmes_ready = true;
	return 0;

fail:
	for_each_possible_cpu(cpu)
		vfree(cpus[cpu].data);
	kfree(cpus);
	return -ENOMEM;
}

void pkm_kmes_emit_kernel(u8 origin_class, const void *event_type,
			  size_t event_type_len, const void *payload,
			  size_t payload_len)
{
	struct pkm_kmes_cpu_state *cpu;
	size_t header_size;
	size_t event_size;
	u64 timestamp;
	u64 sequence;
	unsigned int cpu_id;

	if (!pkm_kmes_ready)
		return;

	preempt_disable();

	cpu_id = smp_processor_id();
	if (cpu_id >= pkm_kmes_cpu_slots || !pkm_kmes_cpus[cpu_id].data)
		goto out;

	cpu = &pkm_kmes_cpus[cpu_id];
	timestamp = ktime_get_real_ns();
	sequence = ++cpu->sequence;

	if (event_type_len == 0 || event_type_len > PKM_KMES_MAX_KERNEL_TYPE_LEN)
		goto drop;
	if (check_add_overflow(PKM_KMES_EVENT_HEADER_BASE_SIZE, event_type_len,
			       &header_size))
		goto drop;
	if (check_add_overflow(header_size, payload_len, &event_size))
		goto drop;
	if (event_size > U32_MAX || event_size > cpu->capacity / 2)
		goto drop;
	if (cpu->cpu_id != cpu_id)
		goto drop;

	pkm_kmes_reserve_space(cpu, event_size);
	pkm_kmes_write_event(cpu, origin_class, event_type, event_type_len,
			     payload, payload_len, timestamp, sequence);
	goto out;

drop:
	pkm_kmes_drop_event(cpu);
out:
	preempt_enable();
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

#ifdef CONFIG_SECURITY_PKM_KUNIT
static int pkm_kmes_find_single_active_cpu(struct pkm_kmes_cpu_state **out_cpu)
{
	struct pkm_kmes_cpu_state *active = NULL;
	unsigned int cpu;

	if (!out_cpu)
		return -EINVAL;

	for_each_possible_cpu(cpu) {
		struct pkm_kmes_cpu_state *candidate = &pkm_kmes_cpus[cpu];

		if (!candidate->data)
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

	if (!pkm_kmes_ready)
		return;

	for_each_possible_cpu(cpu) {
		struct pkm_kmes_cpu_state *state = &pkm_kmes_cpus[cpu];

		if (!state->data)
			continue;

		memset(state->data, 0, state->capacity);
		state->sequence = 0;
		state->write_pos = 0;
		state->tail_pos = 0;
		state->dropped_events = 0;
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
#endif
