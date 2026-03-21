// SPDX-License-Identifier: GPL-2.0-only
/*
 * PKM Event Subsystem — kernel ring buffer for structured audit events.
 *
 * Architecture: single-producer (kernel) / single-consumer (eventd).
 * Ring buffer is mmap'd into eventd's address space. Kernel stamps
 * every event with trusted metadata (identity, timestamp, sequence).
 *
 * Not part of KACS — separate PKM subsystem. KACS emits events into
 * the ring buffer, but the buffer and syscall are independent.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/eventfd.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/uidgid.h>
#include <linux/cred.h>

/* ── Event header (stamped by kernel, unforgeable) ─────────────────────── */

struct peios_event_header {
	u64 sequence;		/* monotonic, never reused */
	u64 timestamp_ns;	/* CLOCK_MONOTONIC */
	u32 emitter_pid;
	u32 emitter_tid;
	u32 emitter_uid;	/* projected UID from token */
	u16 payload_len;
	u8  source;		/* 0 = kernel, 1 = userspace */
	u8  _pad;
};  /* 32 bytes */

#define EVENT_SOURCE_KERNEL    0
#define EVENT_SOURCE_USERSPACE 1
#define EVENT_MAX_BODY_SIZE    8192

/* ── Ring buffer ───────────────────────────────────────────────────────── */

/*
 * Status page (read-only for eventd):
 *   write_ptr, overflow_count, buffer_size
 *
 * Consumer page (read-write for eventd):
 *   read_ptr
 *
 * Event data (read-only for eventd):
 *   circular buffer of events
 */

struct peios_ring_status {
	u64 write_ptr;
	u64 overflow_count;
	u64 buffer_size;
};

struct peios_ring_consumer {
	u64 read_ptr;
};

#define RING_DEFAULT_SIZE  (4 * 1024 * 1024)  /* 4 MB */

static struct {
	void *buffer;			/* event data (circular) */
	struct peios_ring_status *status;
	struct peios_ring_consumer *consumer;
	u64 size;			/* buffer_size in bytes */
	u64 sequence;			/* next sequence number */
	spinlock_t lock;		/* protects writes */
	struct eventfd_ctx *notify;	/* wakeup for eventd */
} ring;

/* ── Ring buffer operations ────────────────────────────────────────────── */

static int ring_init(void)
{
	ring.size = RING_DEFAULT_SIZE;

	ring.status = vzalloc(PAGE_SIZE);
	if (!ring.status)
		return -ENOMEM;

	ring.consumer = vzalloc(PAGE_SIZE);
	if (!ring.consumer) {
		vfree(ring.status);
		return -ENOMEM;
	}

	ring.buffer = vzalloc(ring.size);
	if (!ring.buffer) {
		vfree(ring.consumer);
		vfree(ring.status);
		return -ENOMEM;
	}

	ring.status->buffer_size = ring.size;
	ring.status->write_ptr = 0;
	ring.status->overflow_count = 0;
	ring.consumer->read_ptr = 0;
	ring.sequence = 1;
	spin_lock_init(&ring.lock);
	ring.notify = NULL;

	return 0;
}

/*
 * Write an event into the ring buffer.
 * Returns 0 on success, -ENOSPC if dropped (best_effort overflow).
 */
static int ring_write(const struct peios_event_header *hdr,
		      const void *body, u16 body_len)
{
	u32 total = sizeof(*hdr) + body_len;
	u64 wp, rp, avail, end_offset;
	unsigned long flags;

	if (total > ring.size)
		return -EINVAL;

	spin_lock_irqsave(&ring.lock, flags);

	wp = ring.status->write_ptr;
	rp = ring.consumer->read_ptr;

	/* Available space: full buffer minus what's between read and write. */
	if (wp >= rp)
		avail = ring.size - (wp - rp);
	else
		avail = rp - wp;

	if (avail < total + 1) {
		/* Buffer full — best_effort: drop oldest events. */
		ring.status->overflow_count++;
		/* Advance read_ptr past enough events to make room.
		 * Simple approach: skip to write_ptr (discard everything). */
		ring.consumer->read_ptr = wp;
		/* Recalculate. */
		avail = ring.size;
	}

	/* Write, handling wrap. */
	end_offset = wp % ring.size;

	/* Header */
	if (end_offset + sizeof(*hdr) <= ring.size) {
		memcpy(ring.buffer + end_offset, hdr, sizeof(*hdr));
	} else {
		/* Header wraps — split copy. */
		u32 first = ring.size - end_offset;
		memcpy(ring.buffer + end_offset, hdr, first);
		memcpy(ring.buffer, (u8 *)hdr + first, sizeof(*hdr) - first);
	}

	/* Body */
	if (body_len > 0) {
		u64 body_offset = (end_offset + sizeof(*hdr)) % ring.size;
		if (body_offset + body_len <= ring.size) {
			memcpy(ring.buffer + body_offset, body, body_len);
		} else {
			u32 first = ring.size - body_offset;
			memcpy(ring.buffer + body_offset, body, first);
			memcpy(ring.buffer, (u8 *)body + first, body_len - first);
		}
	}

	ring.status->write_ptr = wp + total;
	spin_unlock_irqrestore(&ring.lock, flags);

	/* Notify eventd. */
	if (ring.notify)
		eventfd_signal(ring.notify);

	return 0;
}

/* ── Internal kernel emit (for KACS SACL, privilege use, etc.) ─────────── */

int peios_event_emit_kernel(const void *body, u32 body_len)
{
	struct peios_event_header hdr;
	unsigned long flags;

	if (!ring.buffer || body_len > EVENT_MAX_BODY_SIZE)
		return -EINVAL;

	hdr.timestamp_ns = ktime_get_ns();
	hdr.emitter_pid = current->tgid;
	hdr.emitter_tid = current->pid;
	hdr.emitter_uid = from_kuid(&init_user_ns, current_fsuid());
	hdr.payload_len = (u16)body_len;
	hdr.source = EVENT_SOURCE_KERNEL;
	hdr._pad = 0;

	spin_lock_irqsave(&ring.lock, flags);
	hdr.sequence = ring.sequence++;
	spin_unlock_irqrestore(&ring.lock, flags);

	return ring_write(&hdr, body, (u16)body_len);
}

/* ── Syscall: event_emit (1050) ────────────────────────────────────────── */

SYSCALL_DEFINE2(event_emit, const void __user *, body, u32, body_len)
{
	struct peios_event_header hdr;
	void *kbody;
	unsigned long flags;
	int ret;

	if (!ring.buffer)
		return -ENODEV;

	if (body_len == 0 || body_len > EVENT_MAX_BODY_SIZE)
		return -EINVAL;

	kbody = kmalloc(body_len, GFP_KERNEL);
	if (!kbody)
		return -ENOMEM;

	if (copy_from_user(kbody, body, body_len)) {
		kfree(kbody);
		return -EFAULT;
	}

	/*
	 * Namespace reservation: reject userspace events that use
	 * reserved prefixes. The event body is msgpack and the first
	 * element is the event type string. Rather than fully parsing
	 * msgpack, do a raw byte scan of the first 64 bytes for the
	 * reserved prefixes. This is imprecise but catches obvious
	 * attempts to forge kernel-namespace events.
	 */
	{
		u32 check_len = body_len < 64 ? body_len : 64;
		const u8 *p = kbody;
		u32 i;

		for (i = 0; i + 5 <= check_len; i++) {
			if (p[i] == 'k' && p[i+1] == 'a' && p[i+2] == 'c' &&
			    p[i+3] == 's' && p[i+4] == '.') {
				kfree(kbody);
				return -EPERM;
			}
		}
		for (i = 0; i + 7 <= check_len; i++) {
			if (p[i] == 'k' && p[i+1] == 'e' && p[i+2] == 'r' &&
			    p[i+3] == 'n' && p[i+4] == 'e' && p[i+5] == 'l' &&
			    p[i+6] == '.') {
				kfree(kbody);
				return -EPERM;
			}
		}
	}

	hdr.timestamp_ns = ktime_get_ns();
	hdr.emitter_pid = current->tgid;
	hdr.emitter_tid = current->pid;
	hdr.emitter_uid = 0; /* TODO: projected UID from token */
	hdr.payload_len = (u16)body_len;
	hdr.source = EVENT_SOURCE_USERSPACE;
	hdr._pad = 0;

	spin_lock_irqsave(&ring.lock, flags);
	hdr.sequence = ring.sequence++;
	spin_unlock_irqrestore(&ring.lock, flags);

	ret = ring_write(&hdr, kbody, (u16)body_len);
	kfree(kbody);
	return ret;
}

/* ── securityfs: /sys/kernel/security/peios/events ─────────────────────── */

/* TODO: mmap support for zero-copy drain by eventd.
 * For now, provide a simple read interface. */

static ssize_t events_read(struct file *file, char __user *buf,
			    size_t count, loff_t *ppos)
{
	/* Return status info for debugging. */
	char kbuf[128];
	int len;

	if (*ppos != 0)
		return 0;

	if (!ring.buffer)
		return -ENODEV;

	len = scnprintf(kbuf, sizeof(kbuf),
			"write_ptr: %llu\nread_ptr: %llu\n"
			"overflow: %llu\nsize: %llu\n",
			ring.status->write_ptr,
			ring.consumer->read_ptr,
			ring.status->overflow_count,
			ring.status->buffer_size);

	return simple_read_from_buffer(buf, count, ppos, kbuf, len);
}

/*
 * eventfd registration: eventd writes an fd number (as ASCII decimal)
 * to this file. The kernel calls eventfd_ctx_fdget() on that fd and
 * stores the context in ring.notify. Subsequent ring_write() calls
 * signal the eventfd, waking eventd without polling.
 */
static ssize_t events_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	char kbuf[16];
	struct eventfd_ctx *ctx;
	int fd;

	if (count > 15)
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = '\0';

	if (kstrtoint(kbuf, 10, &fd))
		return -EINVAL;

	/* Release previous eventfd context if any. */
	if (ring.notify)
		eventfd_ctx_put(ring.notify);

	ctx = eventfd_ctx_fdget(fd);
	if (IS_ERR(ctx)) {
		ring.notify = NULL;
		return PTR_ERR(ctx);
	}

	ring.notify = ctx;
	return count;
}

static const struct file_operations events_fops = {
	.read = events_read,
	.write = events_write,
	.llseek = generic_file_llseek,
	/* TODO: .mmap = events_mmap for zero-copy drain */
};

static int __init peios_events_init(void)
{
	struct dentry *peios_dir, *events_file;
	int ret;

	ret = ring_init();
	if (ret) {
		pr_err("peios: event ring buffer init failed: %d\n", ret);
		return ret;
	}

	peios_dir = securityfs_create_dir("peios", NULL);
	if (IS_ERR(peios_dir))
		return PTR_ERR(peios_dir);

	events_file = securityfs_create_file("events", 0644, peios_dir,
					     NULL, &events_fops);
	if (IS_ERR(events_file)) {
		securityfs_remove(peios_dir);
		return PTR_ERR(events_file);
	}

	pr_info("peios: event subsystem initialized (%llu KB ring buffer)\n",
		ring.size / 1024);
	return 0;
}
late_initcall(peios_events_init);
