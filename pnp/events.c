// SPDX-License-Identifier: GPL-2.0-only
/*
 * The verdict event stream: one record per evaluation, drained through
 * /dev/peios-pnp (misc device, mode 0600, one reader at a time — the
 * intended consumer is pnpd, the observer/authoring daemon).
 *
 * The ring is bounded and overwrites the OLDEST record under pressure;
 * every overwrite is counted and confessed via status (and visible as a
 * seq gap). Writers run in the hook path (softirq), the reader in
 * process context: one irqsave spinlock, held only for copies.
 *
 * ABI: <pkm/pnp.h>. Experimental until PNP ships (PEI-598).
 */

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

#include <pkm/pnp.h>

#include "pnp.h"

#define PEIOS_PNP_EVENT_RING 4096U

static struct {
	spinlock_t lock;
	struct peios_pnp_event *buf;	/* PEIOS_PNP_EVENT_RING entries */
	u32 head;			/* next write slot */
	u32 count;			/* live records */
	u64 next_seq;
	u64 dropped;
	wait_queue_head_t wq;
	atomic_t open;			/* single-reader gate */
} peios_pnp_events = {
	.lock = __SPIN_LOCK_UNLOCKED(peios_pnp_events.lock),
	.wq = __WAIT_QUEUE_HEAD_INITIALIZER(peios_pnp_events.wq),
	.open = ATOMIC_INIT(0),
};

static u8 saturate_u8(u32 v)
{
	return v > 0xff ? 0xff : v;
}

void peios_pnp_event_emit(const struct peios_pnp_snapshot *snap,
			  const struct peios_pnp_outcome *out, u8 layer,
			  u8 flags)
{
	struct peios_pnp_event ev = { };
	unsigned long irqflags;
	u32 slot;

	if (!peios_pnp_events.buf)
		return;

	ev.t_ns = ktime_get_real_ns();
	ev.seat = snap->seat;
	ev.layer = layer;
	ev.verdict = out->verdict;
	ev.reject_kind = out->reject_kind;
	ev.flags = flags | (out->backstop ? PEIOS_PNP_EV_F_BACKSTOP : 0);
	ev.direction = snap->direction;
	ev.addr_family = snap->addr_family;
	ev.protocol = snap->protocol;
	ev.flow_state = snap->flow_state;
	ev.ifindex = snap->ifindex;
	ev.src_port = snap->src_port;
	ev.dst_port = snap->dst_port;
	ev.ether_type = snap->ether_type;
	memcpy(ev.src_addr, snap->src_addr, 16);
	memcpy(ev.dst_addr, snap->dst_addr, 16);
	ev.length = snap->length;
	ev.effects = saturate_u8(out->n_tags) |
		     (u32)saturate_u8(out->n_counts) << 8 |
		     (u32)saturate_u8(out->n_reports) << 16 |
		     (u32)saturate_u8(out->n_prompts) << 24;
	strscpy((char *)ev.attributed, out->attributed,
		sizeof(ev.attributed));

	spin_lock_irqsave(&peios_pnp_events.lock, irqflags);
	ev.seq = peios_pnp_events.next_seq++;
	slot = peios_pnp_events.head;
	peios_pnp_events.buf[slot] = ev;
	peios_pnp_events.head = (slot + 1) % PEIOS_PNP_EVENT_RING;
	if (peios_pnp_events.count < PEIOS_PNP_EVENT_RING)
		peios_pnp_events.count++;
	else
		peios_pnp_events.dropped++;	/* oldest overwritten */
	spin_unlock_irqrestore(&peios_pnp_events.lock, irqflags);

	wake_up_interruptible(&peios_pnp_events.wq);
}

u64 peios_pnp_events_dropped(void)
{
	unsigned long irqflags;
	u64 dropped;

	spin_lock_irqsave(&peios_pnp_events.lock, irqflags);
	dropped = peios_pnp_events.dropped;
	spin_unlock_irqrestore(&peios_pnp_events.lock, irqflags);
	return dropped;
}

/* Copies up to `max` oldest records into `out`, consuming them. */
static u32 peios_pnp_events_pop(struct peios_pnp_event *out, u32 max)
{
	unsigned long irqflags;
	u32 taken = 0;

	spin_lock_irqsave(&peios_pnp_events.lock, irqflags);
	while (taken < max && peios_pnp_events.count) {
		u32 tail = (peios_pnp_events.head + PEIOS_PNP_EVENT_RING -
			    peios_pnp_events.count) % PEIOS_PNP_EVENT_RING;

		out[taken++] = peios_pnp_events.buf[tail];
		peios_pnp_events.count--;
	}
	spin_unlock_irqrestore(&peios_pnp_events.lock, irqflags);
	return taken;
}

static int peios_pnp_dev_open(struct inode *inode, struct file *file)
{
	if (atomic_cmpxchg(&peios_pnp_events.open, 0, 1))
		return -EBUSY;
	return 0;
}

static int peios_pnp_dev_release(struct inode *inode, struct file *file)
{
	atomic_set(&peios_pnp_events.open, 0);
	return 0;
}

static ssize_t peios_pnp_dev_read(struct file *file, char __user *ubuf,
				  size_t len, loff_t *ppos)
{
	struct peios_pnp_event *batch;
	u32 want, got;
	ssize_t ret;

	want = len / sizeof(struct peios_pnp_event);
	if (!want)
		return -EINVAL;
	want = min_t(u32, want, 64);

	batch = kmalloc_array(want, sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return -ENOMEM;

	for (;;) {
		got = peios_pnp_events_pop(batch, want);
		if (got)
			break;
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		}
		ret = wait_event_interruptible(peios_pnp_events.wq,
					       peios_pnp_events.count);
		if (ret)
			goto out;
	}

	if (copy_to_user(ubuf, batch, got * sizeof(*batch))) {
		ret = -EFAULT;
		goto out;
	}
	ret = got * sizeof(*batch);
out:
	kfree(batch);
	return ret;
}

static __poll_t peios_pnp_dev_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &peios_pnp_events.wq, wait);
	return peios_pnp_events.count ? EPOLLIN | EPOLLRDNORM : 0;
}

static long peios_pnp_dev_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case PEIOS_PNP_IOC_STATUS: {
		struct peios_pnp_status status;

		peios_pnp_status_fill(&status);
		if (copy_to_user(uarg, &status, sizeof(status)))
			return -EFAULT;
		return 0;
	}
	case PEIOS_PNP_IOC_COUNTERS: {
		struct peios_pnp_counters_query query;
		long ret;

		if (copy_from_user(&query, uarg, sizeof(query)))
			return -EFAULT;
		ret = peios_pnp_counters_dump(&query);
		if (ret)
			return ret;
		if (copy_to_user(uarg, &query, sizeof(query)))
			return -EFAULT;
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations peios_pnp_dev_fops = {
	.owner = THIS_MODULE,
	.open = peios_pnp_dev_open,
	.release = peios_pnp_dev_release,
	.read = peios_pnp_dev_read,
	.poll = peios_pnp_dev_poll,
	.unlocked_ioctl = peios_pnp_dev_ioctl,
};

static struct miscdevice peios_pnp_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "peios-pnp",
	.mode = 0600,
	.fops = &peios_pnp_dev_fops,
};

int __init peios_pnp_events_init(void)
{
	int ret;

	peios_pnp_events.buf = vzalloc(array_size(
		PEIOS_PNP_EVENT_RING, sizeof(struct peios_pnp_event)));
	if (!peios_pnp_events.buf)
		return -ENOMEM;

	ret = misc_register(&peios_pnp_dev);
	if (ret) {
		vfree(peios_pnp_events.buf);
		peios_pnp_events.buf = NULL;
		pr_err("pnp: /dev/peios-pnp registration failed (%d)\n", ret);
	}
	return ret;
}
