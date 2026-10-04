// SPDX-License-Identifier: GPL-2.0-only
/*
 * The verdict event stream: one record per evaluation, drained through
 * /dev/peios-ntfe (misc device, mode 0600, one reader at a time — the
 * intended consumer is pnpd, the observer/authoring daemon).
 *
 * The ring is bounded and overwrites the OLDEST record under pressure;
 * every overwrite is counted and confessed via status (and visible as a
 * seq gap). Writers run in the hook path (softirq), the reader in
 * process context: one irqsave spinlock, held only for copies.
 *
 * ABI: <pkm/ntfe.h>. Experimental until NTFE ships (PEI-598).
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

#include <pkm/ntfe.h>

#include "ntfe.h"

#define PEIOS_NTFE_EVENT_RING 4096U

static struct {
	spinlock_t lock;
	struct peios_ntfe_event *buf;	/* PEIOS_NTFE_EVENT_RING entries */
	u32 head;			/* next write slot */
	u32 count;			/* live records */
	u64 next_seq;
	u64 dropped;
	wait_queue_head_t wq;
	struct file *reader;		/* the one file draining the ring */
} peios_ntfe_events = {
	.lock = __SPIN_LOCK_UNLOCKED(peios_ntfe_events.lock),
	.wq = __WAIT_QUEUE_HEAD_INITIALIZER(peios_ntfe_events.wq),
};

static u8 saturate_u8(u32 v)
{
	return v > 0xff ? 0xff : v;
}

void peios_ntfe_event_emit(const struct peios_ntfe_snapshot *snap,
			  const struct peios_ntfe_outcome *out, u8 layer,
			  u8 flags)
{
	struct peios_ntfe_event ev = { };
	unsigned long irqflags;
	u32 slot;

	if (!peios_ntfe_events.buf)
		return;

	ev.t_ns = ktime_get_real_ns();
	ev.seat = snap->seat;
	ev.layer = layer;
	ev.verdict = out->verdict;
	ev.reject_kind = out->reject_kind;
	ev.flags = flags | (out->backstop ? PEIOS_NTFE_EV_F_BACKSTOP : 0);
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
	/* The identity facts: set on Flow views, zero everywhere else. */
	ev.local_kind = snap->local_kind;
	ev.remote_kind = snap->remote_kind;
	ev.local_unresolved = snap->local_unresolved;
	ev.remote_unresolved = snap->remote_unresolved;
	ev.local_pid = snap->local_pid;
	ev.remote_pid = snap->remote_pid;
	memcpy(ev.local_guid, snap->local_guid, sizeof(ev.local_guid));
	memcpy(ev.remote_guid, snap->remote_guid, sizeof(ev.remote_guid));
	memcpy(ev.local_comm, snap->local_comm, sizeof(ev.local_comm));
	memcpy(ev.remote_comm, snap->remote_comm, sizeof(ev.remote_comm));
	if (snap->local_token)
		ntfe_rust_owner_sids(snap->local_token, ev.local_user,
				    ev.local_service);
	if (snap->remote_token)
		ntfe_rust_owner_sids(snap->remote_token, ev.remote_user,
				    ev.remote_service);

	spin_lock_irqsave(&peios_ntfe_events.lock, irqflags);
	ev.seq = peios_ntfe_events.next_seq++;
	slot = peios_ntfe_events.head;
	peios_ntfe_events.buf[slot] = ev;
	peios_ntfe_events.head = (slot + 1) % PEIOS_NTFE_EVENT_RING;
	if (peios_ntfe_events.count < PEIOS_NTFE_EVENT_RING)
		peios_ntfe_events.count++;
	else
		peios_ntfe_events.dropped++;	/* oldest overwritten */
	spin_unlock_irqrestore(&peios_ntfe_events.lock, irqflags);

	wake_up_interruptible(&peios_ntfe_events.wq);
}

u64 peios_ntfe_events_dropped(void)
{
	unsigned long irqflags;
	u64 dropped;

	spin_lock_irqsave(&peios_ntfe_events.lock, irqflags);
	dropped = peios_ntfe_events.dropped;
	spin_unlock_irqrestore(&peios_ntfe_events.lock, irqflags);
	return dropped;
}

/* Copies up to `max` oldest records into `out`, consuming them. */
static u32 peios_ntfe_events_pop(struct peios_ntfe_event *out, u32 max)
{
	unsigned long irqflags;
	u32 taken = 0;

	spin_lock_irqsave(&peios_ntfe_events.lock, irqflags);
	while (taken < max && peios_ntfe_events.count) {
		u32 tail = (peios_ntfe_events.head + PEIOS_NTFE_EVENT_RING -
			    peios_ntfe_events.count) % PEIOS_NTFE_EVENT_RING;

		out[taken++] = peios_ntfe_events.buf[tail];
		peios_ntfe_events.count--;
	}
	spin_unlock_irqrestore(&peios_ntfe_events.lock, irqflags);
	return taken;
}

/*
 * Any number of files may be open — status and the dumps are ioctls a
 * tool asks while a viewer holds the stream — but the ring has one
 * drain. The first file to read() claims it and keeps it until it
 * closes; another file's read() is -EBUSY meanwhile.
 */
static int peios_ntfe_dev_release(struct inode *inode, struct file *file)
{
	cmpxchg(&peios_ntfe_events.reader, file, NULL);
	return 0;
}

static ssize_t peios_ntfe_dev_read(struct file *file, char __user *ubuf,
				  size_t len, loff_t *ppos)
{
	struct peios_ntfe_event *batch;
	u32 want, got;
	ssize_t ret;

	if (READ_ONCE(peios_ntfe_events.reader) != file &&
	    cmpxchg(&peios_ntfe_events.reader, NULL, file))
		return -EBUSY;

	want = len / sizeof(struct peios_ntfe_event);
	if (!want)
		return -EINVAL;
	want = min_t(u32, want, 64);

	batch = peios_ntfe_kunit_alloc_should_fail() ? NULL :
		kmalloc_array(want, sizeof(*batch), GFP_KERNEL);
	if (!batch)
		return -ENOMEM;

	for (;;) {
		got = peios_ntfe_events_pop(batch, want);
		if (got)
			break;
		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		}
		ret = wait_event_interruptible(peios_ntfe_events.wq,
					       peios_ntfe_events.count);
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

static __poll_t peios_ntfe_dev_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &peios_ntfe_events.wq, wait);
	return peios_ntfe_events.count ? EPOLLIN | EPOLLRDNORM : 0;
}

static long peios_ntfe_dev_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case PEIOS_NTFE_IOC_STATUS: {
		struct peios_ntfe_status status;

		peios_ntfe_status_fill(&status);
		if (copy_to_user(uarg, &status, sizeof(status)))
			return -EFAULT;
		return 0;
	}
	case PEIOS_NTFE_IOC_COUNTERS: {
		struct peios_ntfe_counters_query query;
		long ret;

		if (copy_from_user(&query, uarg, sizeof(query)))
			return -EFAULT;
		ret = peios_ntfe_counters_dump(&query);
		if (ret)
			return ret;
		if (copy_to_user(uarg, &query, sizeof(query)))
			return -EFAULT;
		return 0;
	}
	case PEIOS_NTFE_IOC_FLOWS: {
		struct peios_ntfe_flows_query query;
		long ret;

		if (copy_from_user(&query, uarg, sizeof(query)))
			return -EFAULT;
		ret = peios_ntfe_flows_dump(&query);
		if (ret)
			return ret;
		if (copy_to_user(uarg, &query, sizeof(query)))
			return -EFAULT;
		return 0;
	}
	case PEIOS_NTFE_IOC_LISTENERS: {
		struct peios_ntfe_listeners_query query;
		long ret;

		if (copy_from_user(&query, uarg, sizeof(query)))
			return -EFAULT;
		ret = peios_ntfe_listeners_dump(&query);
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

static const struct file_operations peios_ntfe_dev_fops = {
	.owner = THIS_MODULE,
	.release = peios_ntfe_dev_release,
	.read = peios_ntfe_dev_read,
	.poll = peios_ntfe_dev_poll,
	.unlocked_ioctl = peios_ntfe_dev_ioctl,
};

static struct miscdevice peios_ntfe_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "peios-ntfe",
	.mode = 0600,
	.fops = &peios_ntfe_dev_fops,
};

#ifdef CONFIG_PEIOS_NTFE_KUNIT
u32 peios_ntfe_kunit_events_pop(struct peios_ntfe_event *out, u32 max)
{
	return peios_ntfe_events_pop(out, max);
}

const struct file_operations *peios_ntfe_kunit_dev_fops(void)
{
	return &peios_ntfe_dev_fops;
}
#endif

int __init peios_ntfe_events_init(void)
{
	int ret;

	peios_ntfe_events.buf = vzalloc(array_size(
		PEIOS_NTFE_EVENT_RING, sizeof(struct peios_ntfe_event)));
	if (!peios_ntfe_events.buf)
		return -ENOMEM;

	ret = misc_register(&peios_ntfe_dev);
	if (ret) {
		vfree(peios_ntfe_events.buf);
		peios_ntfe_events.buf = NULL;
		pr_err("ntfe: /dev/peios-ntfe registration failed (%d)\n", ret);
	}
	return ret;
}
