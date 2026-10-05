// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS source response frame and waiter value helpers.
 */

#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/wait.h>

#include "source_internal.h"

#include <trace/events/lcs.h>

#ifdef CONFIG_SECURITY_PKM_KUNIT
void (*pkm_lcs_kunit_waiter_publish_hook)(
	struct pkm_lcs_source_response_waiter *waiter);
#endif

/*
 * A response waiter lives on its caller's stack, and the caller may return as
 * soon as it sees ->completed; several of its checks take no lock. So the
 * completer publishes ->completed and wakes inside one ->wait.lock section and
 * touches nothing after the unlock, and every exit from a wait takes
 * ->wait.lock once before the caller's frame can die. If the waiter saw
 * ->completed, that waits out the completer's section. If it did not, it was
 * detached under queue_lock and no completer holds the pointer. This is the
 * complete()/completion_done() contract.
 *
 * Lock order: LCS table mutex -> source_fd->queue_lock -> waiter->wait.lock.
 * wait.lock is a leaf: nothing is taken under it but the scheduler's own
 * wake-up locks, and nothing under it sleeps.
 */
static void pkm_lcs_source_response_waiter_sync(
	struct pkm_lcs_source_response_waiter *waiter)
{
	unsigned long flags;

	spin_lock_irqsave(&waiter->wait.lock, flags);
	spin_unlock_irqrestore(&waiter->wait.lock, flags);
}

void pkm_lcs_source_response_waiter_init(
	struct pkm_lcs_source_response_waiter *waiter)
{
	if (!waiter)
		return;

	memset(waiter, 0, sizeof(*waiter));
	init_waitqueue_head(&waiter->wait);
}

void pkm_lcs_source_response_frame_init(
	struct pkm_lcs_source_response_frame *frame)
{
	if (!frame)
		return;

	memset(frame, 0, sizeof(*frame));
}

void pkm_lcs_source_response_frame_destroy(
	struct pkm_lcs_source_response_frame *frame)
{
	if (!frame)
		return;

	kfree(frame->data);
	memset(frame, 0, sizeof(*frame));
}

long pkm_lcs_source_response_waiter_wait(
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_response_result *result)
{
	if (!waiter)
		return -EINVAL;

	wait_event(waiter->wait, READ_ONCE(waiter->completed));
	pkm_lcs_source_response_waiter_sync(waiter);
	if (result)
		*result = waiter->response;
	return waiter->response_errno;
}

unsigned long pkm_lcs_source_deadline_from_timeout_ms(u32 timeout_ms)
{
	unsigned long delta = msecs_to_jiffies(timeout_ms);

	if (timeout_ms && !delta)
		delta = 1;
	return jiffies + delta;
}

long pkm_lcs_source_deadline_remaining(unsigned long deadline)
{
	unsigned long now = jiffies;

	if (time_after_eq(now, deadline))
		return 0;
	return (long)(deadline - now);
}

long pkm_lcs_source_response_waiter_retain_frame(
	struct pkm_lcs_source_response_waiter *waiter,
	struct pkm_lcs_source_response_frame *frame)
{
	if (!waiter || !frame)
		return -EINVAL;

	pkm_lcs_source_response_frame_init(frame);
	waiter->retained_frame = frame;
	return 0;
}

void pkm_lcs_source_response_waiter_complete_with_frame(
	struct pkm_lcs_source_response_waiter *waiter, long response_errno,
	const struct pkm_lcs_source_response_result *result,
	const u8 *frame, size_t frame_len)
{
	struct pkm_lcs_source_response_frame *retained_frame;
	unsigned long flags;

	if (!waiter)
		return;

	retained_frame = waiter->retained_frame;
	if (!response_errno && retained_frame) {
		pkm_lcs_source_response_frame_destroy(retained_frame);
		if (!frame || !frame_len) {
			response_errno = -EIO;
		} else {
			retained_frame->data = kmemdup(frame, frame_len,
						       GFP_KERNEL);
			if (!retained_frame->data)
				response_errno = -ENOMEM;
			else
				retained_frame->len = frame_len;
		}
	}

	if (result)
		waiter->response = *result;
	else
		memset(&waiter->response, 0, sizeof(waiter->response));
	waiter->response_errno = response_errno;

	/*
	 * Everything above may sleep (kmemdup(GFP_KERNEL)); nothing below may.
	 * The unlock is the last access to @waiter: once it is released the
	 * waiter may return and its frame be reused. TASK_NORMAL, so the
	 * uninterruptible sleeper in pkm_lcs_source_response_waiter_wait() is
	 * woken as well as the interruptible one in _wait_until().
	 */
	spin_lock_irqsave(&waiter->wait.lock, flags);
	WRITE_ONCE(waiter->attached, false);
	WRITE_ONCE(waiter->completed, true);
#ifdef CONFIG_SECURITY_PKM_KUNIT
	if (READ_ONCE(pkm_lcs_kunit_waiter_publish_hook))
		pkm_lcs_kunit_waiter_publish_hook(waiter);
#endif
	wake_up_locked(&waiter->wait);
	spin_unlock_irqrestore(&waiter->wait.lock, flags);
}

void pkm_lcs_source_response_waiter_complete(
	struct pkm_lcs_source_response_waiter *waiter, long response_errno,
	const struct pkm_lcs_source_response_result *result)
{
	pkm_lcs_source_response_waiter_complete_with_frame(
		waiter, response_errno, result, NULL, 0);
}

bool pkm_lcs_source_response_waiter_detach(
	struct pkm_lcs_source_response_waiter *waiter)
{
	struct pkm_lcs_source_in_flight_request *record;
	struct pkm_lcs_source_fd *source_fd;
	struct pkm_lcs_source_slot *slot;
	bool detached = false;

	if (!waiter || READ_ONCE(waiter->completed))
		return false;

	pkm_lcs_source_table_lock();
	slot = pkm_lcs_source_slot_find_locked(waiter->source_id);
	if (!slot || !slot->active_fd)
		goto out_unlock_table;

	source_fd = slot->active_fd;
	mutex_lock(&source_fd->queue_lock);
	if (READ_ONCE(waiter->completed))
		goto out_unlock_queue;
	if (!READ_ONCE(waiter->attached))
		goto out_unlock_queue;

	record = pkm_lcs_source_in_flight_find_locked(source_fd,
						      waiter->request_id);
	if (record && record->waiter == waiter) {
		record->waiter = NULL;
		WRITE_ONCE(waiter->attached, false);
		WRITE_ONCE(waiter->detached, true);
		detached = true;
	}

out_unlock_queue:
	mutex_unlock(&source_fd->queue_lock);
out_unlock_table:
	pkm_lcs_source_table_unlock();
	return detached;
}

long pkm_lcs_source_response_waiter_wait_until(
	struct pkm_lcs_source_response_waiter *waiter, unsigned long deadline,
	struct pkm_lcs_source_response_result *result)
{
	long rc = -ETIMEDOUT;
	long ret;

	if (!waiter)
		return -EINVAL;

	for (;;) {
		long remaining;

		if (READ_ONCE(waiter->completed)) {
			rc = waiter->response_errno;
			goto out;
		}

		remaining = pkm_lcs_source_deadline_remaining(deadline);
		if (!remaining)
			break;

		ret = wait_event_interruptible_timeout(
			waiter->wait, READ_ONCE(waiter->completed),
			remaining);
		if (ret < 0) {
			pkm_lcs_source_response_waiter_detach(waiter);
			rc = ret;
			goto out;
		}
		if (!ret)
			break;
	}

	if (READ_ONCE(waiter->completed)) {
		rc = waiter->response_errno;
		goto out;
	}

	pkm_lcs_source_response_waiter_detach(waiter);
	if (READ_ONCE(waiter->completed)) {
		rc = waiter->response_errno;
		goto out;
	}
	rc = -ETIMEDOUT;

out:
	/*
	 * Any of the lockless ->completed checks above may have seen the
	 * completion while the completer is still inside its ->wait.lock
	 * section. Wait that out before reading ->response or letting the
	 * caller's frame die.
	 */
	pkm_lcs_source_response_waiter_sync(waiter);
	/*
	 * The response-wait leg of a source round trip: `waited` is always true
	 * here, `timed_out` distinguishes the deadline expiry. op is unknown at
	 * this shared sink (0); txn_id is only meaningful once completed.
	 */
	if (READ_ONCE(waiter->completed)) {
		if (result)
			*result = waiter->response;
		trace_lcs_rsi_roundtrip_complete(waiter->source_id, 0,
						 waiter->response.txn_id, 0,
						 true, false, rc);
	} else {
		trace_lcs_rsi_roundtrip_complete(waiter->source_id, 0, 0, 0,
						 true, rc == -ETIMEDOUT, rc);
	}
	return rc;
}
