// SPDX-License-Identifier: GPL-2.0-only
/*
 * LCS transaction-fd carrier.
 *
 * reg_begin_transaction() is source-agnostic: the fd holds a monotonic
 * transaction ID and remains unbound until a later mutating operation.
 */

#include <linux/anon_inodes.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/timer.h>
#include <linux/wait.h>

#include <pkm/lcs.h>

#include "transaction_fd.h"

struct pkm_lcs_transaction_fd {
	u64 transaction_id;
	u32 state;
	u32 bound_source_id;
	spinlock_t lock;
	wait_queue_head_t wait;
	struct timer_list timeout_timer;
};

static DEFINE_MUTEX(pkm_lcs_transaction_id_lock);
static u64 pkm_lcs_next_transaction_id = 1;

static const struct file_operations pkm_lcs_transaction_fd_fops;

static unsigned long pkm_lcs_transaction_deadline_from_timeout_ms(
	u32 timeout_ms)
{
	unsigned long delta = msecs_to_jiffies(timeout_ms);

	if (timeout_ms && !delta)
		delta = 1;
	return jiffies + delta;
}

static bool pkm_lcs_transaction_state_active(u32 state)
{
	return state == REG_TXN_ACTIVE_UNBOUND ||
	       state == REG_TXN_ACTIVE_BOUND;
}

static long pkm_lcs_transaction_id_allocate(u64 *transaction_id)
{
	long ret = 0;

	if (!transaction_id)
		return -EINVAL;
	*transaction_id = 0;

	mutex_lock(&pkm_lcs_transaction_id_lock);
	if (!pkm_lcs_next_transaction_id ||
	    pkm_lcs_next_transaction_id == U64_MAX) {
		ret = -EOVERFLOW;
		goto out_unlock;
	}

	*transaction_id = pkm_lcs_next_transaction_id++;

out_unlock:
	mutex_unlock(&pkm_lcs_transaction_id_lock);
	return ret;
}

static void pkm_lcs_transaction_fd_timeout(struct timer_list *timer)
{
	struct pkm_lcs_transaction_fd *txn =
		container_of(timer, struct pkm_lcs_transaction_fd,
			     timeout_timer);
	bool terminal = false;

	spin_lock(&txn->lock);
	if (pkm_lcs_transaction_state_active(txn->state)) {
		txn->state = REG_TXN_TIMED_OUT;
		terminal = true;
	}
	spin_unlock(&txn->lock);

	if (terminal)
		wake_up_all(&txn->wait);
}

static int pkm_lcs_transaction_fd_release(struct inode *inode,
					  struct file *file)
{
	struct pkm_lcs_transaction_fd *txn = file->private_data;

	file->private_data = NULL;
	if (!txn)
		return 0;

	timer_delete_sync(&txn->timeout_timer);

	spin_lock(&txn->lock);
	if (pkm_lcs_transaction_state_active(txn->state))
		txn->state = REG_TXN_ABORTED;
	spin_unlock(&txn->lock);

	wake_up_all(&txn->wait);
	kfree(txn);
	return 0;
}

static __poll_t pkm_lcs_transaction_fd_poll(struct file *file,
					    struct poll_table_struct *wait)
{
	struct pkm_lcs_transaction_fd *txn;
	__poll_t mask = 0;
	u32 state;

	if (!file)
		return EPOLLERR | EPOLLHUP;

	txn = file->private_data;
	if (!txn)
		return EPOLLERR | EPOLLHUP;

	poll_wait(file, &txn->wait, wait);

	spin_lock(&txn->lock);
	state = txn->state;
	spin_unlock(&txn->lock);

	if (!pkm_lcs_transaction_state_active(state))
		mask = EPOLLERR | EPOLLHUP;
	return mask;
}

static const struct file_operations pkm_lcs_transaction_fd_fops = {
	.owner = THIS_MODULE,
	.release = pkm_lcs_transaction_fd_release,
	.poll = pkm_lcs_transaction_fd_poll,
	.llseek = noop_llseek,
};

long pkm_lcs_transaction_fd_publish(u32 timeout_ms)
{
	struct pkm_lcs_transaction_fd *txn;
	long ret;
	int fd;

	if (!timeout_ms)
		return -EINVAL;

	txn = kzalloc(sizeof(*txn), GFP_KERNEL);
	if (!txn)
		return -ENOMEM;

	ret = pkm_lcs_transaction_id_allocate(&txn->transaction_id);
	if (ret)
		goto out_free;

	txn->state = REG_TXN_ACTIVE_UNBOUND;
	spin_lock_init(&txn->lock);
	init_waitqueue_head(&txn->wait);
	timer_setup(&txn->timeout_timer, pkm_lcs_transaction_fd_timeout, 0);

	fd = anon_inode_getfd("lcs-transaction", &pkm_lcs_transaction_fd_fops,
			      txn, O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto out_free;
	}

	mod_timer(&txn->timeout_timer,
		  pkm_lcs_transaction_deadline_from_timeout_ms(timeout_ms));
	return fd;

out_free:
	kfree(txn);
	return ret;
}

static long pkm_lcs_transaction_fd_get(
	int fd, struct fd *held, struct pkm_lcs_transaction_fd **txn_out)
{
	struct file *file;

	if (!held || !txn_out)
		return -EINVAL;
	*txn_out = NULL;

	*held = fdget(fd);
	file = fd_file(*held);
	if (!file)
		return -EBADF;

	if (file->f_op != &pkm_lcs_transaction_fd_fops) {
		fdput(*held);
		return -EINVAL;
	}

	*txn_out = file->private_data;
	if (!*txn_out) {
		fdput(*held);
		return -EINVAL;
	}

	return 0;
}

long pkm_lcs_transaction_fd_snapshot(
	int fd, struct pkm_lcs_transaction_fd_snapshot *out)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	spin_lock(&txn->lock);
	out->transaction_id = txn->transaction_id;
	out->state = txn->state;
	out->bound_source_id = txn->bound_source_id;
	out->timer_pending = timer_pending(&txn->timeout_timer);
	spin_unlock(&txn->lock);

	fdput(held);
	return 0;
}

long pkm_lcs_reg_begin_transaction(void)
{
	return pkm_lcs_transaction_fd_publish(
		PKM_LCS_TRANSACTION_TIMEOUT_MS_DEFAULT);
}

SYSCALL_DEFINE0(reg_begin_transaction)
{
	return pkm_lcs_reg_begin_transaction();
}
