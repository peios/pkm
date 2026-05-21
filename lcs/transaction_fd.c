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
#include <linux/uaccess.h>
#include <linux/wait.h>

#include <pkm/lcs.h>

#include "transaction_fd.h"
#include "source_device.h"

struct pkm_lcs_transaction_fd {
	u64 transaction_id;
	u32 state;
	u32 bound_source_id;
	u8 bound_root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	spinlock_t lock;
	struct mutex bind_lock;
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

static long pkm_lcs_transaction_terminal_errno(u32 state, s32 *errno_out)
{
	if (!errno_out)
		return -EINVAL;

	switch (state) {
	case REG_TXN_ACTIVE_UNBOUND:
	case REG_TXN_ACTIVE_BOUND:
	case REG_TXN_COMMITTED:
		*errno_out = 0;
		return 0;
	case REG_TXN_ABORTED:
		*errno_out = EINVAL;
		return 0;
	case REG_TXN_TIMED_OUT:
		*errno_out = ETIMEDOUT;
		return 0;
	case REG_TXN_SOURCE_DOWN:
		*errno_out = EIO;
		return 0;
	default:
		*errno_out = 0;
		return -EIO;
	}
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

static bool pkm_lcs_transaction_root_guid_valid(
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
{
	u32 i;

	if (!root_guid)
		return false;

	for (i = 0; i < PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES; i++) {
		if (root_guid[i])
			return true;
	}
	return false;
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

static long pkm_lcs_transaction_fd_status_from_state(
	struct pkm_lcs_transaction_fd *txn, struct reg_txn_status_args *out)
{
	u32 state;
	long ret;

	if (!txn || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	spin_lock(&txn->lock);
	state = txn->state;
	spin_unlock(&txn->lock);

	ret = pkm_lcs_transaction_terminal_errno(state, &out->terminal_errno);
	if (ret) {
		memset(out, 0, sizeof(*out));
		return ret;
	}
	out->state = state;
	return 0;
}

static long pkm_lcs_transaction_fd_commit_from_state(
	struct pkm_lcs_transaction_fd *txn)
{
	u32 state;

	if (!txn)
		return -EINVAL;

	spin_lock(&txn->lock);
	state = txn->state;
	spin_unlock(&txn->lock);

	switch (state) {
	case REG_TXN_ACTIVE_UNBOUND:
	case REG_TXN_COMMITTED:
	case REG_TXN_ABORTED:
		return -EINVAL;
	case REG_TXN_TIMED_OUT:
		return -ETIMEDOUT;
	case REG_TXN_SOURCE_DOWN:
		return -EIO;
	case REG_TXN_ACTIVE_BOUND:
		return -EIO;
	default:
		return -EIO;
	}
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

static long pkm_lcs_transaction_fd_ioctl(struct file *file, unsigned int cmd,
					 unsigned long arg)
{
	struct pkm_lcs_transaction_fd *txn;
	struct reg_txn_status_args status;
	long ret;

	if (!file)
		return -EBADF;

	txn = file->private_data;
	if (!txn)
		return -EINVAL;

	switch (cmd) {
	case REG_IOC_COMMIT:
		return pkm_lcs_transaction_fd_commit_from_state(txn);
	case REG_IOC_TXN_STATUS:
		if (!arg)
			return -EFAULT;
		ret = pkm_lcs_transaction_fd_status_from_state(txn, &status);
		if (ret)
			return ret;
		if (copy_to_user((void __user *)arg, &status, sizeof(status)))
			return -EFAULT;
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations pkm_lcs_transaction_fd_fops = {
	.owner = THIS_MODULE,
	.release = pkm_lcs_transaction_fd_release,
	.poll = pkm_lcs_transaction_fd_poll,
	.unlocked_ioctl = pkm_lcs_transaction_fd_ioctl,
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
	mutex_init(&txn->bind_lock);
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
	memcpy(out->bound_root_guid, txn->bound_root_guid,
	       sizeof(out->bound_root_guid));
	out->timer_pending = timer_pending(&txn->timeout_timer);
	spin_unlock(&txn->lock);

	fdput(held);
	return 0;
}

long pkm_lcs_transaction_fd_status(int fd, struct reg_txn_status_args *out)
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

	ret = pkm_lcs_transaction_fd_status_from_state(txn, out);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_commit(int fd)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_fd_commit_from_state(txn);
	fdput(held);
	return ret;
}

static long pkm_lcs_transaction_fd_prepare_read_context_from_state(
	struct pkm_lcs_transaction_fd *txn, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_read_plan *out)
{
	u32 state;
	long ret;

	if (!txn || !out || !source_id ||
	    !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	spin_lock(&txn->lock);
	state = txn->state;
	out->state = state;
	out->bound_source_id = txn->bound_source_id;
	memcpy(out->bound_root_guid, txn->bound_root_guid,
	       sizeof(out->bound_root_guid));
	switch (state) {
	case REG_TXN_ACTIVE_UNBOUND:
		out->txn_id = 0;
		out->use_transaction = false;
		ret = 0;
		break;
	case REG_TXN_ACTIVE_BOUND:
		if (txn->bound_source_id == source_id &&
		    !memcmp(txn->bound_root_guid, root_guid,
			    sizeof(txn->bound_root_guid))) {
			out->txn_id = txn->transaction_id;
			out->use_transaction = true;
			ret = 0;
		} else {
			memset(out, 0, sizeof(*out));
			ret = -EXDEV;
		}
		break;
	case REG_TXN_TIMED_OUT:
		memset(out, 0, sizeof(*out));
		ret = -ETIMEDOUT;
		break;
	case REG_TXN_SOURCE_DOWN:
		memset(out, 0, sizeof(*out));
		ret = -EIO;
		break;
	case REG_TXN_COMMITTED:
	case REG_TXN_ABORTED:
		memset(out, 0, sizeof(*out));
		ret = -EINVAL;
		break;
	default:
		memset(out, 0, sizeof(*out));
		ret = -EIO;
		break;
	}
	spin_unlock(&txn->lock);
	return ret;
}

long pkm_lcs_transaction_fd_prepare_read_context(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_read_plan *out)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!source_id || !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_fd_prepare_read_context_from_state(
		txn, source_id, root_guid, out);
	fdput(held);
	return ret;
}

static long pkm_lcs_transaction_fd_prepare_mutation_binding_from_state(
	struct pkm_lcs_transaction_fd *txn, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_binding_plan *out)
{
	u32 state;
	long ret;

	if (!txn || !out || !source_id ||
	    !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	spin_lock(&txn->lock);
	state = txn->state;
	out->transaction_id = txn->transaction_id;
	out->state = state;
	out->bound_source_id = txn->bound_source_id;
	memcpy(out->bound_root_guid, txn->bound_root_guid,
	       sizeof(out->bound_root_guid));
	switch (state) {
	case REG_TXN_ACTIVE_UNBOUND:
		out->action = PKM_LCS_TRANSACTION_BIND_NEW;
		ret = 0;
		break;
	case REG_TXN_ACTIVE_BOUND:
		if (txn->bound_source_id == source_id &&
		    !memcmp(txn->bound_root_guid, root_guid,
			    sizeof(txn->bound_root_guid))) {
			out->action = PKM_LCS_TRANSACTION_BIND_REUSE;
			ret = 0;
		} else {
			memset(out, 0, sizeof(*out));
			ret = -EXDEV;
		}
		break;
	case REG_TXN_TIMED_OUT:
		memset(out, 0, sizeof(*out));
		ret = -ETIMEDOUT;
		break;
	case REG_TXN_SOURCE_DOWN:
		memset(out, 0, sizeof(*out));
		ret = -EIO;
		break;
	case REG_TXN_COMMITTED:
	case REG_TXN_ABORTED:
		memset(out, 0, sizeof(*out));
		ret = -EINVAL;
		break;
	default:
		memset(out, 0, sizeof(*out));
		ret = -EIO;
		break;
	}
	spin_unlock(&txn->lock);
	return ret;
}

long pkm_lcs_transaction_fd_prepare_mutation_binding(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_binding_plan *out)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!source_id || !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_fd_prepare_mutation_binding_from_state(
		txn, source_id, root_guid, out);
	fdput(held);
	return ret;
}

static long pkm_lcs_transaction_fd_complete_first_bind_from_state(
	struct pkm_lcs_transaction_fd *txn, u64 transaction_id, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
{
	long ret = 0;

	if (!txn || !transaction_id || !source_id ||
	    !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	spin_lock(&txn->lock);
	switch (txn->state) {
	case REG_TXN_ACTIVE_UNBOUND:
		if (txn->transaction_id != transaction_id) {
			ret = -EINVAL;
			break;
		}
		txn->state = REG_TXN_ACTIVE_BOUND;
		txn->bound_source_id = source_id;
		memcpy(txn->bound_root_guid, root_guid,
		       sizeof(txn->bound_root_guid));
		ret = 0;
		break;
	case REG_TXN_TIMED_OUT:
		ret = -ETIMEDOUT;
		break;
	case REG_TXN_SOURCE_DOWN:
		ret = -EIO;
		break;
	case REG_TXN_ACTIVE_BOUND:
	case REG_TXN_COMMITTED:
	case REG_TXN_ABORTED:
		ret = -EINVAL;
		break;
	default:
		ret = -EIO;
		break;
	}
	spin_unlock(&txn->lock);

	return ret;
}

long pkm_lcs_transaction_fd_complete_first_bind(
	int fd, u64 transaction_id, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES])
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	ret = pkm_lcs_transaction_fd_complete_first_bind_from_state(
		txn, transaction_id, source_id, root_guid);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_bind_for_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	struct pkm_lcs_transaction_binding_plan *out)
{
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	u32 count = 0;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	if (!source_id || !pkm_lcs_transaction_root_guid_valid(root_guid))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	mutex_lock(&txn->bind_lock);

	ret = pkm_lcs_transaction_fd_prepare_mutation_binding_from_state(
		txn, source_id, root_guid, &plan);
	if (ret)
		goto out_unlock;

	if (plan.action == PKM_LCS_TRANSACTION_BIND_REUSE) {
		*out = plan;
		goto out_unlock;
	}

	ret = pkm_lcs_source_bound_transaction_acquire(source_id, &count);
	if (ret)
		goto out_clear;

	ret = pkm_lcs_source_begin_transaction_round_trip(
		source_id, plan.transaction_id, RSI_TXN_READ_WRITE, NULL, NULL);
	if (ret)
		goto out_release_counter;

	ret = pkm_lcs_transaction_fd_complete_first_bind_from_state(
		txn, plan.transaction_id, source_id, root_guid);
	if (ret) {
		(void)pkm_lcs_source_dispatch_abort_transaction_request(
			source_id, plan.transaction_id, NULL);
		goto out_release_counter;
	}

	plan.state = REG_TXN_ACTIVE_BOUND;
	plan.bound_source_id = source_id;
	memcpy(plan.bound_root_guid, root_guid, sizeof(plan.bound_root_guid));
	*out = plan;
	goto out_unlock;

out_release_counter:
	(void)pkm_lcs_source_bound_transaction_release(source_id, &count);
out_clear:
	memset(out, 0, sizeof(*out));
out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	return ret;
}

#ifdef CONFIG_SECURITY_PKM_KUNIT
static bool pkm_lcs_transaction_state_known(u32 state)
{
	return state == REG_TXN_ACTIVE_UNBOUND ||
	       state == REG_TXN_ACTIVE_BOUND ||
	       state == REG_TXN_COMMITTED ||
	       state == REG_TXN_ABORTED ||
	       state == REG_TXN_TIMED_OUT ||
	       state == REG_TXN_SOURCE_DOWN;
}

long pkm_lcs_kunit_transaction_fd_set_state(int fd, u32 state,
					    u32 bound_source_id)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	if (!pkm_lcs_transaction_state_known(state))
		return -EINVAL;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	spin_lock(&txn->lock);
	txn->state = state;
	txn->bound_source_id = bound_source_id;
	memset(txn->bound_root_guid, 0, sizeof(txn->bound_root_guid));
	spin_unlock(&txn->lock);

	if (!pkm_lcs_transaction_state_active(state))
		wake_up_all(&txn->wait);

	fdput(held);
	return 0;
}
#endif

long pkm_lcs_reg_begin_transaction(void)
{
	return pkm_lcs_transaction_fd_publish(
		PKM_LCS_TRANSACTION_TIMEOUT_MS_DEFAULT);
}

SYSCALL_DEFINE0(reg_begin_transaction)
{
	return pkm_lcs_reg_begin_transaction();
}
