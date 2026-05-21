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
#include <linux/list.h>
#include <linux/limits.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include <pkm/lcs.h>

#include "transaction_fd.h"
#include "source_device.h"

struct pkm_lcs_transaction_fd {
	u64 transaction_id;
	u64 next_operation_index;
	u32 state;
	u32 bound_source_id;
	u8 bound_root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	spinlock_t lock;
	struct mutex bind_lock;
	wait_queue_head_t wait;
	struct timer_list timeout_timer;
	struct work_struct timeout_work;
	struct list_head registry_link;
	struct list_head mutation_log;
	u32 mutation_log_entries;
	u32 mutation_log_capacity;
	bool commit_in_flight;
	bool timeout_abort_pending;
	bool registry_linked;
};

struct pkm_lcs_transaction_key_create_log {
	u8 parent_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u8 target_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u64 sequence;
	char *child_name;
	char *layer;
	char **parent_path;
	u8 (*parent_ancestor_guids)[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES];
	u32 child_name_len;
	u32 layer_len;
	u32 parent_depth;
};

struct pkm_lcs_transaction_log_entry {
	struct list_head link;
	u64 operation_index;
	u32 kind;
	union {
		struct pkm_lcs_transaction_key_create_log create_key;
	};
};

static DEFINE_MUTEX(pkm_lcs_transaction_id_lock);
static u64 pkm_lcs_next_transaction_id = 1;
static DEFINE_MUTEX(pkm_lcs_transaction_registry_lock);
static LIST_HEAD(pkm_lcs_transaction_registry);

static const struct file_operations pkm_lcs_transaction_fd_fops;
static long pkm_lcs_transaction_fd_complete_first_bind_from_state(
	struct pkm_lcs_transaction_fd *txn, u64 transaction_id, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES]);

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

static void
pkm_lcs_transaction_fd_registry_add(struct pkm_lcs_transaction_fd *txn)
{
	if (!txn)
		return;

	mutex_lock(&pkm_lcs_transaction_registry_lock);
	if (!txn->registry_linked) {
		list_add_tail(&txn->registry_link, &pkm_lcs_transaction_registry);
		txn->registry_linked = true;
	}
	mutex_unlock(&pkm_lcs_transaction_registry_lock);
}

static void
pkm_lcs_transaction_fd_registry_remove(struct pkm_lcs_transaction_fd *txn)
{
	if (!txn)
		return;

	mutex_lock(&pkm_lcs_transaction_registry_lock);
	if (txn->registry_linked) {
		list_del_init(&txn->registry_link);
		txn->registry_linked = false;
	}
	mutex_unlock(&pkm_lcs_transaction_registry_lock);
}

static bool pkm_lcs_transaction_name_len_valid(size_t len)
{
	return len && len <= U16_MAX;
}

static void pkm_lcs_transaction_key_create_log_destroy(
	struct pkm_lcs_transaction_key_create_log *entry)
{
	u32 i;

	if (!entry)
		return;

	kfree(entry->child_name);
	kfree(entry->layer);
	if (entry->parent_path) {
		for (i = 0; i < entry->parent_depth; i++)
			kfree(entry->parent_path[i]);
		kfree(entry->parent_path);
	}
	kfree(entry->parent_ancestor_guids);
	memset(entry, 0, sizeof(*entry));
}

static void pkm_lcs_transaction_log_entry_destroy(
	struct pkm_lcs_transaction_log_entry *entry)
{
	if (!entry)
		return;

	switch (entry->kind) {
	case PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY:
		pkm_lcs_transaction_key_create_log_destroy(
			&entry->create_key);
		break;
	default:
		break;
	}
	kfree(entry);
}

static void pkm_lcs_transaction_log_clear(
	struct pkm_lcs_transaction_fd *txn)
{
	struct pkm_lcs_transaction_log_entry *entry;
	struct pkm_lcs_transaction_log_entry *tmp;

	if (!txn)
		return;

	list_for_each_entry_safe(entry, tmp, &txn->mutation_log, link) {
		list_del(&entry->link);
		pkm_lcs_transaction_log_entry_destroy(entry);
	}
	txn->mutation_log_entries = 0;
}

static long pkm_lcs_transaction_dup_path_components(
	const char * const *src, u32 count, char ***out)
{
	char **copy;
	u32 i;

	if (!out || !count || !src)
		return -EINVAL;
	*out = NULL;

	copy = kcalloc(count, sizeof(*copy), GFP_KERNEL);
	if (!copy)
		return -ENOMEM;

	for (i = 0; i < count; i++) {
		size_t len;

		if (!src[i])
			goto out_inval;
		len = strnlen(src[i], U16_MAX + 1UL);
		if (!pkm_lcs_transaction_name_len_valid(len))
			goto out_inval;
		copy[i] = kstrndup(src[i], len, GFP_KERNEL);
		if (!copy[i])
			goto out_nomem;
	}

	*out = copy;
	return 0;

out_nomem:
	for (i = 0; i < count; i++)
		kfree(copy[i]);
	kfree(copy);
	return -ENOMEM;
out_inval:
	for (i = 0; i < count; i++)
		kfree(copy[i]);
	kfree(copy);
	return -EINVAL;
}

static long pkm_lcs_transaction_key_create_log_alloc(
	const struct pkm_lcs_transaction_key_create_log_input *input,
	struct pkm_lcs_transaction_log_entry **out)
{
	struct pkm_lcs_transaction_log_entry *entry;
	size_t guid_bytes;
	long ret;

	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!input || !input->parent_guid || !input->target_guid ||
	    !input->child_name || !input->layer || !input->parent_path ||
	    !input->parent_ancestor_guids || !input->parent_depth ||
	    !input->sequence ||
	    !pkm_lcs_transaction_name_len_valid(input->child_name_len) ||
	    !pkm_lcs_transaction_name_len_valid(input->layer_len))
		return -EINVAL;
	if (input->parent_depth > PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT)
		return -EINVAL;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->link);
	entry->kind = PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY;
	memcpy(entry->create_key.parent_guid, input->parent_guid,
	       sizeof(entry->create_key.parent_guid));
	memcpy(entry->create_key.target_guid, input->target_guid,
	       sizeof(entry->create_key.target_guid));
	entry->create_key.sequence = input->sequence;
	entry->create_key.parent_depth = input->parent_depth;
	entry->create_key.child_name_len = (u32)input->child_name_len;
	entry->create_key.layer_len = (u32)input->layer_len;

	entry->create_key.child_name =
		kmemdup_nul(input->child_name, input->child_name_len,
			    GFP_KERNEL);
	if (!entry->create_key.child_name) {
		ret = -ENOMEM;
		goto out_free;
	}
	entry->create_key.layer =
		kmemdup_nul(input->layer, input->layer_len, GFP_KERNEL);
	if (!entry->create_key.layer) {
		ret = -ENOMEM;
		goto out_free;
	}

	ret = pkm_lcs_transaction_dup_path_components(
		input->parent_path, input->parent_depth,
		&entry->create_key.parent_path);
	if (ret)
		goto out_free;

	if (check_mul_overflow((size_t)input->parent_depth,
			       sizeof(*entry->create_key.parent_ancestor_guids),
			       &guid_bytes)) {
		ret = -EINVAL;
		goto out_free;
	}
	entry->create_key.parent_ancestor_guids =
		kmemdup(input->parent_ancestor_guids, guid_bytes, GFP_KERNEL);
	if (!entry->create_key.parent_ancestor_guids) {
		ret = -ENOMEM;
		goto out_free;
	}

	if (memcmp(entry->create_key.parent_ancestor_guids[input->parent_depth - 1],
		   entry->create_key.parent_guid,
		   sizeof(entry->create_key.parent_guid))) {
		ret = -EINVAL;
		goto out_free;
	}

	*out = entry;
	return 0;

out_free:
	pkm_lcs_transaction_log_entry_destroy(entry);
	return ret;
}

static void pkm_lcs_transaction_fd_timeout(struct timer_list *timer)
{
	struct pkm_lcs_transaction_fd *txn =
		container_of(timer, struct pkm_lcs_transaction_fd,
			     timeout_timer);
	bool schedule_cleanup = false;
	bool terminal = false;

	spin_lock(&txn->lock);
	if (txn->state == REG_TXN_ACTIVE_BOUND) {
		if (!txn->commit_in_flight) {
			txn->timeout_abort_pending = true;
			schedule_cleanup = true;
		}
		txn->state = REG_TXN_TIMED_OUT;
		terminal = true;
	} else if (txn->state == REG_TXN_ACTIVE_UNBOUND) {
		txn->state = REG_TXN_TIMED_OUT;
		terminal = true;
	}
	spin_unlock(&txn->lock);

	if (terminal)
		wake_up_all(&txn->wait);
	if (schedule_cleanup)
		schedule_work(&txn->timeout_work);
}

static void pkm_lcs_transaction_fd_timeout_work(struct work_struct *work)
{
	struct pkm_lcs_transaction_fd *txn =
		container_of(work, struct pkm_lcs_transaction_fd,
			     timeout_work);
	u64 transaction_id = 0;
	u32 source_id = 0;
	u32 count = 0;
	bool cleanup = false;

	mutex_lock(&txn->bind_lock);
	spin_lock(&txn->lock);
	if (txn->state == REG_TXN_TIMED_OUT && txn->timeout_abort_pending) {
		transaction_id = txn->transaction_id;
		source_id = txn->bound_source_id;
		txn->timeout_abort_pending = false;
		cleanup = transaction_id && source_id;
	}
	spin_unlock(&txn->lock);

	if (cleanup) {
		(void)pkm_lcs_source_dispatch_abort_transaction_request(
			source_id, transaction_id, NULL);
		(void)pkm_lcs_source_bound_transaction_release(source_id,
							       &count);
		pkm_lcs_transaction_log_clear(txn);
	}
	mutex_unlock(&txn->bind_lock);
}

static int pkm_lcs_transaction_fd_release(struct inode *inode,
					  struct file *file)
{
	struct pkm_lcs_transaction_fd *txn = file->private_data;
	u64 transaction_id = 0;
	u32 source_id = 0;
	u32 count = 0;
	bool dispatch_abort = false;
	bool release_counter = false;
	bool wake = false;

	file->private_data = NULL;
	if (!txn)
		return 0;

	pkm_lcs_transaction_fd_registry_remove(txn);
	timer_delete_sync(&txn->timeout_timer);
	cancel_work_sync(&txn->timeout_work);

	spin_lock(&txn->lock);
	if (txn->state == REG_TXN_ACTIVE_BOUND) {
		transaction_id = txn->transaction_id;
		source_id = txn->bound_source_id;
		txn->state = REG_TXN_ABORTED;
		dispatch_abort = transaction_id && source_id;
		release_counter = source_id != 0;
		wake = true;
	} else if (txn->state == REG_TXN_ACTIVE_UNBOUND) {
		txn->state = REG_TXN_ABORTED;
		wake = true;
	} else if (txn->state == REG_TXN_TIMED_OUT &&
		   txn->timeout_abort_pending) {
		transaction_id = txn->transaction_id;
		source_id = txn->bound_source_id;
		txn->timeout_abort_pending = false;
		dispatch_abort = transaction_id && source_id;
		release_counter = source_id != 0;
	}
	spin_unlock(&txn->lock);

	if (dispatch_abort)
		(void)pkm_lcs_source_dispatch_abort_transaction_request(
			source_id, transaction_id, NULL);
	if (release_counter)
		(void)pkm_lcs_source_bound_transaction_release(source_id,
							       &count);
	if (wake)
		wake_up_all(&txn->wait);
	pkm_lcs_transaction_log_clear(txn);
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
	u64 transaction_id;
	u32 source_id;
	u32 state;
	long ret;
	u32 count;

	if (!txn)
		return -EINVAL;

	mutex_lock(&txn->bind_lock);

	spin_lock(&txn->lock);
	state = txn->state;
	transaction_id = txn->transaction_id;
	source_id = txn->bound_source_id;
	spin_unlock(&txn->lock);

	switch (state) {
	case REG_TXN_ACTIVE_UNBOUND:
	case REG_TXN_COMMITTED:
	case REG_TXN_ABORTED:
		ret = -EINVAL;
		goto out_unlock;
	case REG_TXN_TIMED_OUT:
		ret = -ETIMEDOUT;
		goto out_unlock;
	case REG_TXN_SOURCE_DOWN:
		ret = -EIO;
		goto out_unlock;
	case REG_TXN_ACTIVE_BOUND:
		if (!transaction_id || !source_id) {
			ret = -EIO;
			goto out_unlock;
		}
		break;
	default:
		ret = -EIO;
		goto out_unlock;
	}

	spin_lock(&txn->lock);
	if (txn->state == REG_TXN_ACTIVE_BOUND &&
	    txn->transaction_id == transaction_id &&
	    txn->bound_source_id == source_id) {
		txn->commit_in_flight = true;
		ret = 0;
	} else if (txn->state == REG_TXN_TIMED_OUT) {
		ret = -ETIMEDOUT;
	} else if (txn->state == REG_TXN_SOURCE_DOWN) {
		ret = -EIO;
	} else {
		ret = -EINVAL;
	}
	spin_unlock(&txn->lock);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_source_commit_transaction_round_trip(
		source_id, transaction_id, NULL, NULL);
	if (ret) {
		spin_lock(&txn->lock);
		txn->commit_in_flight = false;
		spin_unlock(&txn->lock);
		goto out_unlock;
	}

	spin_lock(&txn->lock);
	txn->commit_in_flight = false;
	if (txn->state == REG_TXN_ACTIVE_BOUND &&
	    txn->transaction_id == transaction_id &&
	    txn->bound_source_id == source_id) {
		txn->state = REG_TXN_COMMITTED;
		ret = 0;
	} else if (txn->state == REG_TXN_TIMED_OUT) {
		ret = -ETIMEDOUT;
	} else if (txn->state == REG_TXN_SOURCE_DOWN) {
		ret = -EIO;
	} else {
		ret = -EINVAL;
	}
	spin_unlock(&txn->lock);
	if (ret)
		goto out_unlock;

	timer_delete_sync(&txn->timeout_timer);
	pkm_lcs_transaction_log_clear(txn);
	/*
	 * The source has already committed durably. Counter-release failure is
	 * an internal bookkeeping inconsistency, not a reason to report commit
	 * failure to the caller.
	 */
	(void)pkm_lcs_source_bound_transaction_release(source_id, &count);
	wake_up_all(&txn->wait);

out_unlock:
	mutex_unlock(&txn->bind_lock);
	return ret;
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
	txn->next_operation_index = 1;
	txn->mutation_log_capacity =
		PKM_LCS_TRANSACTION_MUTATION_LOG_CAPACITY_DEFAULT;
	spin_lock_init(&txn->lock);
	mutex_init(&txn->bind_lock);
	init_waitqueue_head(&txn->wait);
	INIT_LIST_HEAD(&txn->registry_link);
	INIT_LIST_HEAD(&txn->mutation_log);
	timer_setup(&txn->timeout_timer, pkm_lcs_transaction_fd_timeout, 0);
	INIT_WORK(&txn->timeout_work, pkm_lcs_transaction_fd_timeout_work);
	pkm_lcs_transaction_fd_registry_add(txn);

	fd = anon_inode_getfd("lcs-transaction", &pkm_lcs_transaction_fd_fops,
			      txn, O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto out_unregister;
	}

	mod_timer(&txn->timeout_timer,
		  pkm_lcs_transaction_deadline_from_timeout_ms(timeout_ms));
	return fd;

out_unregister:
	pkm_lcs_transaction_fd_registry_remove(txn);
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

static void pkm_lcs_transaction_mutation_handle_release(
	struct pkm_lcs_transaction_mutation_handle *handle)
{
	if (!handle || !handle->active)
		return;

	mutex_unlock(&handle->txn->bind_lock);
	fdput(handle->held);
	memset(handle, 0, sizeof(*handle));
}

static long pkm_lcs_transaction_log_capacity_check(
	const struct pkm_lcs_transaction_fd *txn)
{
	if (!txn || !txn->mutation_log_capacity)
		return -EINVAL;
	if (txn->mutation_log_entries >= txn->mutation_log_capacity)
		return -ENOMEM;
	if (!txn->next_operation_index ||
	    txn->next_operation_index == U64_MAX)
		return -EOVERFLOW;
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

long pkm_lcs_transaction_fd_log_snapshot(
	int fd, struct pkm_lcs_transaction_mutation_log_snapshot *out)
{
	struct pkm_lcs_transaction_log_entry *entry;
	struct pkm_lcs_transaction_log_entry *last = NULL;
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	if (!out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	mutex_lock(&txn->bind_lock);
	out->next_operation_index = txn->next_operation_index;
	out->entry_count = txn->mutation_log_entries;
	out->capacity = txn->mutation_log_capacity;
	list_for_each_entry(entry, &txn->mutation_log, link)
		last = entry;

	if (last) {
		out->last_operation_index = last->operation_index;
		out->last_kind = last->kind;
		switch (last->kind) {
		case PKM_LCS_TRANSACTION_LOG_KIND_CREATE_KEY:
			out->last_sequence = last->create_key.sequence;
			out->last_parent_depth = last->create_key.parent_depth;
			strscpy(out->last_child_name,
				last->create_key.child_name,
				sizeof(out->last_child_name));
			strscpy(out->last_layer, last->create_key.layer,
				sizeof(out->last_layer));
			break;
		default:
			ret = -EIO;
			goto out_unlock;
		}
	}

	ret = 0;

out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	if (ret)
		memset(out, 0, sizeof(*out));
	return ret;
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

long pkm_lcs_transaction_fd_mark_source_down(u32 source_id, u32 *marked_out)
{
	struct pkm_lcs_transaction_fd *txn;
	u32 marked = 0;

	if (marked_out)
		*marked_out = 0;
	if (!source_id)
		return -EINVAL;

	mutex_lock(&pkm_lcs_transaction_registry_lock);
	list_for_each_entry(txn, &pkm_lcs_transaction_registry, registry_link) {
		bool stop_timer = false;
		bool wake = false;

		mutex_lock(&txn->bind_lock);
		spin_lock(&txn->lock);
		if (txn->state == REG_TXN_ACTIVE_BOUND &&
		    txn->bound_source_id == source_id) {
			txn->state = REG_TXN_SOURCE_DOWN;
			txn->commit_in_flight = false;
			txn->timeout_abort_pending = false;
			stop_timer = true;
			wake = true;
			marked++;
		}
		spin_unlock(&txn->lock);

		if (stop_timer) {
			timer_delete_sync(&txn->timeout_timer);
			pkm_lcs_transaction_log_clear(txn);
		}
		mutex_unlock(&txn->bind_lock);

		if (wake)
			wake_up_all(&txn->wait);
	}
	mutex_unlock(&pkm_lcs_transaction_registry_lock);

	if (marked_out)
		*marked_out = marked;
	return 0;
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

long pkm_lcs_transaction_fd_begin_key_create_mutation(
	int fd, u32 source_id,
	const u8 root_guid[PKM_LCS_TRANSACTION_HIVE_ROOT_GUID_BYTES],
	const struct pkm_lcs_transaction_key_create_log_input *input,
	struct pkm_lcs_transaction_mutation_handle *handle,
	struct pkm_lcs_transaction_binding_plan *binding)
{
	struct pkm_lcs_transaction_binding_plan plan = { };
	struct pkm_lcs_transaction_log_entry *entry = NULL;
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	u32 count = 0;
	long ret;

	if (!handle || !binding)
		return -EINVAL;
	memset(handle, 0, sizeof(*handle));
	memset(binding, 0, sizeof(*binding));
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

	ret = pkm_lcs_transaction_log_capacity_check(txn);
	if (ret)
		goto out_unlock;

	ret = pkm_lcs_transaction_key_create_log_alloc(input, &entry);
	if (ret)
		goto out_unlock;

	if (plan.action == PKM_LCS_TRANSACTION_BIND_NEW) {
		ret = pkm_lcs_source_bound_transaction_acquire(source_id,
							       &count);
		if (ret)
			goto out_free_entry;

		ret = pkm_lcs_source_begin_transaction_round_trip(
			source_id, plan.transaction_id, RSI_TXN_READ_WRITE,
			NULL, NULL);
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
		memcpy(plan.bound_root_guid, root_guid,
		       sizeof(plan.bound_root_guid));
	}

	handle->held = held;
	handle->txn = txn;
	handle->entry = entry;
	handle->active = true;
	*binding = plan;
	return 0;

out_release_counter:
	(void)pkm_lcs_source_bound_transaction_release(source_id, &count);
out_free_entry:
	pkm_lcs_transaction_log_entry_destroy(entry);
out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	return ret;
}

long pkm_lcs_transaction_fd_commit_mutation(
	struct pkm_lcs_transaction_mutation_handle *handle)
{
	struct pkm_lcs_transaction_log_entry *entry;
	struct pkm_lcs_transaction_fd *txn;
	long ret;

	if (!handle || !handle->active || !handle->txn || !handle->entry)
		return -EINVAL;

	txn = handle->txn;
	entry = handle->entry;
	ret = pkm_lcs_transaction_log_capacity_check(txn);
	if (ret)
		return -EIO;

	entry->operation_index = txn->next_operation_index++;
	list_add_tail(&entry->link, &txn->mutation_log);
	txn->mutation_log_entries++;
	handle->entry = NULL;
	pkm_lcs_transaction_mutation_handle_release(handle);
	return 0;
}

void pkm_lcs_transaction_fd_cancel_mutation(
	struct pkm_lcs_transaction_mutation_handle *handle)
{
	if (!handle || !handle->active)
		return;

	pkm_lcs_transaction_log_entry_destroy(handle->entry);
	handle->entry = NULL;
	pkm_lcs_transaction_mutation_handle_release(handle);
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

long pkm_lcs_kunit_transaction_fd_set_log_capacity(int fd, u32 capacity)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	mutex_lock(&txn->bind_lock);
	if (!capacity || capacity < txn->mutation_log_entries) {
		ret = -EINVAL;
		goto out_unlock;
	}
	txn->mutation_log_capacity = capacity;
	ret = 0;

out_unlock:
	mutex_unlock(&txn->bind_lock);
	fdput(held);
	return ret;
}

long pkm_lcs_kunit_transaction_fd_set_commit_in_flight(int fd,
						       bool in_flight)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	spin_lock(&txn->lock);
	txn->commit_in_flight = in_flight;
	spin_unlock(&txn->lock);

	fdput(held);
	return 0;
}

long pkm_lcs_kunit_transaction_fd_flush_timeout_work(int fd)
{
	struct pkm_lcs_transaction_fd *txn;
	struct fd held;
	long ret;

	ret = pkm_lcs_transaction_fd_get(fd, &held, &txn);
	if (ret)
		return ret;

	flush_work(&txn->timeout_work);
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
