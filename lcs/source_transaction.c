// SPDX-License-Identifier: GPL-2.0-only
/* RSI lifetime control is out of band: it consumes no request queue slots.
 * Lock order: source table -> source queue -> lifetime registry. No lifetime
 * registry holder enters the source table or a transaction-fd lock.
 */
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <pkm/lcs.h>
#include "source_internal.h"
#include "source_transaction.h"

#define LCS_CLEANUP_LEASE_NS (5ULL * NSEC_PER_SEC)
struct lcs_transaction_owner {
	struct list_head link;
	u64 id;
	u64 session;
	u64 lifetime;
	u64 lease;
	bool terminal;
};
static LIST_HEAD(lcs_transaction_owners);
static DEFINE_MUTEX(lcs_transaction_owners_lock);

static struct lcs_transaction_owner *owner_find(u64 id)
{
	struct lcs_transaction_owner *owner;
	list_for_each_entry(owner, &lcs_transaction_owners, link)
		if (owner->id == id)
			return owner;
	return NULL;
}

long pkm_lcs_source_transaction_own(u64 id, u32 lifetime_ms)
{
	struct lcs_transaction_owner *owner;
	if (!id)
		return -EINVAL;
	owner = kzalloc(sizeof(*owner), GFP_KERNEL);
	if (!owner)
		return -ENOMEM;
	owner->id = id;
	if (lifetime_ms)
		owner->lifetime = ktime_get_ns() + (u64)lifetime_ms * NSEC_PER_MSEC;
	mutex_lock(&lcs_transaction_owners_lock);
	if (owner_find(id)) {
		mutex_unlock(&lcs_transaction_owners_lock);
		kfree(owner);
		return -EEXIST;
	}
	list_add_tail(&owner->link, &lcs_transaction_owners);
	mutex_unlock(&lcs_transaction_owners_lock);
	return 0;
}

void pkm_lcs_source_transaction_put(u64 id)
{
	struct lcs_transaction_owner *owner;
	mutex_lock(&lcs_transaction_owners_lock);
	owner = owner_find(id);
	if (owner) {
		list_del(&owner->link);
		kfree(owner);
	}
	mutex_unlock(&lcs_transaction_owners_lock);
}

void pkm_lcs_source_transaction_end(u64 id)
{
	struct lcs_transaction_owner *owner;
	mutex_lock(&lcs_transaction_owners_lock);
	owner = owner_find(id);
	if (owner)
		owner->terminal = true;
	mutex_unlock(&lcs_transaction_owners_lock);
}

static bool owner_live(struct lcs_transaction_owner *owner, u64 now)
{
	if ((owner->lifetime && now >= owner->lifetime) ||
	    (owner->lease && now >= owner->lease))
		owner->terminal = true;
	return !owner->terminal;
}

/* A definitive BEGIN failure created no provider transaction. Permit another
 * binding attempt without moving the owner's original lifetime deadline. An
 * uncertain or expired BEGIN must never be recycled this way. */
void pkm_lcs_source_transaction_begin_failed(u64 id, u64 session)
{
	struct lcs_transaction_owner *owner;
	mutex_lock(&lcs_transaction_owners_lock);
	owner = owner_find(id);
	if (owner && owner->session == session && owner_live(owner, ktime_get_ns())) {
		owner->session = 0;
		owner->lease = 0;
	}
	mutex_unlock(&lcs_transaction_owners_lock);
}

long pkm_lcs_source_transaction_bind(u64 id, struct pkm_lcs_source_fd *source)
{
	struct lcs_transaction_owner *owner;
	u64 now = ktime_get_ns();
	long ret = 0;
	mutex_lock(&lcs_transaction_owners_lock);
	owner = owner_find(id);
	if (!owner) {
		/* Legacy source test clients may supply their own transaction IDs. */
		ret = source->lifetime_protocol ? -EINVAL : 0;
	} else if (!owner_live(owner, now)) {
		ret = -ETIMEDOUT;
	} else if (owner->session && source->lifetime_protocol) {
		ret = owner->session == source->session ? -EALREADY : -ESTALE;
	} else {
		owner->session = source->session;
		if (source->lifetime_protocol && !owner->lease) {
			owner->lease = now + LCS_CLEANUP_LEASE_NS;
			if (owner->lifetime)
				owner->lease = min(owner->lease, owner->lifetime);
		}
	}
	mutex_unlock(&lcs_transaction_owners_lock);
	return ret;
}

long pkm_lcs_source_lifetime_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	struct pkm_lcs_source_fd *source = file->private_data;
	struct reg_src_negotiate_args negotiate;
	struct reg_src_request_context_args context;
	struct reg_src_renew_args renew;
	struct pkm_lcs_source_in_flight_request *record;
	struct lcs_transaction_owner *owner;
	void __user *user = (void __user *)arg;
	u64 session, id = 0, now;
	long ret = 0;

	if (!source)
		return -EBADF;
	if (cmd == REG_SRC_NEGOTIATE) {
		if (copy_from_user(&negotiate, user, sizeof(negotiate)))
			return -EFAULT;
		if (negotiate.version != REG_SRC_LIFETIME_VERSION || negotiate.flags || negotiate.session)
			return -EINVAL;
		mutex_lock(&source->queue_lock);
		if (source->closing || source->state != PKM_LCS_SOURCE_FD_UNREGISTERED) {
			ret = -EBUSY;
		} else {
			negotiate.session = source->session;
			if (copy_to_user(user, &negotiate, sizeof(negotiate)))
				ret = -EFAULT;
			else
				source->lifetime_protocol = true;
		}
		mutex_unlock(&source->queue_lock);
		return ret;
	}
	if (cmd == REG_SRC_REQUEST_CONTEXT) {
		if (copy_from_user(&context, user, sizeof(context)))
			return -EFAULT;
		session = context.session;
		context.request_deadline_ns = 0;
		context.lifetime_deadline_ns = 0;
		context.lease_deadline_ns = 0;
	} else if (cmd == REG_SRC_RENEW) {
		if (copy_from_user(&renew, user, sizeof(renew)))
			return -EFAULT;
		session = renew.session;
		id = renew.transaction_id;
	} else {
		return -ENOTTY;
	}
	mutex_lock(&source->queue_lock);
	if (!source->lifetime_protocol || source->closing ||
	    source->state != PKM_LCS_SOURCE_FD_ACTIVE || session != source->session) {
		ret = -ESTALE;
		goto out;
	}
	if (cmd == REG_SRC_REQUEST_CONTEXT) {
		record = pkm_lcs_source_in_flight_find_locked(source, context.request_id);
		if (!record || !record->delivered || record->response_accepted) {
			ret = -ENOENT;
			goto out;
		}
		context.request_deadline_ns = record->deadline_ns;
		id = record->txn_id;
	}
	mutex_lock(&lcs_transaction_owners_lock);
	now = ktime_get_ns();
	owner = owner_find(id);
	if (owner && owner->session == session && owner_live(owner, now)) {
		if (cmd == REG_SRC_RENEW) {
			owner->lease = now + LCS_CLEANUP_LEASE_NS;
			if (owner->lifetime)
				owner->lease = min(owner->lease, owner->lifetime);
			renew.lifetime_deadline_ns = owner->lifetime;
			renew.lease_deadline_ns = owner->lease;
		} else {
			context.lifetime_deadline_ns = owner->lifetime;
			context.lease_deadline_ns = owner->lease;
		}
	} else if (cmd == REG_SRC_RENEW) {
		ret = -ESTALE;
	}
	mutex_unlock(&lcs_transaction_owners_lock);
	if (!ret && cmd == REG_SRC_RENEW && copy_to_user(user, &renew, sizeof(renew)))
		ret = -EFAULT;
	if (!ret && cmd == REG_SRC_REQUEST_CONTEXT && copy_to_user(user, &context, sizeof(context)))
		ret = -EFAULT;
out:
	mutex_unlock(&source->queue_lock);
	return ret;
}
