// SPDX-License-Identifier: GPL-2.0-only
/*
 * PNP — Peios Network Policy: engine bring-up and hook registration.
 *
 * Registers the ratified standing seats:
 *  - LOCAL_IN at filter priority for IPv4 and IPv6 (the inbound proper
 *    seat: after conntrack, after defrag, routing decided; Packet then
 *    Flow);
 *  - LOCAL_OUT at filter priority for IPv4 and IPv6 (the outbound Flow
 *    seat: after conntrack classified the new flow);
 *  - per-device ingress and egress hooks (the device seats), attached to
 *    every net device from birth via a netdevice notifier — loopback
 *    included: localhost is policed like everything else.
 *
 * init_net only for now: Peios has no container/netns story yet, and
 * minting per-netns policy semantics before that story exists would be
 * design by accident. Revisit with the netns work.
 *
 * FORWARD is deliberately absent until the router era.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/net_namespace.h>
#include <net/netfilter/nf_conntrack.h>

#include "pnp.h"

static const struct nf_hook_ops peios_pnp_inet_hooks[] = {
	{
		.hook = peios_pnp_hook_local_in,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER,
	},
	{
		.hook = peios_pnp_hook_local_in,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_FILTER,
	},
	/* The outbound Flow seat (rung 2): after conntrack classified the
	 * new flow, before anything confirmed it.
	 */
	{
		.hook = peios_pnp_hook_local_out,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FILTER,
	},
	{
		.hook = peios_pnp_hook_local_out,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP6_PRI_FILTER,
	},
};

/* Per-device seat registration, tracked for unregister on device removal. */
struct peios_pnp_dev_hooks {
	struct list_head list;
	int ifindex;
	struct nf_hook_ops ops[2];	/* ingress, egress */
};

static LIST_HEAD(peios_pnp_devs);
static DEFINE_SPINLOCK(peios_pnp_devs_lock);

static int peios_pnp_attach_device(struct net_device *dev)
{
	struct peios_pnp_dev_hooks *hooks;
	int ret;

	hooks = kzalloc(sizeof(*hooks), GFP_KERNEL);
	if (!hooks)
		return -ENOMEM;

	hooks->ifindex = dev->ifindex;
	hooks->ops[0] = (struct nf_hook_ops){
		.hook = peios_pnp_hook_ingress,
		.pf = NFPROTO_NETDEV,
		.hooknum = NF_NETDEV_INGRESS,
		.priority = 0,
		.dev = dev,
	};
	hooks->ops[1] = (struct nf_hook_ops){
		.hook = peios_pnp_hook_egress,
		.pf = NFPROTO_NETDEV,
		.hooknum = NF_NETDEV_EGRESS,
		.priority = 0,
		.dev = dev,
	};

	ret = nf_register_net_hooks(dev_net(dev), hooks->ops,
				    ARRAY_SIZE(hooks->ops));
	if (ret) {
		kfree(hooks);
		return ret;
	}

	spin_lock(&peios_pnp_devs_lock);
	list_add(&hooks->list, &peios_pnp_devs);
	spin_unlock(&peios_pnp_devs_lock);
	return 0;
}

static void peios_pnp_detach_device(struct net_device *dev)
{
	struct peios_pnp_dev_hooks *hooks, *found = NULL;

	spin_lock(&peios_pnp_devs_lock);
	list_for_each_entry(hooks, &peios_pnp_devs, list) {
		if (hooks->ifindex == dev->ifindex) {
			found = hooks;
			list_del(&found->list);
			break;
		}
	}
	spin_unlock(&peios_pnp_devs_lock);

	if (found) {
		nf_unregister_net_hooks(dev_net(dev), found->ops,
					ARRAY_SIZE(found->ops));
		kfree(found);
	}
}

static int peios_pnp_netdev_event(struct notifier_block *nb,
				  unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	int ret;

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_REGISTER:
		ret = peios_pnp_attach_device(dev);
		if (ret)
			pr_warn("pnp: could not attach device seats to %s: %d\n",
				dev->name, ret);
		break;
	case NETDEV_UNREGISTER:
		peios_pnp_detach_device(dev);
		break;
	default:
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block peios_pnp_netdev_nb = {
	.notifier_call = peios_pnp_netdev_event,
};

static int __init peios_pnp_init(void)
{
	int ret;

	/* Prove the staged pnp-core compiled and linked. */
	if (pnp_rust_kunit_probe() == 0) {
		pr_err("pnp: pnp-core compile probe failed\n");
		return -EINVAL;
	}

	/*
	 * Conntrack hooks are demand-activated: historically it was a
	 * ct-using iptables/nft rule that pinned them. Those frontends are
	 * gone (the clean slate), and PNP is the conntrack consumer now —
	 * without this, nf_ct_get() is NULL on every packet, FlowState
	 * reads untracked, and the ESTABLISHED cornerstone rule never
	 * matches (found live: DNS replies reached the tap and died at
	 * LOCAL_IN while every stateless rule worked).
	 */
	ret = nf_ct_netns_get(&init_net, NFPROTO_INET);
	if (ret) {
		pr_err("pnp: could not pin conntrack: %d\n", ret);
		return ret;
	}
	/* Per-flow packet and byte accounting for the flows dump: PNP is
	 * conntrack's consumer, so it turns the knob the old frontends
	 * left to the administrator.
	 */
	init_net.ct.sysctl_acct = 1;

	/* The verdict event stream and /dev/peios-pnp. */
	ret = peios_pnp_events_init();
	if (ret) {
		nf_ct_netns_put(&init_net, NFPROTO_INET);
		return ret;
	}

	ret = nf_register_net_hooks(&init_net, peios_pnp_inet_hooks,
				    ARRAY_SIZE(peios_pnp_inet_hooks));
	if (ret) {
		pr_err("pnp: could not register IP seats: %d\n", ret);
		nf_ct_netns_put(&init_net, NFPROTO_INET);
		return ret;
	}

	/* register_netdevice_notifier replays NETDEV_REGISTER for every
	 * existing device, so boot-time interfaces get their seats too.
	 */
	ret = register_netdevice_notifier(&peios_pnp_netdev_nb);
	if (ret) {
		nf_unregister_net_hooks(&init_net, peios_pnp_inet_hooks,
					ARRAY_SIZE(peios_pnp_inet_hooks));
		nf_ct_netns_put(&init_net, NFPROTO_INET);
		pr_err("pnp: could not register device notifier: %d\n", ret);
		return ret;
	}

	/* The loud gen-0 confession (ratified): the seats stand, nothing
	 * is enforced until the first policy generation ingests.
	 */
	pr_info("pnp: seats registered; generation %llu%s\n",
		pnp_rust_generation(),
		pnp_rust_generation() == 0 ?
			" — no policy loaded, not enforcing" : "");
	return 0;
}

late_initcall(peios_pnp_init);
