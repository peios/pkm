// SPDX-License-Identifier: GPL-2.0-only
/*
 * The standing seats and the dispatch law (ratified, PEI-598):
 *
 *   RawPacket matches all traffic at the device seats, unconditionally.
 *   The Packet layer judges every traversal exactly once, at its proper
 *   seat — inbound IP at the IP hook (flow facts attached, defrag done),
 *   everything outbound at egress (frame complete, flow facts still
 *   aboard) — falling back to the ingress seat iff the traversal will
 *   never reach its proper seat (non-IP ethertypes; bridge-enslaved
 *   ports, whose frames never cross the IP hooks).
 *
 * Generation 0 is permissive by ratified decision: until the first policy
 * generation ingests from the registry, every seat evaluates nothing and
 * accepts, and says so loudly (main.c logs it; the verdict stream will
 * carry it). The evaluator engages when the LCS ingestion path lands.
 */

#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>

#include "pnp.h"

struct peios_pnp_stats peios_pnp_stats;

bool peios_pnp_traversal_reaches_ip_seat(__be16 protocol,
					 const struct net_device *dev)
{
	if (protocol != htons(ETH_P_IP) && protocol != htons(ETH_P_IPV6))
		return false;
	/* Bridge-forwarded frames are switched at L2 and never enter the
	 * IP stack on this device: the ingress seat is their only seat.
	 * (A copy delivered to the bridge device itself is a separate
	 * traversal on that device and is judged there.)
	 */
	if (dev && netif_is_bridge_port(dev))
		return false;
	return true;
}

/*
 * Judge one traversal at one seat. Generation 0: build the snapshot (the
 * builder is exercised from first boot; refusals are counted), evaluate
 * nothing, accept.
 */
static unsigned int judge(const struct sk_buff *skb,
			  const struct net_device *dev, u8 seat, u8 direction)
{
	struct peios_pnp_snapshot snap;

	if (peios_pnp_snapshot_from_skb(skb, dev, seat, direction, &snap))
		atomic64_inc(&peios_pnp_stats.parse_errors);
	return NF_ACCEPT;
}

unsigned int peios_pnp_hook_ingress(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	atomic64_inc(&peios_pnp_stats.seen_ingress);

	/* RawPacket layer: judges everything here, unconditionally. */
	judge(skb, state->in, PEIOS_PNP_SEAT_INGRESS, PEIOS_PNP_DIR_IN);

	/* Packet layer: proper seat if reachable, else fallback here. */
	if (peios_pnp_traversal_reaches_ip_seat(skb->protocol, state->in)) {
		atomic64_inc(&peios_pnp_stats.deferred);
		return NF_ACCEPT;
	}
	atomic64_inc(&peios_pnp_stats.fallback_judged);
	return judge(skb, state->in, PEIOS_PNP_SEAT_INGRESS,
		     PEIOS_PNP_DIR_IN);
}

unsigned int peios_pnp_hook_egress(void *priv, struct sk_buff *skb,
				   const struct nf_hook_state *state)
{
	atomic64_inc(&peios_pnp_stats.seen_egress);

	/* Both layers' outbound seat: RawPacket and the Packet layer's
	 * proper outbound judgment happen here (frame complete, flow facts
	 * still riding the skb).
	 */
	return judge(skb, state->out, PEIOS_PNP_SEAT_EGRESS,
		     PEIOS_PNP_DIR_OUT);
}

unsigned int peios_pnp_hook_local_in(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
	atomic64_inc(&peios_pnp_stats.seen_local_in);
	return judge(skb, state->in, PEIOS_PNP_SEAT_LOCAL_IN,
		     PEIOS_PNP_DIR_IN);
}
