// SPDX-License-Identifier: GPL-2.0-only
/*
 * REPORT emission (machinery slice, ratified PEI-598).
 *
 * A REPORT(Level) whose level clears CurrentReportingLevel becomes one
 * KMES event: origin class PNP, event type `network-report`, msgpack
 * payload — a string-keyed map carrying the attribution (rule path), the
 * level, where the judgment stood (layer, seat), what it said (verdict,
 * reject kind), the packet's tuple and flow state, the generation, and a
 * timestamp. Built on the stack: the packet path runs in softirq and the
 * KMES kernel emit is preempt-disabled ring writing with no allocation,
 * so nothing here may sleep or allocate.
 *
 * Flood control is by design the author's (the level gate); KMES's own
 * ring accounting is the backstop.
 */

#include <linux/inet.h>
#include <linux/ktime.h>
#include <linux/string.h>

#include <pkm/kmes.h>

#include "../../security/pkm/kmes/kmes.h"
#include "pnp.h"

#define PNP_REPORT_MAX_PAYLOAD	512
#define PNP_REPORT_EVENT_TYPE	"network-report"

struct pnp_mp {
	u8 *buf;
	size_t len;
	size_t cap;
	bool overflow;
	u16 entries;
};

static void mp_put(struct pnp_mp *m, const void *bytes, size_t n)
{
	if (m->overflow || m->len + n > m->cap) {
		m->overflow = true;
		return;
	}
	memcpy(m->buf + m->len, bytes, n);
	m->len += n;
}

static void mp_byte(struct pnp_mp *m, u8 b)
{
	mp_put(m, &b, 1);
}

static void mp_str(struct pnp_mp *m, const char *s, size_t n)
{
	if (n < 32) {
		mp_byte(m, 0xa0 | (u8)n);
	} else if (n < 256) {
		mp_byte(m, 0xd9);
		mp_byte(m, (u8)n);
	} else {
		/* Nothing we emit is this long; truncate rather than lie
		 * about the length.
		 */
		n = 255;
		mp_byte(m, 0xd9);
		mp_byte(m, 0xff);
	}
	mp_put(m, s, n);
}

static void mp_cstr(struct pnp_mp *m, const char *s)
{
	mp_str(m, s, strlen(s));
}

static void mp_uint(struct pnp_mp *m, u64 v)
{
	if (v < 128) {
		mp_byte(m, (u8)v);
	} else if (v <= U8_MAX) {
		mp_byte(m, 0xcc);
		mp_byte(m, (u8)v);
	} else if (v <= U16_MAX) {
		__be16 be = cpu_to_be16((u16)v);

		mp_byte(m, 0xcd);
		mp_put(m, &be, 2);
	} else if (v <= U32_MAX) {
		__be32 be = cpu_to_be32((u32)v);

		mp_byte(m, 0xce);
		mp_put(m, &be, 4);
	} else {
		__be64 be = cpu_to_be64(v);

		mp_byte(m, 0xcf);
		mp_put(m, &be, 8);
	}
}

static void mp_key_str(struct pnp_mp *m, const char *key, const char *s,
		       size_t n)
{
	mp_cstr(m, key);
	mp_str(m, s, n);
	m->entries++;
}

static void mp_key_cstr(struct pnp_mp *m, const char *key, const char *s)
{
	mp_key_str(m, key, s, strlen(s));
}

static void mp_key_uint(struct pnp_mp *m, const char *key, u64 v)
{
	mp_cstr(m, key);
	mp_uint(m, v);
	m->entries++;
}

static const char *pnp_layer_name(u8 layer)
{
	return layer == PEIOS_PNP_LAYER_RAWPACKET ? "RawPacket" : "Packet";
}

static const char *pnp_seat_name(u8 seat)
{
	switch (seat) {
	case PEIOS_PNP_SEAT_INGRESS:
		return "ingress";
	case PEIOS_PNP_SEAT_EGRESS:
		return "egress";
	case PEIOS_PNP_SEAT_LOCAL_IN:
		return "local-in";
	default:
		return "unknown";
	}
}

static const char *pnp_verdict_name(u8 verdict)
{
	switch (verdict) {
	case PEIOS_PNP_VERDICT_PASS:
		return "PASS";
	case PEIOS_PNP_VERDICT_REJECT:
		return "REJECT";
	default:
		return "DROP";
	}
}

static const char *pnp_flow_state_name(u8 state)
{
	switch (state) {
	case PEIOS_PNP_FLOW_NEW:
		return "new";
	case PEIOS_PNP_FLOW_ESTABLISHED:
		return "established";
	case PEIOS_PNP_FLOW_RELATED:
		return "related";
	case PEIOS_PNP_FLOW_INVALID:
		return "invalid";
	case PEIOS_PNP_FLOW_UNTRACKED:
		return "untracked";
	default:
		return "";
	}
}

static void pnp_addr_text(u8 family, const u8 addr[16], char *out,
			  size_t out_len)
{
	if (family == 4)
		snprintf(out, out_len, "%pI4", addr);
	else if (family == 6)
		snprintf(out, out_len, "%pI6c", addr);
	else
		out[0] = '\0';
}

void peios_pnp_report_emit(const struct peios_pnp_snapshot *snap,
			   const char *rule, size_t rule_len, u8 level,
			   u8 layer, u8 verdict, u8 reject_kind)
{
	u8 payload[PNP_REPORT_MAX_PAYLOAD];
	struct pnp_mp m = { .buf = payload, .cap = sizeof(payload) };
	char addr[INET6_ADDRSTRLEN];
	__be16 count;

	/* map16 header, count patched at the end. */
	mp_byte(&m, 0xde);
	mp_put(&m, "\0\0", 2);

	mp_key_str(&m, "rule", rule, rule_len);
	mp_key_uint(&m, "level", level);
	mp_key_cstr(&m, "layer", pnp_layer_name(layer));
	mp_key_cstr(&m, "seat", pnp_seat_name(snap->seat));
	mp_key_cstr(&m, "verdict", pnp_verdict_name(verdict));
	if (verdict == PEIOS_PNP_VERDICT_REJECT)
		mp_key_cstr(&m, "reject_kind",
			    reject_kind == PEIOS_PNP_REJECT_PROHIBITED ?
				    "Prohibited" : "Refused");
	mp_key_cstr(&m, "direction",
		    snap->direction == PEIOS_PNP_DIR_OUT ? "out" : "in");
	mp_key_cstr(&m, "interface", snap->ifname);
	mp_key_uint(&m, "ifindex", snap->ifindex > 0 ? snap->ifindex : 0);
	mp_key_uint(&m, "ether_type", snap->ether_type);
	mp_key_uint(&m, "family", snap->addr_family);
	if (snap->addr_family) {
		mp_key_uint(&m, "protocol", snap->protocol);
		pnp_addr_text(snap->addr_family, snap->src_addr, addr,
			      sizeof(addr));
		mp_key_cstr(&m, "src", addr);
		pnp_addr_text(snap->addr_family, snap->dst_addr, addr,
			      sizeof(addr));
		mp_key_cstr(&m, "dst", addr);
	}
	if (snap->has & PEIOS_PNP_HAS_PORTS) {
		mp_key_uint(&m, "src_port", snap->src_port);
		mp_key_uint(&m, "dst_port", snap->dst_port);
	}
	if (snap->flow_state != PEIOS_PNP_FLOW_ABSENT)
		mp_key_cstr(&m, "flow_state",
			    pnp_flow_state_name(snap->flow_state));
	mp_key_uint(&m, "length", snap->length);
	mp_key_uint(&m, "generation", pnp_rust_generation());
	mp_key_uint(&m, "t_ns", ktime_get_real_ns());

	if (m.overflow)
		return;	/* cannot happen at these sizes; never emit a lie */
	count = cpu_to_be16(m.entries);
	memcpy(payload + 1, &count, 2);

	pkm_kmes_emit_kernel(KMES_ORIGIN_PNP, PNP_REPORT_EVENT_TYPE,
			     sizeof(PNP_REPORT_EVENT_TYPE) - 1, payload, m.len);
	atomic64_inc(&peios_pnp_stats.reports_emitted);
}
