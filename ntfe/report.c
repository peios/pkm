// SPDX-License-Identifier: GPL-2.0-only
/*
 * REPORT emission (machinery slice, ratified PEI-598).
 *
 * A REPORT(Level) whose level clears CurrentReportingLevel becomes one
 * KMES event: origin class NTFE, event type `network-report`, msgpack
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
#include "ntfe.h"

#define NTFE_REPORT_MAX_PAYLOAD	512
#define NTFE_REPORT_EVENT_TYPE	"network-report"

struct ntfe_mp {
	u8 *buf;
	size_t len;
	size_t cap;
	bool overflow;
	u16 entries;
};

static void mp_put(struct ntfe_mp *m, const void *bytes, size_t n)
{
	if (m->overflow || m->len + n > m->cap) {
		m->overflow = true;
		return;
	}
	memcpy(m->buf + m->len, bytes, n);
	m->len += n;
}

static void mp_byte(struct ntfe_mp *m, u8 b)
{
	mp_put(m, &b, 1);
}

/* The bytes mp_str's header takes for a string of n bytes. */
static size_t mp_str_header(size_t n)
{
	return n < 32 ? 1 : n < 256 ? 2 : 3;
}

static void mp_str(struct ntfe_mp *m, const char *s, size_t n)
{
	if (n < 32) {
		mp_byte(m, 0xa0 | (u8)n);
	} else if (n < 256) {
		mp_byte(m, 0xd9);
		mp_byte(m, (u8)n);
	} else {
		__be16 be;

		/* No more fits in the payload than str16 can say. */
		n = min_t(size_t, n, U16_MAX);
		be = cpu_to_be16((u16)n);
		mp_byte(m, 0xda);
		mp_put(m, &be, 2);
	}
	mp_put(m, s, n);
}

static void mp_cstr(struct ntfe_mp *m, const char *s)
{
	mp_str(m, s, strlen(s));
}

static void mp_uint(struct ntfe_mp *m, u64 v)
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

static void mp_key_str(struct ntfe_mp *m, const char *key, const char *s,
		       size_t n)
{
	mp_cstr(m, key);
	mp_str(m, s, n);
	m->entries++;
}

static void mp_key_cstr(struct ntfe_mp *m, const char *key, const char *s)
{
	mp_key_str(m, key, s, strlen(s));
}

static void mp_key_uint(struct ntfe_mp *m, const char *key, u64 v)
{
	mp_cstr(m, key);
	mp_uint(m, v);
	m->entries++;
}

static const char *ntfe_layer_name(u8 layer)
{
	switch (layer) {
	case PEIOS_NTFE_LAYER_RAWPACKET:
		return "RawPacket";
	case PEIOS_NTFE_LAYER_FLOW:
		return "Flow";
	default:
		return "Packet";
	}
}

static const char *ntfe_seat_name(u8 seat)
{
	switch (seat) {
	case PEIOS_NTFE_SEAT_INGRESS:
		return "ingress";
	case PEIOS_NTFE_SEAT_EGRESS:
		return "egress";
	case PEIOS_NTFE_SEAT_LOCAL_IN:
		return "local-in";
	case PEIOS_NTFE_SEAT_LOCAL_OUT:
		return "local-out";
	default:
		return "unknown";
	}
}

static const char *ntfe_verdict_name(u8 verdict)
{
	switch (verdict) {
	case PEIOS_NTFE_VERDICT_PASS:
		return "PASS";
	case PEIOS_NTFE_VERDICT_REJECT:
		return "REJECT";
	default:
		return "DROP";
	}
}

static const char *ntfe_flow_state_name(u8 state)
{
	switch (state) {
	case PEIOS_NTFE_FLOW_NEW:
		return "new";
	case PEIOS_NTFE_FLOW_ESTABLISHED:
		return "established";
	case PEIOS_NTFE_FLOW_RELATED:
		return "related";
	case PEIOS_NTFE_FLOW_INVALID:
		return "invalid";
	case PEIOS_NTFE_FLOW_UNTRACKED:
		return "untracked";
	default:
		return "";
	}
}

static void ntfe_addr_text(u8 family, const u8 addr[16], char *out,
			  size_t out_len)
{
	if (family == 4)
		snprintf(out, out_len, "%pI4", addr);
	else if (family == 6)
		snprintf(out, out_len, "%pI6c", addr);
	else
		out[0] = '\0';
}

void peios_ntfe_report_emit(const struct peios_ntfe_snapshot *snap,
			   const char *rule, size_t rule_len, u8 level,
			   u8 layer, u8 verdict, u8 reject_kind)
{
	u8 payload[NTFE_REPORT_MAX_PAYLOAD];
	struct ntfe_mp m = { .buf = payload, .cap = sizeof(payload) };
	char addr[INET6_ADDRSTRLEN];
	size_t room, n = rule_len;
	bool truncated = false;
	__be16 count;

	/* map16 header, count patched at the end. */
	mp_byte(&m, 0xde);
	mp_put(&m, "\0\0", 2);

	mp_key_uint(&m, "level", level);
	mp_key_cstr(&m, "layer", ntfe_layer_name(layer));
	mp_key_cstr(&m, "seat", ntfe_seat_name(snap->seat));
	mp_key_cstr(&m, "verdict", ntfe_verdict_name(verdict));
	if (verdict == PEIOS_NTFE_VERDICT_REJECT)
		mp_key_cstr(&m, "reject_kind",
			    reject_kind == PEIOS_NTFE_REJECT_PROHIBITED ?
				    "Prohibited" : "Refused");
	mp_key_cstr(&m, "direction",
		    snap->direction == PEIOS_NTFE_DIR_OUT ? "out" : "in");
	mp_key_cstr(&m, "interface", snap->ifname);
	mp_key_uint(&m, "ifindex", snap->ifindex > 0 ? snap->ifindex : 0);
	mp_key_uint(&m, "ether_type", snap->ether_type);
	mp_key_uint(&m, "family", snap->addr_family);
	if (snap->addr_family) {
		mp_key_uint(&m, "protocol", snap->protocol);
		ntfe_addr_text(snap->addr_family, snap->src_addr, addr,
			      sizeof(addr));
		mp_key_cstr(&m, "src", addr);
		ntfe_addr_text(snap->addr_family, snap->dst_addr, addr,
			      sizeof(addr));
		mp_key_cstr(&m, "dst", addr);
	}
	if (snap->has & PEIOS_NTFE_HAS_PORTS) {
		mp_key_uint(&m, "src_port", snap->src_port);
		mp_key_uint(&m, "dst_port", snap->dst_port);
	}
	if (snap->flow_state != PEIOS_NTFE_FLOW_ABSENT)
		mp_key_cstr(&m, "flow_state",
			    ntfe_flow_state_name(snap->flow_state));
	mp_key_uint(&m, "length", snap->length);
	mp_key_uint(&m, "generation", ntfe_rust_generation());
	mp_key_uint(&m, "t_ns", ktime_get_real_ns());

	/*
	 * The rule last: it is the one key of unbounded length (a path down
	 * a tree of key names). The hash of the whole path always goes in,
	 * so a reader can resolve a path the payload could not hold; a path
	 * that does not fit is cut at a character boundary and the cut is
	 * said (PEI-1310: the whole event was once dropped, silently).
	 */
	mp_key_uint(&m, "rule_hash", peios_ntfe_path_hash(rule, rule_len));
	room = m.overflow ? 0 : m.cap - m.len;
	if (sizeof("rule") + mp_str_header(n) + n > room) {
		/* "rule" (5) and a str16 header (3), "rule_truncated" (15)
		 * and its value (1).
		 */
		n = room > 5 + 3 + 16 ? room - (5 + 3 + 16) : 0;
		while (n && ((u8)rule[n] & 0xc0) == 0x80)
			n--;
		truncated = true;
	}
	mp_key_str(&m, "rule", rule, n);
	if (truncated)
		mp_key_uint(&m, "rule_truncated", 1);

	if (m.overflow)
		return;	/* cannot happen at these sizes; never emit a lie */
	count = cpu_to_be16(m.entries);
	memcpy(payload + 1, &count, 2);

	pkm_kmes_emit_kernel(KMES_ORIGIN_NTFE, NTFE_REPORT_EVENT_TYPE,
			     sizeof(NTFE_REPORT_EVENT_TYPE) - 1, payload, m.len);
	atomic64_inc(&peios_ntfe_stats.reports_emitted);
}
