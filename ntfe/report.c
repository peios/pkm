// SPDX-License-Identifier: GPL-2.0-only
/*
 * REPORT emission (machinery slice, ratified PEI-598).
 *
 * A REPORT(Level) whose level clears CurrentReportingLevel becomes one
 * KMES event: origin class NTFE, event type `ntfe.verdict.reported`,
 * msgpack payload laid out as the evman catalogue's ntfe fragment says —
 * nested maps, one per path segment: `rule` (the attribution, its level,
 * where the judgment stood), `outcome` (what it said), `network`,
 * `source`, `destination` and `flow` (the packet), and `policy` (the
 * generation). The time rides in the KMES header. Built on the stack:
 * the packet path runs in softirq and the KMES kernel emit is
 * preempt-disabled ring writing with no allocation, so nothing here may
 * sleep or allocate.
 *
 * Flood control is by design the author's (the level gate); KMES's own
 * ring accounting is the backstop.
 */

#include <linux/inet.h>
#include <linux/socket.h>
#include <linux/string.h>

#include <pkm/kmes.h>

#include "../../security/pkm/kmes/kmes.h"
#include "ntfe.h"

#define NTFE_REPORT_MAX_PAYLOAD	512
#define NTFE_REPORT_EVENT_TYPE	"ntfe.verdict.reported"

struct ntfe_mp {
	u8 *buf;
	size_t len;
	size_t cap;
	bool overflow;
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

/* Every map here has at most 7 keys: a fixmap, one byte. */
static void mp_map(struct ntfe_mp *m, u8 n)
{
	mp_byte(m, 0x80 | n);
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
}

static void mp_key_cstr(struct ntfe_mp *m, const char *key, const char *s)
{
	mp_key_str(m, key, s, strlen(s));
}

static void mp_key_uint(struct ntfe_mp *m, const char *key, u64 v)
{
	mp_cstr(m, key);
	mp_uint(m, v);
}

static const char *ntfe_layer_name(u8 layer)
{
	switch (layer) {
	case PEIOS_NTFE_LAYER_RAWPACKET:
		return "raw-packet";
	case PEIOS_NTFE_LAYER_FLOW:
		return "flow";
	default:
		return "packet";
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
		return "pass";
	case PEIOS_NTFE_VERDICT_REJECT:
		return "reject";
	default:
		return "drop";
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
	default:
		return "untracked";
	}
}

/* The snapshot says 4 or 6; network.family is the AF_* number. */
static u8 ntfe_af(u8 family)
{
	return family == 4 ? AF_INET : family == 6 ? AF_INET6 : AF_UNSPEC;
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

/* `source` or `destination`: the address, and the port when it has one. */
static void ntfe_endpoint(struct ntfe_mp *m, const char *key, u8 family,
			  const u8 addr[16], bool has_port, u16 port)
{
	char text[INET6_ADDRSTRLEN];

	ntfe_addr_text(family, addr, text, sizeof(text));
	mp_cstr(m, key);
	mp_map(m, has_port ? 2 : 1);
	mp_key_cstr(m, "address", text);
	if (has_port)
		mp_key_uint(m, "port", port);
}

void peios_ntfe_report_emit(const struct peios_ntfe_snapshot *snap,
			   const char *rule, size_t rule_len, u8 level,
			   u8 layer, u8 verdict, u8 reject_kind)
{
	u8 payload[NTFE_REPORT_MAX_PAYLOAD];
	struct ntfe_mp m = { .buf = payload, .cap = sizeof(payload) };
	/* Addresses and protocol exist only above the raw-packet layer;
	 * ports are parsed only beneath an address family.
	 */
	bool l3 = snap->addr_family != 0;
	bool ports = l3 && (snap->has & PEIOS_NTFE_HAS_PORTS);
	bool tracked = snap->flow_state != PEIOS_NTFE_FLOW_ABSENT;
	bool rejected = verdict == PEIOS_NTFE_VERDICT_REJECT;
	bool named = snap->ifname[0] != '\0';
	size_t room, rule_map, n = rule_len;
	bool truncated = false;

	/* outcome, network, policy and rule always; source and destination
	 * with an address family; flow when tracking applied.
	 */
	mp_map(&m, 4 + (l3 ? 2 : 0) + (tracked ? 1 : 0));

	mp_cstr(&m, "outcome");
	mp_map(&m, rejected ? 2 : 1);
	mp_key_cstr(&m, "verdict", ntfe_verdict_name(verdict));
	if (rejected)
		mp_key_cstr(&m, "reason",
			    reject_kind == PEIOS_NTFE_REJECT_PROHIBITED ?
				    "prohibited" : "refused");

	mp_cstr(&m, "network");
	mp_map(&m, l3 ? 6 : 5);
	mp_key_cstr(&m, "direction",
		    snap->direction == PEIOS_NTFE_DIR_OUT ? "out" : "in");
	/* With no device there is no name to give, and "" is not one; the
	 * index says 0, which the catalogue defines as no interface.
	 */
	mp_cstr(&m, "interface");
	mp_map(&m, named ? 2 : 1);
	if (named)
		mp_key_cstr(&m, "name", snap->ifname);
	mp_key_uint(&m, "index", snap->ifindex > 0 ? snap->ifindex : 0);
	mp_key_uint(&m, "ether-type", snap->ether_type);
	mp_key_uint(&m, "family", ntfe_af(snap->addr_family));
	if (l3)
		mp_key_uint(&m, "protocol", snap->protocol);
	mp_key_uint(&m, "length", snap->length);

	if (l3) {
		ntfe_endpoint(&m, "source", snap->addr_family, snap->src_addr,
			      ports, snap->src_port);
		ntfe_endpoint(&m, "destination", snap->addr_family,
			      snap->dst_addr, ports, snap->dst_port);
	}

	if (tracked) {
		mp_cstr(&m, "flow");
		mp_map(&m, 1);
		mp_key_cstr(&m, "state", ntfe_flow_state_name(snap->flow_state));
	}

	mp_cstr(&m, "policy");
	mp_map(&m, 1);
	mp_key_uint(&m, "generation", ntfe_rust_generation());

	/*
	 * The rule last, and its name last within it: the name is the one
	 * value of unbounded length (a path down a tree of key names). The
	 * hash of the whole path always goes in, so a reader can resolve a
	 * path the payload could not hold; a path that does not fit is cut
	 * at a character boundary and the cut is said (PEI-1310: the whole
	 * event was once dropped, silently). Every other map's size is known
	 * before it is written; this one's one-byte header is settled once
	 * the name's fate is.
	 */
	mp_cstr(&m, "rule");
	rule_map = m.len;
	mp_map(&m, 0);
	mp_key_uint(&m, "hash", peios_ntfe_path_hash(rule, rule_len));
	mp_key_uint(&m, "report-level", level);
	mp_key_cstr(&m, "layer", ntfe_layer_name(layer));
	mp_key_cstr(&m, "seat", ntfe_seat_name(snap->seat));
	room = m.overflow ? 0 : m.cap - m.len;
	if (sizeof("name") + mp_str_header(n) + n > room) {
		/* "name" (5) and a str16 header (3), "name-truncated" (15)
		 * and its bool (1).
		 */
		n = room > 5 + 3 + 16 ? room - (5 + 3 + 16) : 0;
		while (n && ((u8)rule[n] & 0xc0) == 0x80)
			n--;
		truncated = true;
	}
	mp_key_str(&m, "name", rule, n);
	if (truncated) {
		mp_cstr(&m, "name-truncated");
		mp_byte(&m, 0xc3);	/* true */
	}

	if (m.overflow)
		return;	/* cannot happen at these sizes; never emit a lie */
	payload[rule_map] = 0x80 | (truncated ? 6 : 5);

	pkm_kmes_emit_kernel(KMES_ORIGIN_NTFE, NTFE_REPORT_EVENT_TYPE,
			     sizeof(NTFE_REPORT_EVENT_TYPE) - 1, payload, m.len);
	atomic64_inc(&peios_ntfe_stats.reports_emitted);
}
