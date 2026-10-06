// SPDX-License-Identifier: GPL-2.0-only
/*
 * NTFE's own lifecycle in the event stream: ntfe.policy.published when a
 * generation of rules goes into force, ntfe.policy.rejected when a policy
 * walk is refused and the previous generation stays.
 *
 * Both are written in process context — publication runs under a mutex
 * and the walk under another, from the LCS bootstrap or the deferred
 * re-walk on system_wq — and never from the packet path, so nothing here
 * runs in softirq. The payloads are built on the stack like report.c's,
 * as nested maps, one per path segment (PGSS §6.4), laid out as the evman
 * catalogue's ntfe fragment says.
 */

#include <linux/bitops.h>
#include <linux/bits.h>
#include <linux/build_bug.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include <pkm/kmes.h>

#include "../../security/pkm/kmes/kmes.h"
#include "ntfe.h"

/* kacs/ntfe_runtime.rs holds NtfeBuildWhyC to the same size. */
static_assert(sizeof(struct peios_ntfe_build_why) == 320);

/* The published payload at its widest is 134 bytes: three 9-byte uints. */
#define NTFE_PUBLISHED_MAX_PAYLOAD	192
#define NTFE_REJECTED_MAX_PAYLOAD	512

struct ntfe_lc_mp {
	u8 *buf;
	size_t len;
	size_t cap;
	bool overflow;
};

static void lc_put(struct ntfe_lc_mp *m, const void *bytes, size_t n)
{
	if (m->overflow || m->len + n > m->cap) {
		m->overflow = true;
		return;
	}
	memcpy(m->buf + m->len, bytes, n);
	m->len += n;
}

static void lc_byte(struct ntfe_lc_mp *m, u8 b)
{
	lc_put(m, &b, 1);
}

/* Every map and array here has at most 15 entries: one byte. */
static void lc_map(struct ntfe_lc_mp *m, u8 n)
{
	lc_byte(m, 0x80 | n);
}

static void lc_array(struct ntfe_lc_mp *m, u8 n)
{
	lc_byte(m, 0x90 | n);
}

/* Strings here are under 256 bytes: the rule path is held to 256 by its
 * buffer and cut further to fit, and every other string is a name.
 */
static void lc_str(struct ntfe_lc_mp *m, const char *s, size_t n)
{
	if (n < 32) {
		lc_byte(m, 0xa0 | (u8)n);
	} else {
		n = min_t(size_t, n, U8_MAX);
		lc_byte(m, 0xd9);
		lc_byte(m, (u8)n);
	}
	lc_put(m, s, n);
}

static void lc_cstr(struct ntfe_lc_mp *m, const char *s)
{
	lc_str(m, s, strlen(s));
}

static void lc_uint(struct ntfe_lc_mp *m, u64 v)
{
	if (v < 128) {
		lc_byte(m, (u8)v);
	} else if (v <= U8_MAX) {
		lc_byte(m, 0xcc);
		lc_byte(m, (u8)v);
	} else if (v <= U16_MAX) {
		__be16 be = cpu_to_be16((u16)v);

		lc_byte(m, 0xcd);
		lc_put(m, &be, 2);
	} else if (v <= U32_MAX) {
		__be32 be = cpu_to_be32((u32)v);

		lc_byte(m, 0xce);
		lc_put(m, &be, 4);
	} else {
		__be64 be = cpu_to_be64(v);

		lc_byte(m, 0xcf);
		lc_put(m, &be, 8);
	}
}

/* A negative errno: a negative fixint, or int8/16/32. */
static void lc_errno(struct ntfe_lc_mp *m, long v)
{
	if (v >= -32) {
		lc_byte(m, (u8)(s8)v);
	} else if (v >= S8_MIN) {
		lc_byte(m, 0xd0);
		lc_byte(m, (u8)(s8)v);
	} else if (v >= S16_MIN) {
		__be16 be = cpu_to_be16((u16)(s16)v);

		lc_byte(m, 0xd1);
		lc_put(m, &be, 2);
	} else {
		__be32 be = cpu_to_be32((u32)(s32)v);

		lc_byte(m, 0xd2);
		lc_put(m, &be, 4);
	}
}

static void lc_key_uint(struct ntfe_lc_mp *m, const char *key, u64 v)
{
	lc_cstr(m, key);
	lc_uint(m, v);
}

static void lc_key_cstr(struct ntfe_lc_mp *m, const char *key, const char *s)
{
	lc_cstr(m, key);
	lc_cstr(m, s);
}

static const char *ntfe_lc_layer_name(u8 layer)
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

void peios_ntfe_build_why_reset(struct peios_ntfe_build_why *why)
{
	memset(why, 0, sizeof(*why));
	why->layer = PEIOS_NTFE_WHY_NO_LAYER;
}

void peios_ntfe_policy_published_emit(u64 generation, u64 generation_previous,
				      u8 layers, u8 threshold,
				      u8 threshold_previous)
{
	/* The catalogue's order for policy.layers. */
	static const u8 order[] = {
		PEIOS_NTFE_LAYER_RAWPACKET,
		PEIOS_NTFE_LAYER_PACKET,
		PEIOS_NTFE_LAYER_FLOW,
	};
	u8 payload[NTFE_PUBLISHED_MAX_PAYLOAD];
	struct ntfe_lc_mp m = { .buf = payload, .cap = sizeof(payload) };
	unsigned int i;

	lc_map(&m, 1);
	lc_cstr(&m, "policy");
	lc_map(&m, 5);
	lc_key_uint(&m, "generation", generation);
	lc_key_uint(&m, "generation-previous", generation_previous);
	lc_cstr(&m, "layers");
	lc_array(&m, hweight8(layers & (BIT(PEIOS_NTFE_LAYER_COUNT) - 1)));
	for (i = 0; i < ARRAY_SIZE(order); i++)
		if (layers & BIT(order[i]))
			lc_cstr(&m, ntfe_lc_layer_name(order[i]));
	lc_key_uint(&m, "report-threshold", threshold);
	lc_key_uint(&m, "report-threshold-previous", threshold_previous);

	if (m.overflow)
		return;	/* cannot happen at this size; never emit a lie */
	pkm_kmes_emit_kernel(KMES_ORIGIN_NTFE, PEIOS_NTFE_EV_POLICY_PUBLISHED,
			     sizeof(PEIOS_NTFE_EV_POLICY_PUBLISHED) - 1, payload,
			     m.len);
}

int peios_ntfe_policy_rejected_emit(const struct peios_ntfe_build_why *why,
				    long err)
{
	u8 payload[NTFE_REJECTED_MAX_PAYLOAD];
	struct ntfe_lc_mp m = { .buf = payload, .cap = sizeof(payload) };
	size_t rule_len = min_t(size_t, why->rule_len, sizeof(why->rule));
	bool has_rule = rule_len > 0;
	bool has_action = has_rule && why->action_error[0];
	bool has_layer = has_rule && why->layer < PEIOS_NTFE_LAYER_COUNT;
	bool cut = has_rule && why->rule_truncated;
	size_t reason_len = strnlen(why->reason, sizeof(why->reason));
	size_t action_len = strnlen(why->action_error,
				    sizeof(why->action_error));

	lc_map(&m, 2 + (has_rule ? 1 : 0));

	lc_cstr(&m, "policy");
	lc_map(&m, 2);
	lc_key_uint(&m, "generation", ntfe_rust_generation());
	/* NTFE refuses a policy whole: the generation in force stays. */
	lc_cstr(&m, "previous-retained");
	lc_byte(&m, 0xc3);	/* true */

	lc_cstr(&m, "outcome");
	lc_map(&m, err ? 2 : 1);
	if (err) {
		lc_cstr(&m, "errno");
		lc_errno(&m, err < 0 ? err : -err);
	}
	lc_cstr(&m, "reason");
	lc_str(&m, why->reason, reason_len);

	/*
	 * The rule last, and its name last within it, so that a path too
	 * long for what is left is cut at a character boundary and the cut
	 * said, as ntfe.verdict.reported does.
	 */
	if (has_rule) {
		size_t room, rule_map, n = rule_len;

		lc_cstr(&m, "rule");
		rule_map = m.len;
		lc_map(&m, 0);	/* settled once the name's fate is */
		if (has_layer)
			lc_key_cstr(&m, "layer", ntfe_lc_layer_name(why->layer));
		if (has_action) {
			lc_cstr(&m, "action-error");
			lc_str(&m, why->action_error, action_len);
		}
		/* "name" (5), a str8 header (2), "name-truncated" (15) and its
		 * bool (1); a str8 says at most 255 bytes.
		 */
		room = m.overflow ? 0 : m.cap - m.len;
		if (n > U8_MAX || 5 + 2 + n + 16 > room) {
			n = room > 5 + 2 + 16 ? room - (5 + 2 + 16) : 0;
			n = min_t(size_t, n, min_t(size_t, rule_len, U8_MAX));
			while (n && ((u8)why->rule[n] & 0xc0) == 0x80)
				n--;
			cut = true;
		}
		lc_cstr(&m, "name");
		lc_str(&m, why->rule, n);
		if (cut) {
			lc_cstr(&m, "name-truncated");
			lc_byte(&m, 0xc3);	/* true */
		}
		if (!m.overflow)
			payload[rule_map] = 0x80 | (1 + (has_layer ? 1 : 0) +
						    (has_action ? 1 : 0) +
						    (cut ? 1 : 0));
	}

	if (m.overflow)
		return -EOVERFLOW;	/* cannot happen at these sizes */
	pkm_kmes_emit_kernel(KMES_ORIGIN_NTFE, PEIOS_NTFE_EV_POLICY_REJECTED,
			     sizeof(PEIOS_NTFE_EV_POLICY_REJECTED) - 1, payload,
			     m.len);
	return m.len;
}
