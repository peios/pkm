#!/usr/bin/env python3
"""Generate the kernel's event-type table from the evman catalogue.

The kernel's emission policy (PGSS §6.9, kmes/event_policy.c) needs a
closed, compile-time list of every event type the kernel writes, each
with its tier, so that an essential type folds to "always on" at compile
time and every other type has a bit in the enabled mask. The kernel's own
fragments in pkm/evman/ are that list; this script turns them into:

  kmes/event_types.h   enum ids, type strings, tiers, the default mask
                       and the segment trie the policy walk follows
  kmes/event_types.rs  the same ids, strings and tiers for the Rust
                       emitters, plus the FFI call into the C check

Both files are generated wholesale and must not be edited by hand. When a
fragment gains, loses or re-tiers an event, re-run this script and commit
the result; the build has no other source for the table.

Ids are assigned in sorted order of the type name, so adding a type
renumbers the ones after it. Nothing outside the kernel sees an id -- the
enabled mask is private and the ring carries type strings -- so that is
harmless, and it keeps a re-run after a merge a plain re-run.

Usage:  python3 tools/gen-kmes-event-table.py [--check]

With --check, writes nothing and exits non-zero if either file on disk
differs from what would be generated.
"""
import pathlib
import re
import sys

PKM = pathlib.Path(__file__).resolve().parents[1]
FRAGMENTS = PKM / "evman"
OUT_H = PKM / "kmes" / "event_types.h"
OUT_RS = PKM / "kmes" / "event_types.rs"
TOOL = "tools/gen-kmes-event-table.py"

TIERS = ["essential", "standard", "verbose", "debug"]
# The enabled mask is one u64; past 64 types it has to move behind an RCU
# pointer (see kmes/event_policy.c). The generator refuses rather than
# emit a table the C side cannot hold.
MAX_TYPES = 64
SEGMENT = re.compile(r"[a-z][a-z0-9-]*\Z")


def die(msg):
    print(f"gen-kmes-event-table: {msg}", file=sys.stderr)
    sys.exit(2)


def parse_events():
    """[(name, tier, fragment)] for every event record in pkm/evman/."""
    events = []
    for path in sorted(FRAGMENTS.glob("*.evman")):
        current = None
        in_headers = False
        for n, raw in enumerate(path.read_text().splitlines(), 1):
            if raw.startswith("--- "):
                parts = raw[4:].split()
                current = None
                in_headers = False
                if len(parts) == 2 and parts[0] == "event":
                    current = {"name": parts[1], "tier": None,
                               "fragment": path.name, "line": n}
                    events.append(current)
                    in_headers = True
                continue
            if current is None or not in_headers:
                continue
            if not raw.strip():
                in_headers = False
                continue
            if ":" in raw:
                key, value = raw.split(":", 1)
                if key.strip() == "tier":
                    current["tier"] = value.strip()
    out = []
    seen = {}
    for ev in events:
        where = f"{ev['fragment']}:{ev['line']}"
        name, tier = ev["name"], ev["tier"]
        if name in seen:
            die(f"{where}: event {name} already defined at {seen[name]}")
        seen[name] = where
        if tier not in TIERS:
            die(f"{where}: event {name} has tier {tier!r}, not one of "
                + ", ".join(TIERS))
        segments = name.split(".")
        if len(segments) < 2 or not all(SEGMENT.match(s) for s in segments):
            die(f"{where}: event {name} is not a dotted lower-case type")
        out.append((name, tier, ev["fragment"]))
    out.sort()
    if not out:
        die(f"no event records under {FRAGMENTS}")
    if len(out) > MAX_TYPES:
        die(f"{len(out)} kernel event types; the enabled mask holds "
            f"{MAX_TYPES}. Move it behind an RCU pointer first.")
    return out


def ident(name):
    return name.upper().replace(".", "_").replace("-", "_")


def build_trie(events):
    """Nodes in pre-order, parents before children: [(segment, parent)],
    plus each type's leaf node index."""
    tree = {}
    for name, _, _ in events:
        node = tree
        for seg in name.split("."):
            node = node.setdefault(seg, {})
    nodes = []
    index_of = {}

    def walk(subtree, parent, prefix):
        for seg in sorted(subtree):
            path = prefix + (seg,)
            index_of[path] = len(nodes)
            nodes.append((seg, parent))
            walk(subtree[seg], index_of[path], path)

    walk(tree, -1, ())
    leaves = [index_of[tuple(name.split("."))] for name, _, _ in events]
    return nodes, leaves


def c_header(events, nodes, leaves):
    ids = [ident(name) for name, _, _ in events]
    if len(set(ids)) != len(ids):
        die("two event types map to the same C identifier")
    roots = sorted({name.split(".")[0] for name, _, _ in events})
    default_mask = 0
    for i, (_, tier, _) in enumerate(events):
        if tier in ("essential", "standard"):
            default_mask |= 1 << i
    width = max(len(i) for i in ids)
    lines = []
    w = lines.append
    w("/* SPDX-License-Identifier: GPL-2.0-only */")
    w("/*")
    w(f" * GENERATED by {TOOL} from the fragments in evman/.")
    w(" * Do not edit;")
    w(" * change the fragment and re-run the generator.")
    w(" *")
    w(" * Every event type the kernel writes, with its tier (PGSS §6.8). The")
    w(" * emission policy (event_policy.h) keeps one enabled bit per id.")
    w(" *")
    w(" * How an emitter uses it. The check is the emitter's first statement,")
    w(" * before any payload sizing, building or allocation:")
    w(" *")
    w(" *	if (!pkm_kmes_event_enabled(PKM_KMES_EV_KMES_BUFFER_SWAP_FAILED))")
    w(" *		return 0;")
    w(" *	...")
    w(" *	pkm_kmes_emit_kernel(KMES_ORIGIN_KMES,")
    w(" *			     PKM_KMES_EV_KMES_BUFFER_SWAP_FAILED_TYPE,")
    w(" *			     sizeof(PKM_KMES_EV_KMES_BUFFER_SWAP_FAILED_TYPE) - 1,")
    w(" *			     payload, len);")
    w(" *")
    w(" * The id must be a compile-time constant: for an essential type the")
    w(" * check then folds to true and never reads the policy (§6.9 MUST).")
    w(" * Essential emitters may leave the call out, but calling it uniformly")
    w(" * keeps a later re-tier a one-line fragment change. The policy decides")
    w(" * first and any gating (a SACL, an alarm mask, a REPORT level) second;")
    w(" * the two combine by AND. Rust emitters use event_types.rs, whose")
    w(" * enabled() calls the same check through pkm_kmes_event_enabled_ffi().")
    w(" */")
    w("#ifndef _SECURITY_PKM_KMES_EVENT_TYPES_H")
    w("#define _SECURITY_PKM_KMES_EVENT_TYPES_H")
    w("")
    w("#include <linux/build_bug.h>")
    w("#include <linux/types.h>")
    w("")
    w("enum pkm_kmes_event_tier {")
    for t in TIERS:
        w(f"\tPKM_KMES_EV_TIER_{t.upper()} = {TIERS.index(t)},")
    w("};")
    w("")
    w("enum pkm_kmes_event_id {")
    for i, (name, tier, frag) in enumerate(events):
        w(f"\tPKM_KMES_EV_{ids[i]:<{width}} = {i}, /* {tier}, {frag} */")
    w(f"\tPKM_KMES_EV_COUNT{' ' * (width - 5)} = {len(events)},")
    w("};")
    w("")
    w("static_assert(PKM_KMES_EV_COUNT <= 64,")
    w("\t      \"the enabled mask is one u64; move it behind RCU first\");")
    w("")
    w("/* The type strings, for pkm_kmes_emit_kernel(). */")
    for i, (name, _, _) in enumerate(events):
        w(f"#define PKM_KMES_EV_{ids[i]}_TYPE \"{name}\"")
    w("")
    w("/*")
    w(" * Each type's tier. With a constant id this folds at compile time,")
    w(" * which is what lets pkm_kmes_event_enabled() skip the policy for an")
    w(" * essential type without a load.")
    w(" */")
    w("static __always_inline enum pkm_kmes_event_tier")
    w("pkm_kmes_event_tier(enum pkm_kmes_event_id id)")
    w("{")
    w("\tswitch (id) {")
    for t in TIERS:
        members = [ids[i] for i, (_, tier, _) in enumerate(events) if tier == t]
        if not members:
            continue
        for m in members:
            w(f"\tcase PKM_KMES_EV_{m}:")
        w(f"\t\treturn PKM_KMES_EV_TIER_{t.upper()};")
    w("\tdefault:")
    w("\t\t/* Not a kernel type: never let the policy hide it. */")
    w("\t\treturn PKM_KMES_EV_TIER_ESSENTIAL;")
    w("\t}")
    w("}")
    w("")
    w("/*")
    w(" * The mask in force before the policy has ever been read (§6.9: decide")
    w(" * by tier alone): essential and standard on, verbose and debug off.")
    w(" */")
    w(f"#define PKM_KMES_EV_DEFAULT_MASK 0x{default_mask:016x}ULL")
    w("")
    w(f"#define PKM_KMES_EV_NODE_COUNT {len(nodes)}")
    w(f"#define PKM_KMES_EV_ROOT_COUNT {len(roots)}")
    w("")
    w("#ifdef PKM_KMES_EVENT_TYPES_WANT_TABLES")
    w("/*")
    w(" * The tables the policy walk needs, compiled into event_policy.c alone.")
    w(" *")
    w(" * The nodes are the trie of every type's segments beneath")
    w(" * Machine\\Generic\\Events, in pre-order: a node's parent always comes")
    w(" * before it, and parent -1 is the Events key itself. A type's leaf is")
    w(" * the node its last segment names.")
    w(" */")
    w("struct pkm_kmes_event_node {")
    w("\tconst char *segment;")
    w("\tu8 segment_len;")
    w("\ts16 parent;")
    w("};")
    w("")
    w("static const struct pkm_kmes_event_node")
    w("\tpkm_kmes_event_nodes[PKM_KMES_EV_NODE_COUNT] = {")
    for i, (seg, parent) in enumerate(nodes):
        w(f"\t[{i}] = {{ \"{seg}\", {len(seg)}, {parent} }},")
    w("};")
    w("")
    w("static const u16 pkm_kmes_event_leaf[PKM_KMES_EV_COUNT] = {")
    for i, leaf in enumerate(leaves):
        w(f"\t[PKM_KMES_EV_{ids[i]}] = {leaf},")
    w("};")
    w("")
    w("static const char * const pkm_kmes_event_names[PKM_KMES_EV_COUNT] = {")
    for i, (name, _, _) in enumerate(events):
        w(f"\t[PKM_KMES_EV_{ids[i]}] = PKM_KMES_EV_{ids[i]}_TYPE,")
    w("};")
    w("")
    w("/* The first segments: the only keys under Events the kernel watches. */")
    w("static const char * const")
    w("\tpkm_kmes_event_roots[PKM_KMES_EV_ROOT_COUNT] = {")
    for r in roots:
        w(f"\t\"{r}\",")
    w("};")
    w("#endif /* PKM_KMES_EVENT_TYPES_WANT_TABLES */")
    w("")
    w("#endif /* _SECURITY_PKM_KMES_EVENT_TYPES_H */")
    return "\n".join(lines) + "\n"


def rust_module(events):
    lines = []
    w = lines.append
    w("// SPDX-License-Identifier: GPL-2.0-only")
    w("")
    w(f"//! GENERATED by {TOOL} from the fragments in evman/.")
    w("//! Do not edit;")
    w("//! change the fragment and re-run the generator.")
    w("//!")
    w("//! The kernel's event types for the Rust emitters: the same ids, type")
    w("//! strings and tiers as `event_types.h`. Check `enabled()` before")
    w("//! building a payload; it folds to `true` for an essential type and")
    w("//! otherwise asks the C emission policy through")
    w("//! `pkm_kmes_event_enabled_ffi()`.")
    w("//!")
    w("//! ```ignore")
    w("//! if !kmes_event_types::enabled(&kmes_event_types::KACS_CAAP_SACL_SKIPPED) {")
    w("//!     continue;")
    w("//! }")
    w("//! emit(kmes_event_types::KACS_CAAP_SACL_SKIPPED.name, &payload);")
    w("//! ```")
    w("")
    w("/// An event type's tier (PGSS §6.8).")
    w("#[derive(Clone, Copy, PartialEq, Eq, Debug)]")
    w("#[repr(u8)]")
    w("pub(crate) enum Tier {")
    for t in TIERS:
        w(f"    {t.capitalize()} = {TIERS.index(t)},")
    w("}")
    w("")
    w("/// One kernel event type.")
    w("#[derive(Clone, Copy, Debug)]")
    w("pub(crate) struct EventType {")
    w("    /// The id the C side knows it by (`PKM_KMES_EV_*`).")
    w("    pub(crate) id: u32,")
    w("    /// The type string written to the ring.")
    w("    pub(crate) name: &'static [u8],")
    w("    pub(crate) tier: Tier,")
    w("}")
    w("")
    for i, (name, tier, _) in enumerate(events):
        w(f"pub(crate) const {ident(name)}: EventType = EventType {{")
        w(f"    id: {i},")
        w(f"    name: b\"{name}\",")
        w(f"    tier: Tier::{tier.capitalize()},")
        w("};")
    w("")
    w(f"/// How many kernel event types there are.")
    w(f"pub(crate) const COUNT: u32 = {len(events)};")
    w("")
    w("extern \"C\" {")
    w("    fn pkm_kmes_event_enabled_ffi(id: u32) -> bool;")
    w("}")
    w("")
    w("/// Whether `event` is switched on. An essential type is always on and")
    w("/// never reads the policy; any other asks the kernel's cached policy.")
    w("#[inline]")
    w("pub(crate) fn enabled(event: &EventType) -> bool {")
    w("    if event.tier == Tier::Essential {")
    w("        return true;")
    w("    }")
    w("    // SAFETY: a plain read of the published mask; any id is accepted.")
    w("    unsafe { pkm_kmes_event_enabled_ffi(event.id) }")
    w("}")
    return "\n".join(lines) + "\n"


def main():
    events = parse_events()
    nodes, leaves = build_trie(events)
    if len(nodes) > 32767:
        die("too many trie nodes for an s16 parent index")
    outputs = {
        OUT_H: c_header(events, nodes, leaves),
        OUT_RS: rust_module(events),
    }
    if "--check" in sys.argv[1:]:
        drift = [p for p, text in outputs.items()
                 if not p.exists() or p.read_text() != text]
        for p in drift:
            print(f"out of date: {p.relative_to(PKM)}", file=sys.stderr)
        if drift:
            print(f"regenerate with {TOOL}", file=sys.stderr)
            return 1
        print(f"up to date: {len(events)} kernel event types")
        return 0
    for p, text in outputs.items():
        if not p.exists() or p.read_text() != text:
            p.write_text(text)
            print(f"wrote {p.relative_to(PKM)}")
    print(f"{len(events)} kernel event types, {len(nodes)} trie nodes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
