// SPDX-License-Identifier: GPL-2.0-only

//! PNP kernel bridge: the C ABI between net/pnp's hooks and the staged
//! `pnp-core` semantic crate.
//!
//! Three surfaces:
//! - the policy **builder** (process context): C feeds registry-shaped
//!   rules in, `build_forest` validates, the finished forest crosses the
//!   ABI as an opaque pointer that C publishes under RCU;
//! - **evaluation** (softirq context): C hands a fact snapshot and a
//!   forest pointer, gets a verdict + effect counts back. All allocation
//!   is GFP_ATOMIC (see pnp-core's pkm_alloc); allocation failure returns
//!   -ENOMEM and the glue fails closed;
//! - the **generation** counter: advanced by C at publication; 0 means
//!   nothing ever ingested (loudly permissive, ratified).
//!
//! The `#[repr(C)]` structs mirror `net/pnp/pnp.h` field for field — keep
//! them in lockstep.

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::pnp_core::eval::{evaluate, Effect, EvalContext};
use crate::pnp_core::ingest::{build_forest, RuleInput};
use crate::pnp_core::pkm_alloc::{String as PkmString, Vec as PkmVec};
use crate::pnp_core::rule::{Forest, Layer};
use crate::pnp_core::snapshot::{Direction, FlowState, Snapshot, TimeFacts};
use crate::pnp_core::strutil::str_to_pkm;
use crate::pnp_core::value::RegValue;
use crate::pnp_core::Verdict;

const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;
const ENOENT: c_int = 2;

/// Current policy generation. 0 until the first publication.
static PNP_GENERATION: AtomicU64 = AtomicU64::new(0);

#[no_mangle]
/// Proves the staged `pnp-core` tree is linked and callable; returns its
/// known constant (`MAX_PROMPT_CHAIN`).
pub extern "C" fn pnp_rust_kunit_probe() -> usize {
    crate::pnp_core::kernel_compile_probe()
}

#[no_mangle]
/// The current policy generation (0 = permissive, nothing ever ingested).
pub extern "C" fn pnp_rust_generation() -> u64 {
    PNP_GENERATION.load(Ordering::Acquire)
}

#[no_mangle]
/// Advances the generation at publication time; returns the new value.
pub extern "C" fn pnp_rust_generation_advance() -> u64 {
    PNP_GENERATION.fetch_add(1, Ordering::AcqRel) + 1
}

// --- validity bits: keep in lockstep with PEIOS_PNP_HAS_* in pnp.h ---
const HAS_ETHER_TYPE: u32 = 1 << 0;
const HAS_MACS: u32 = 1 << 1;
const HAS_VLAN: u32 = 1 << 2;
const HAS_TTL: u32 = 1 << 3;
const HAS_DSCP: u32 = 1 << 4;
const HAS_FRAGMENT: u32 = 1 << 5;
const HAS_PORTS: u32 = 1 << 6;
const HAS_TCP_FLAGS: u32 = 1 << 7;
const HAS_ICMP: u32 = 1 << 8;
const HAS_TIME: u32 = 1 << 9;

/// Mirror of `struct peios_pnp_snapshot` (pnp.h). Field-for-field.
#[repr(C)]
pub struct PnpSnapshotC {
    seat: u8,
    direction: u8,
    addr_family: u8,
    flow_state: u8,
    has: u32,
    ifindex: c_int,
    ifname: [c_char; 16],
    ether_type: u16,
    vlan: u16,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    protocol: u8,
    ttl: u8,
    dscp: u8,
    fragment: u8,
    tcp_flags: u8,
    icmp_type: u8,
    icmp_code: u8,
    src_port: u16,
    dst_port: u16,
    length: u32,
    t_year: i64,
    t_month: u8,
    t_day_of_month: u8,
    t_day_of_week: u8,
    t_hour: u8,
    t_minute: u8,
    t_second: u8,
}

/// Mirror of `struct peios_pnp_outcome` (pnp.h). Field-for-field.
#[repr(C)]
pub struct PnpOutcomeC {
    /// 0 = PASS, 1 = REJECT, 2 = DROP (strictness order).
    verdict: u8,
    /// 1 when the backstop answered.
    backstop: u8,
    n_tags: u32,
    n_counts: u32,
    n_reports: u32,
    n_prompts: u32,
    /// Winning rule's attribution path, NUL-terminated, truncated.
    attributed: [c_char; 96],
}

fn c_str_slice(buf: &[c_char]) -> &str {
    let bytes: &[u8] =
        unsafe { core::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len()) };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).unwrap_or("")
}

fn snapshot_from_c(c: &PnpSnapshotC) -> Result<Snapshot, ()> {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let mut snap = Snapshot::default();
    snap.direction = Some(if c.direction == 1 {
        Direction::Out
    } else {
        Direction::In
    });
    snap.interface = Some(str_to_pkm(c_str_slice(&c.ifname)).map_err(|_| ())?);
    if c.has & HAS_ETHER_TYPE != 0 {
        snap.ether_type = Some(c.ether_type);
    }
    if c.has & HAS_VLAN != 0 {
        snap.vlan = Some(c.vlan);
    }
    if c.has & HAS_MACS != 0 {
        snap.src_mac = Some(c.src_mac);
        snap.dst_mac = Some(c.dst_mac);
    }
    match c.addr_family {
        4 => {
            let s: [u8; 4] = c.src_addr[..4].try_into().map_err(|_| ())?;
            let d: [u8; 4] = c.dst_addr[..4].try_into().map_err(|_| ())?;
            snap.src_addr = Some(IpAddr::V4(Ipv4Addr::from(s)));
            snap.dst_addr = Some(IpAddr::V4(Ipv4Addr::from(d)));
            snap.protocol = Some(c.protocol);
        }
        6 => {
            snap.src_addr = Some(IpAddr::V6(Ipv6Addr::from(c.src_addr)));
            snap.dst_addr = Some(IpAddr::V6(Ipv6Addr::from(c.dst_addr)));
            snap.protocol = Some(c.protocol);
        }
        _ => {}
    }
    if c.has & HAS_TTL != 0 {
        snap.ttl = Some(c.ttl);
    }
    if c.has & HAS_DSCP != 0 {
        snap.dscp = Some(c.dscp);
    }
    if c.has & HAS_FRAGMENT != 0 {
        snap.fragment = Some(c.fragment != 0);
    }
    if c.has & HAS_PORTS != 0 {
        snap.src_port = Some(c.src_port);
        snap.dst_port = Some(c.dst_port);
    }
    if c.has & HAS_TCP_FLAGS != 0 {
        snap.tcp_flags = Some(c.tcp_flags);
    }
    if c.has & HAS_ICMP != 0 {
        snap.icmp_type = Some(c.icmp_type);
        snap.icmp_code = Some(c.icmp_code);
    }
    snap.length = Some(c.length);
    snap.flow_state = match c.flow_state {
        1 => Some(FlowState::New),
        2 => Some(FlowState::Established),
        3 => Some(FlowState::Related),
        4 => Some(FlowState::Invalid),
        5 => Some(FlowState::Untracked),
        _ => None,
    };
    if c.has & HAS_TIME != 0 {
        snap.time = Some(TimeFacts {
            year: c.t_year,
            month: c.t_month as i64,
            day_of_month: c.t_day_of_month as i64,
            day_of_week: c.t_day_of_week as i64,
            hour: c.t_hour as i64,
            minute: c.t_minute as i64,
            second: c.t_second as i64,
        });
    }
    // Flow tags and counter cells are machinery facts; their stores are not
    // wired yet, so those facts are absent (the absent-fact law keeps rules
    // over them safely unmatched until the machinery lands).
    Ok(snap)
}

// --- the policy builder -------------------------------------------------

/// Builder state: a stack of open rules plus finished roots. C drives it
/// with begin/value/end calls mirroring the registry walk.
struct Builder {
    roots: PkmVec<RuleInput>,
    stack: PkmVec<RuleInput>,
    /// An open list value: (key, elements). None when no list is open.
    pending_list: Option<(PkmString, PkmVec<RegValue>)>,
}

unsafe fn str_arg<'a>(ptr: *const c_char, len: usize) -> Result<&'a str, c_int> {
    if ptr.is_null() {
        return Err(-EINVAL);
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), len) };
    core::str::from_utf8(bytes).map_err(|_| -EINVAL)
}

fn builder_mut<'a>(b: *mut c_void) -> Result<&'a mut Builder, c_int> {
    if b.is_null() {
        return Err(-EINVAL);
    }
    Ok(unsafe { &mut *b.cast::<Builder>() })
}

#[no_mangle]
/// Creates a policy builder. Returns NULL on allocation failure.
pub extern "C" fn pnp_rust_builder_new() -> *mut c_void {
    let builder = Builder {
        roots: PkmVec::new(),
        stack: PkmVec::new(),
        pending_list: None,
    };
    match kernel::alloc::KBox::new(builder, kernel::alloc::flags::GFP_KERNEL) {
        Ok(b) => kernel::alloc::KBox::into_raw(b).cast(),
        Err(_) => core::ptr::null_mut(),
    }
}

#[no_mangle]
/// Frees an unfinished builder.
pub extern "C" fn pnp_rust_builder_free(b: *mut c_void) {
    if !b.is_null() {
        drop(unsafe { kernel::alloc::KBox::from_raw(b.cast::<Builder>()) });
    }
}

#[no_mangle]
/// Opens a rule (a registry key). Nested calls create exceptions.
pub extern "C" fn pnp_rust_builder_rule_begin(
    b: *mut c_void,
    name: *const c_char,
    name_len: usize,
) -> c_int {
    let builder = match builder_mut(b) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let name = match unsafe { str_arg(name, name_len) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Ok(name) = str_to_pkm(name) else {
        return -ENOMEM;
    };
    let rule = RuleInput {
        name,
        values: PkmVec::new(),
        children: PkmVec::new(),
    };
    if builder.stack.push(rule).is_err() {
        return -ENOMEM;
    }
    0
}

#[no_mangle]
/// Closes the innermost open rule, attaching it to its parent (or the
/// forest roots).
pub extern "C" fn pnp_rust_builder_rule_end(b: *mut c_void) -> c_int {
    let builder = match builder_mut(b) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if builder.pending_list.is_some() {
        return -EINVAL;
    }
    let Some(rule) = builder.stack.pop() else {
        return -EINVAL;
    };
    let dest = match builder.stack.iter_mut().last() {
        Some(parent) => &mut parent.children,
        None => &mut builder.roots,
    };
    if dest.push(rule).is_err() {
        return -ENOMEM;
    }
    0
}

fn add_value(builder: &mut Builder, key: &str, value: RegValue) -> c_int {
    let Some(rule) = builder.stack.iter_mut().last() else {
        return -EINVAL;
    };
    let Ok(key) = str_to_pkm(key) else {
        return -ENOMEM;
    };
    if rule.values.push((key, value)).is_err() {
        return -ENOMEM;
    }
    0
}

#[no_mangle]
/// Adds an integer value to the open rule.
pub extern "C" fn pnp_rust_builder_value_int(
    b: *mut c_void,
    key: *const c_char,
    key_len: usize,
    value: i64,
) -> c_int {
    let builder = match builder_mut(b) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let key = match unsafe { str_arg(key, key_len) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    add_value(builder, key, RegValue::Int(value))
}

#[no_mangle]
/// Adds a string value to the open rule.
pub extern "C" fn pnp_rust_builder_value_str(
    b: *mut c_void,
    key: *const c_char,
    key_len: usize,
    value: *const c_char,
    value_len: usize,
) -> c_int {
    let builder = match builder_mut(b) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let key = match unsafe { str_arg(key, key_len) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    let value = match unsafe { str_arg(value, value_len) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Ok(value) = str_to_pkm(value) else {
        return -ENOMEM;
    };
    add_value(builder, key, RegValue::Str(value))
}

#[no_mangle]
/// Opens a list value on the open rule.
pub extern "C" fn pnp_rust_builder_value_list_begin(
    b: *mut c_void,
    key: *const c_char,
    key_len: usize,
) -> c_int {
    let builder = match builder_mut(b) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if builder.pending_list.is_some() || builder.stack.is_empty() {
        return -EINVAL;
    }
    let key = match unsafe { str_arg(key, key_len) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Ok(key) = str_to_pkm(key) else {
        return -ENOMEM;
    };
    builder.pending_list = Some((key, PkmVec::new()));
    0
}

#[no_mangle]
/// Appends a string element to the open list.
pub extern "C" fn pnp_rust_builder_list_str(
    b: *mut c_void,
    value: *const c_char,
    value_len: usize,
) -> c_int {
    let builder = match builder_mut(b) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let value = match unsafe { str_arg(value, value_len) } {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some((_, items)) = builder.pending_list.as_mut() else {
        return -EINVAL;
    };
    let Ok(value) = str_to_pkm(value) else {
        return -ENOMEM;
    };
    if items.push(RegValue::Str(value)).is_err() {
        return -ENOMEM;
    }
    0
}

#[no_mangle]
/// Appends an integer element to the open list.
pub extern "C" fn pnp_rust_builder_list_int(b: *mut c_void, value: i64) -> c_int {
    let builder = match builder_mut(b) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some((_, items)) = builder.pending_list.as_mut() else {
        return -EINVAL;
    };
    if items.push(RegValue::Int(value)).is_err() {
        return -ENOMEM;
    }
    0
}

#[no_mangle]
/// Closes the open list, attaching it to the open rule.
pub extern "C" fn pnp_rust_builder_value_list_end(b: *mut c_void) -> c_int {
    let builder = match builder_mut(b) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some((key, items)) = builder.pending_list.take() else {
        return -EINVAL;
    };
    let Some(rule) = builder.stack.iter_mut().last() else {
        return -EINVAL;
    };
    if rule.values.push((key, RegValue::List(items))).is_err() {
        return -ENOMEM;
    }
    0
}

#[no_mangle]
/// Validates and builds the forest, consuming the builder. layer: 0 =
/// Packet, 1 = RawPacket. On success writes the opaque forest pointer to
/// `out` and returns 0; on validation failure returns -EINVAL (the old
/// policy generation stays — atomic transitions).
pub extern "C" fn pnp_rust_builder_build(
    b: *mut c_void,
    layer: u8,
    out: *mut *mut c_void,
) -> c_int {
    if b.is_null() || out.is_null() {
        return -EINVAL;
    }
    let builder = unsafe { kernel::alloc::KBox::from_raw(b.cast::<Builder>()) };
    if !builder.stack.is_empty() || builder.pending_list.is_some() {
        return -EINVAL;
    }
    let layer = match layer {
        0 => Layer::Packet,
        1 => Layer::RawPacket,
        _ => return -EINVAL,
    };
    match build_forest(layer, builder.roots.as_slice()) {
        Ok(output) => {
            // In-kernel ingestion drops lints: the authoring surface
            // (pnpd) runs the same lint userspace-side, loudly.
            match kernel::alloc::KBox::new(output.forest, kernel::alloc::flags::GFP_KERNEL) {
                Ok(f) => {
                    unsafe { *out = kernel::alloc::KBox::into_raw(f).cast() };
                    0
                }
                Err(_) => -ENOMEM,
            }
        }
        Err(crate::pnp_core::BuildError::Alloc) => -ENOMEM,
        Err(_) => -EINVAL,
    }
}

#[no_mangle]
/// Frees a forest that is no longer published (called from RCU teardown).
pub extern "C" fn pnp_rust_forest_free(f: *mut c_void) {
    if !f.is_null() {
        drop(unsafe { kernel::alloc::KBox::from_raw(f.cast::<Forest>()) });
    }
}

// --- evaluation ---------------------------------------------------------

#[no_mangle]
/// Judges one snapshot against one forest. Returns 0 with `out` filled,
/// -EINVAL on bad arguments, -ENOMEM when atomic allocation failed
/// mid-evaluation (the caller fails closed), -ENOENT for a null forest.
pub extern "C" fn pnp_rust_evaluate(
    f: *const c_void,
    snap: *const PnpSnapshotC,
    out: *mut PnpOutcomeC,
) -> c_int {
    if snap.is_null() || out.is_null() {
        return -EINVAL;
    }
    if f.is_null() {
        return -ENOENT;
    }
    let forest = unsafe { &*f.cast::<Forest>() };
    let snap_c = unsafe { &*snap };
    let Ok(snapshot) = snapshot_from_c(snap_c) else {
        return -ENOMEM;
    };
    let ctx = EvalContext { reporting_level: 0 };
    let evaluation = match evaluate(forest, &snapshot, &ctx) {
        Ok(e) => e,
        Err(_) => return -ENOMEM,
    };

    let out = unsafe { &mut *out };
    out.verdict = match evaluation.verdict {
        Verdict::Pass => 0,
        Verdict::Reject => 1,
        Verdict::Drop => 2,
    };
    out.backstop = evaluation.backstop as u8;
    out.n_tags = 0;
    out.n_counts = 0;
    out.n_reports = 0;
    out.n_prompts = 0;
    for effect in evaluation.effects.iter() {
        match effect {
            Effect::Tag { .. } => out.n_tags += 1,
            Effect::Count { .. } => out.n_counts += 1,
            Effect::Report { .. } => out.n_reports += 1,
            Effect::PromptIssued { .. } => out.n_prompts += 1,
        }
    }
    let path = evaluation.attributed_to.as_bytes();
    let n = path.len().min(out.attributed.len() - 1);
    for (i, &byte) in path[..n].iter().enumerate() {
        out.attributed[i] = byte as c_char;
    }
    out.attributed[n] = 0;
    0
}
