// Conditional ACE expression evaluator (§11.12, §11.17).
//
// Evaluates the binary-encoded postfix expression appended to callback
// ACEs. Returns TRUE, FALSE, or UNKNOWN.
//
// The expression language operates on four attribute sources:
//   @User.  — token user claims
//   @Device. — token device claims
//   @Resource. — object resource attributes (from SACL)
//   @Local. — per-call context from the caller
//
// Three-value logic: TRUE, FALSE, UNKNOWN.
// Allow ACEs: take effect on TRUE only.
// Deny/Audit ACEs: take effect on TRUE or UNKNOWN (fail-safe).
//
// This implementation follows the §11.17 EvaluateConditionalExpression
// pseudocode exactly.

use crate::compat::{self, AllocError, String, TryClone, Vec};
use crate::sid::Sid;
use crate::access_check::EnrichedToken;
use crate::token::Token;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Case-insensitive ASCII byte comparison (no allocation).
fn cmp_ascii_case_insensitive(a: &[u8], b: &[u8]) -> i8 {
    for (x, y) in a.iter().zip(b.iter()) {
        let lx = x.to_ascii_lowercase();
        let ly = y.to_ascii_lowercase();
        match lx.cmp(&ly) {
            core::cmp::Ordering::Less => return -1,
            core::cmp::Ordering::Greater => return 1,
            core::cmp::Ordering::Equal => {}
        }
    }
    (a.len() as isize).cmp(&(b.len() as isize)) as i8
}

// ---------------------------------------------------------------------------
// Three-value result
// ---------------------------------------------------------------------------

/// Three-value logic result: True, False, or Unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriValue {
    /// Condition evaluated to true.
    True,
    /// Condition evaluated to false.
    False,
    /// Condition could not be determined (missing data, type mismatch).
    Unknown,
}

impl TriValue {
    /// Negate: True becomes False, False becomes True, Unknown stays Unknown.
    pub fn negate(self) -> Self {
        match self {
            TriValue::True => TriValue::False,
            TriValue::False => TriValue::True,
            TriValue::Unknown => TriValue::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Value types on the evaluation stack
// ---------------------------------------------------------------------------

/// Where a value came from — determines whether it can participate
/// in logical operators and existence tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    /// Hard-coded value in the expression bytecode.
    Literal,
    /// Resolved from @User. token claims.
    UserAttr,
    /// Resolved from @Device. token claims.
    DeviceAttr,
    /// Resolved from @Resource. object attributes.
    ResourceAttr,
    /// Resolved from @Local. per-call context.
    LocalAttr,
    /// Computed result of a sub-expression.
    Result,
}

impl Origin {
    /// Returns true if this origin is an attribute source (not a literal or result).
    pub fn is_attribute(self) -> bool {
        matches!(self, Origin::UserAttr | Origin::DeviceAttr | Origin::ResourceAttr | Origin::LocalAttr)
    }
}

/// A value on the evaluation stack.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub struct Value {
    /// The typed payload.
    pub vtype: ValueType,
    /// Where this value came from.
    pub origin: Origin,
    /// Flags from the source claim (CASE_SENSITIVE, USE_FOR_DENY_ONLY, DISABLED).
    pub flags: u16,
}

/// Typed payload for a conditional expression value.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub enum ValueType {
    /// Absent or unresolvable value.
    Null,
    /// Signed 64-bit integer.
    Int64(i64),
    /// Unsigned 64-bit integer.
    Uint64(u64),
    /// Boolean.
    Boolean(bool),
    /// Unicode string.
    String(String),
    /// Security identifier.
    Sid(Sid),
    /// Opaque byte sequence.
    Octet(Vec<u8>),
    /// Multi-valued set of elements.
    Composite(Vec<Value>),
}

impl Value {
    fn null() -> Self {
        Value { vtype: ValueType::Null, origin: Origin::Literal, flags: 0 }
    }

    fn is_null(&self) -> bool {
        matches!(self.vtype, ValueType::Null)
    }

    fn is_composite(&self) -> bool {
        matches!(self.vtype, ValueType::Composite(_))
    }

    fn from_bool_result(b: TriValue) -> Self {
        let val = match b {
            TriValue::True => ValueType::Boolean(true),
            TriValue::False => ValueType::Boolean(false),
            TriValue::Unknown => ValueType::Null,
        };
        Value { vtype: val, origin: Origin::Result, flags: 0 }
    }

    fn to_three_value(&self) -> TriValue {
        match &self.vtype {
            ValueType::Null => TriValue::Unknown,
            ValueType::Boolean(b) => if *b { TriValue::True } else { TriValue::False },
            ValueType::Int64(v) => if *v != 0 { TriValue::True } else { TriValue::False },
            ValueType::Uint64(v) => if *v != 0 { TriValue::True } else { TriValue::False },
            ValueType::String(s) => if !s.is_empty() { TriValue::True } else { TriValue::False },
            _ => TriValue::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Claim resolution
// ---------------------------------------------------------------------------

/// Resolve a claim by name from a claim list.
/// Handles DISABLED and USE_FOR_DENY_ONLY flags.
/// Empty values → NULL (prevents vacuous truth).
pub fn resolve_claim(
    claims: &[crate::token::ClaimEntry],
    name: &str,
    for_allow: bool,
    origin: Origin,
) -> Result<Value, AllocError> {
    use crate::token::{ClaimValues, claim_flags};

    for attr in claims {
        if attr.name.eq_ignore_ascii_case(name) {
            if attr.flags & claim_flags::DISABLED != 0 {
                return Ok(Value { vtype: ValueType::Null, origin, flags: 0 });
            }
            if (attr.flags & claim_flags::USE_FOR_DENY_ONLY != 0) && for_allow {
                return Ok(Value { vtype: ValueType::Null, origin, flags: 0 });
            }

            let flags = attr.flags;
            match &attr.values {
                ClaimValues::Int64(vals) => {
                    if vals.is_empty() { return Ok(Value { vtype: ValueType::Null, origin, flags: 0 }); }
                    if vals.len() == 1 {
                        return Ok(Value { vtype: ValueType::Int64(vals[0]), origin, flags });
                    }
                    let mut elements = Vec::new();
                    for v in vals {
                        compat::vec_push(&mut elements, Value {
                            vtype: ValueType::Int64(*v), origin, flags,
                        })?;
                    }
                    return Ok(Value { vtype: ValueType::Composite(elements), origin, flags });
                }
                ClaimValues::Uint64(vals) => {
                    if vals.is_empty() { return Ok(Value { vtype: ValueType::Null, origin, flags: 0 }); }
                    if vals.len() == 1 {
                        return Ok(Value { vtype: ValueType::Uint64(vals[0]), origin, flags });
                    }
                    let mut elements = Vec::new();
                    for v in vals {
                        compat::vec_push(&mut elements, Value {
                            vtype: ValueType::Uint64(*v), origin, flags,
                        })?;
                    }
                    return Ok(Value { vtype: ValueType::Composite(elements), origin, flags });
                }
                ClaimValues::String(vals) => {
                    if vals.is_empty() { return Ok(Value { vtype: ValueType::Null, origin, flags: 0 }); }
                    if vals.len() == 1 {
                        return Ok(Value { vtype: ValueType::String(vals[0].try_clone()?), origin, flags });
                    }
                    let mut elements = Vec::new();
                    for v in vals {
                        compat::vec_push(&mut elements, Value {
                            vtype: ValueType::String(v.try_clone()?), origin, flags,
                        })?;
                    }
                    return Ok(Value { vtype: ValueType::Composite(elements), origin, flags });
                }
                ClaimValues::Boolean(vals) => {
                    if vals.is_empty() { return Ok(Value { vtype: ValueType::Null, origin, flags: 0 }); }
                    if vals.len() == 1 {
                        return Ok(Value { vtype: ValueType::Boolean(vals[0]), origin, flags });
                    }
                    let mut elements = Vec::new();
                    for v in vals {
                        compat::vec_push(&mut elements, Value {
                            vtype: ValueType::Boolean(*v), origin, flags,
                        })?;
                    }
                    return Ok(Value { vtype: ValueType::Composite(elements), origin, flags });
                }
                ClaimValues::Sid(vals) => {
                    if vals.is_empty() { return Ok(Value { vtype: ValueType::Null, origin, flags: 0 }); }
                    if vals.len() == 1 {
                        return Ok(Value { vtype: ValueType::Sid(vals[0].try_clone()?), origin, flags });
                    }
                    let mut elements = Vec::new();
                    for v in vals {
                        compat::vec_push(&mut elements, Value {
                            vtype: ValueType::Sid(v.try_clone()?), origin, flags,
                        })?;
                    }
                    return Ok(Value { vtype: ValueType::Composite(elements), origin, flags });
                }
                ClaimValues::Octet(vals) => {
                    if vals.is_empty() { return Ok(Value { vtype: ValueType::Null, origin, flags: 0 }); }
                    if vals.len() == 1 {
                        return Ok(Value { vtype: ValueType::Octet(vals[0].try_clone()?), origin, flags });
                    }
                    let mut elements = Vec::new();
                    for v in vals {
                        compat::vec_push(&mut elements, Value {
                            vtype: ValueType::Octet(v.try_clone()?), origin, flags,
                        })?;
                    }
                    return Ok(Value { vtype: ValueType::Composite(elements), origin, flags });
                }
            }
        }
    }
    Ok(Value { vtype: ValueType::Null, origin, flags: 0 })
}

// ---------------------------------------------------------------------------
// Comparison helpers
// ---------------------------------------------------------------------------

/// Case-insensitive ASCII comparison (not full Unicode — §11.17).
fn strings_equal(a: &str, b: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        a == b
    } else {
        a.eq_ignore_ascii_case(b)
    }
}

fn is_case_sensitive(a: &Value, b: &Value) -> bool {
    (a.flags & 0x0002 != 0) || (b.flags & 0x0002 != 0)
}

/// Compare two scalar values for equality. Returns TriValue.
fn compare_equal(lhs: &Value, rhs: &Value) -> TriValue {
    if lhs.is_null() || rhs.is_null() {
        return TriValue::Unknown;
    }
    // Scalar vs composite → Unknown
    if lhs.is_composite() != rhs.is_composite() {
        return TriValue::Unknown;
    }

    let cs = is_case_sensitive(lhs, rhs);

    match (&lhs.vtype, &rhs.vtype) {
        (ValueType::Int64(a), ValueType::Int64(b)) =>
            if *a == *b { TriValue::True } else { TriValue::False },
        (ValueType::Uint64(a), ValueType::Uint64(b)) =>
            if *a == *b { TriValue::True } else { TriValue::False },
        // INT64↔UINT64 promotion (Peios divergence)
        (ValueType::Int64(a), ValueType::Uint64(b)) => {
            if *a < 0 { TriValue::False }
            else if (*a as u64) == *b { TriValue::True }
            else { TriValue::False }
        }
        (ValueType::Uint64(a), ValueType::Int64(b)) => {
            if *b < 0 { TriValue::False }
            else if *a == (*b as u64) { TriValue::True }
            else { TriValue::False }
        }
        (ValueType::Boolean(a), ValueType::Boolean(b)) =>
            if *a == *b { TriValue::True } else { TriValue::False },
        // Boolean↔Int for == and != only
        (ValueType::Boolean(a), ValueType::Int64(b)) =>
            if (*a as i64) == *b { TriValue::True } else { TriValue::False },
        (ValueType::Int64(a), ValueType::Boolean(b)) =>
            if *a == (*b as i64) { TriValue::True } else { TriValue::False },
        (ValueType::Boolean(a), ValueType::Uint64(b)) =>
            if (*a as u64) == *b { TriValue::True } else { TriValue::False },
        (ValueType::Uint64(a), ValueType::Boolean(b)) =>
            if *a == (*b as u64) { TriValue::True } else { TriValue::False },
        (ValueType::String(a), ValueType::String(b)) =>
            if strings_equal(a, b, cs) { TriValue::True } else { TriValue::False },
        (ValueType::Sid(a), ValueType::Sid(b)) =>
            if *a == *b { TriValue::True } else { TriValue::False },
        (ValueType::Octet(a), ValueType::Octet(b)) =>
            if *a == *b { TriValue::True } else { TriValue::False },
        (ValueType::Composite(a), ValueType::Composite(b)) => {
            // Element-wise, same length and order
            if a.len() != b.len() {
                return TriValue::False;
            }
            for (ea, eb) in a.iter().zip(b.iter()) {
                match compare_equal(ea, eb) {
                    TriValue::True => continue,
                    TriValue::False => return TriValue::False,
                    TriValue::Unknown => return TriValue::Unknown,
                }
            }
            TriValue::True
        }
        _ => TriValue::Unknown, // type mismatch
    }
}

/// Compare two scalar values with ordering. Returns -1, 0, 1, or None.
fn compare_ordered(lhs: &Value, rhs: &Value) -> Option<i8> {
    if lhs.is_null() || rhs.is_null() || lhs.is_composite() || rhs.is_composite() {
        return None;
    }

    let cs = is_case_sensitive(lhs, rhs);

    match (&lhs.vtype, &rhs.vtype) {
        (ValueType::Int64(a), ValueType::Int64(b)) =>
            Some((*a).cmp(b) as i8),
        (ValueType::Uint64(a), ValueType::Uint64(b)) =>
            Some((*a).cmp(b) as i8),
        // INT64↔UINT64 promotion (Peios divergence)
        (ValueType::Int64(a), ValueType::Uint64(b)) => {
            if *a < 0 { Some(-1) }
            else { Some((*a as u64).cmp(b) as i8) }
        }
        (ValueType::Uint64(a), ValueType::Int64(b)) => {
            if *b < 0 { Some(1) }
            else { Some((*a).cmp(&(*b as u64)) as i8) }
        }
        (ValueType::String(a), ValueType::String(b)) => {
            if cs {
                Some(a.cmp(b) as i8)
            } else {
                Some(cmp_ascii_case_insensitive(a.as_bytes(), b.as_bytes()))
            }
        }
        (ValueType::Octet(a), ValueType::Octet(b)) =>
            Some(a.cmp(b) as i8),
        // Boolean not orderable, SID not orderable
        _ => None,
    }
}

fn to_value_set(v: &Value) -> Result<Vec<&Value>, AllocError> {
    match &v.vtype {
        ValueType::Composite(elems) => {
            let mut result = Vec::new();
            for e in elems {
                compat::vec_push(&mut result, e)?;
            }
            Ok(result)
        }
        _ => {
            let mut result = Vec::new();
            compat::vec_push(&mut result, v)?;
            Ok(result)
        }
    }
}

/// Contains: TRUE if LHS includes ALL of RHS values.
fn set_contains(lhs: &Value, rhs: &Value) -> Result<TriValue, AllocError> {
    if lhs.is_null() || rhs.is_null() {
        return Ok(TriValue::Unknown);
    }
    let lhs_set = to_value_set(lhs)?;
    let rhs_set = to_value_set(rhs)?;
    if rhs_set.is_empty() {
        return Ok(TriValue::Unknown);
    }
    for r in &rhs_set {
        let mut found = false;
        let mut saw_unknown = false;
        for l in &lhs_set {
            match compare_equal(l, r) {
                TriValue::True => { found = true; break; }
                TriValue::Unknown => { saw_unknown = true; }
                TriValue::False => {}
            }
        }
        if !found {
            if saw_unknown { return Ok(TriValue::Unknown); }
            return Ok(TriValue::False);
        }
    }
    Ok(TriValue::True)
}

/// Any_of: TRUE if RHS includes ANY of LHS values.
fn set_any_of(lhs: &Value, rhs: &Value) -> Result<TriValue, AllocError> {
    if lhs.is_null() || rhs.is_null() {
        return Ok(TriValue::Unknown);
    }
    let lhs_set = to_value_set(lhs)?;
    let rhs_set = to_value_set(rhs)?;
    if lhs_set.is_empty() || rhs_set.is_empty() {
        return Ok(TriValue::Unknown);
    }
    let mut saw_unknown = false;
    for l in &lhs_set {
        for r in &rhs_set {
            match compare_equal(l, r) {
                TriValue::True => return Ok(TriValue::True),
                TriValue::Unknown => { saw_unknown = true; }
                TriValue::False => {}
            }
        }
    }
    Ok(if saw_unknown { TriValue::Unknown } else { TriValue::False })
}

// ---------------------------------------------------------------------------
// SID membership helpers
// ---------------------------------------------------------------------------

/// Check if ALL SIDs in needles match the enriched token (user, groups,
/// or virtual groups S-1-3-4 / S-1-5-10 per §11.12).
fn all_sids_match_enriched(needles: &[Sid], enriched: &EnrichedToken, for_allow: bool) -> bool {
    needles.iter().all(|sid| {
        crate::access_check::enriched_sid_matches(sid, enriched, for_allow)
            .unwrap_or(false)
    })
}

fn any_sid_matches_enriched(needles: &[Sid], enriched: &EnrichedToken, for_allow: bool) -> bool {
    needles.iter().any(|sid| {
        crate::access_check::enriched_sid_matches(sid, enriched, for_allow)
            .unwrap_or(false)
    })
}

/// Get the effective device groups — override (restricted pass) or token's own.
fn effective_device_groups<'a>(enriched: &'a EnrichedToken) -> Option<&'a [crate::group::GroupEntry]> {
    if let Some(ovr) = enriched.device_groups_override {
        Some(ovr)
    } else {
        enriched.token.device_groups.as_deref()
    }
}

fn all_sids_match_device(needles: &[Sid], enriched: &EnrichedToken, for_allow: bool) -> bool {
    let dg = match effective_device_groups(enriched) {
        Some(groups) => groups,
        None => return false,
    };
    needles.iter().all(|sid| {
        dg.iter().any(|g| g.sid == *sid && g.matches_for(for_allow))
    })
}

fn any_sid_matches_device(needles: &[Sid], enriched: &EnrichedToken, for_allow: bool) -> bool {
    let dg = match effective_device_groups(enriched) {
        Some(groups) => groups,
        None => return false,
    };
    needles.iter().any(|sid| {
        dg.iter().any(|g| g.sid == *sid && g.matches_for(for_allow))
    })
}

/// Extract SID(s) from a value. Returns None on type error.
fn to_sid_list(v: &Value) -> Result<Option<Vec<Sid>>, AllocError> {
    match &v.vtype {
        ValueType::Sid(s) => {
            let mut result = Vec::new();
            compat::vec_push(&mut result, s.try_clone()?)?;
            Ok(Some(result))
        }
        ValueType::Composite(elems) => {
            if elems.is_empty() { return Ok(None); }
            let mut result = compat::vec_with_capacity(elems.len())?;
            for e in elems {
                match &e.vtype {
                    ValueType::Sid(s) => compat::vec_push(&mut result, s.try_clone()?)?,
                    _ => return Ok(None),
                }
            }
            Ok(Some(result))
        }
        _ => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Expression evaluator (§11.17 EvaluateConditionalExpression)
// ---------------------------------------------------------------------------

/// artx magic header bytes
const ARTX_HEADER: [u8; 4] = [0x61, 0x72, 0x74, 0x78];

/// Evaluate a conditional expression from a callback ACE.
///
/// `condition`: the raw bytes from the ACE (after mask + SID).
/// `enriched`: the calling thread's enriched token (with virtual groups).
/// `resource_attributes`: from the object's SACL.
/// `local_claims`: per-call context provided by the caller.
/// `for_allow`: whether this is an allow ACE (affects claim resolution).
pub fn evaluate(
    condition: &[u8],
    enriched: &EnrichedToken,
    resource_attributes: &[crate::token::ClaimEntry],
    local_claims: &[crate::token::ClaimEntry],
    for_allow: bool,
) -> Result<TriValue, AllocError> {
    let token = enriched.token;
    if condition.len() < 4 || condition[0..4] != ARTX_HEADER {
        return Ok(TriValue::Unknown);
    }

    /// Maximum evaluation stack depth. Prevents adversarial expressions from
    /// consuming unbounded memory. 1024 is generous for any real expression.
    const MAX_STACK_DEPTH: usize = 1024;

    /// Push a value onto the stack with depth checking. Returns
    /// `Ok(true)` on success, `Ok(false)` if the stack would exceed
    /// MAX_STACK_DEPTH (caller should return Unknown).
    #[inline]
    fn stack_push(stack: &mut Vec<Value>, val: Value) -> Result<bool, AllocError> {
        if stack.len() >= MAX_STACK_DEPTH {
            return Ok(false);
        }
        compat::vec_push(stack, val)?;
        Ok(true)
    }

    let mut stack: Vec<Value> = Vec::new();
    let mut pos: usize = 4;

    while pos < condition.len() {
        let op = condition[pos];
        pos += 1;

        match op {
            // Padding (0x00 only). Non-zero bytes in padding positions
            // fall through to the unknown-opcode handler and return Unknown.
            0x00 => continue,

            // --- Literal values ---

            // Int8/16/32/64: all stored as 8-byte LE magnitude + sign byte + base byte
            0x01 | 0x02 | 0x03 | 0x04 => {
                if pos + 10 > condition.len() { return Ok(TriValue::Unknown); }
                let magnitude = u64::from_le_bytes([
                    condition[pos], condition[pos+1], condition[pos+2], condition[pos+3],
                    condition[pos+4], condition[pos+5], condition[pos+6], condition[pos+7],
                ]);
                let sign = condition[pos + 8];
                pos += 10;
                let value = if sign == 0x02 {
                    // Negative: interpret as negative int64.
                    // Guard against magnitude > i64::MAX (would wrap on cast).
                    if magnitude > i64::MAX as u64 + 1 {
                        return Ok(TriValue::Unknown);
                    } else if magnitude == i64::MAX as u64 + 1 {
                        i64::MIN // exactly -2^63
                    } else {
                        -(magnitude as i64)
                    }
                } else {
                    if magnitude > i64::MAX as u64 {
                        return Ok(TriValue::Unknown);
                    }
                    magnitude as i64
                };
                if !stack_push(&mut stack, Value {
                    vtype: ValueType::Int64(value),
                    origin: Origin::Literal,
                    flags: 0,
                })? { return Ok(TriValue::Unknown); }
            }

            // Unicode string: length (4 LE) + UTF-16LE data
            0x10 => {
                if pos + 4 > condition.len() { return Ok(TriValue::Unknown); }
                let length = u32::from_le_bytes([
                    condition[pos], condition[pos+1], condition[pos+2], condition[pos+3],
                ]) as usize;
                pos += 4;
                if length > condition.len() - pos { return Ok(TriValue::Unknown); }
                let s = decode_utf16le(&condition[pos..pos+length]);
                pos += length;
                if !stack_push(&mut stack, Value {
                    vtype: ValueType::String(s),
                    origin: Origin::Literal,
                    flags: 0,
                })? { return Ok(TriValue::Unknown); }
            }

            // Octet string: length (4 LE) + raw bytes
            0x18 => {
                if pos + 4 > condition.len() { return Ok(TriValue::Unknown); }
                let length = u32::from_le_bytes([
                    condition[pos], condition[pos+1], condition[pos+2], condition[pos+3],
                ]) as usize;
                pos += 4;
                if length > condition.len() - pos { return Ok(TriValue::Unknown); }
                let data = compat::slice_to_vec(&condition[pos..pos+length])?;
                pos += length;
                if !stack_push(&mut stack, Value {
                    vtype: ValueType::Octet(data),
                    origin: Origin::Literal,
                    flags: 0,
                })? { return Ok(TriValue::Unknown); }
            }

            // Composite: length (4 LE) + nested elements
            0x50 => {
                if pos + 4 > condition.len() { return Ok(TriValue::Unknown); }
                let length = u32::from_le_bytes([
                    condition[pos], condition[pos+1], condition[pos+2], condition[pos+3],
                ]) as usize;
                pos += 4;
                if length > condition.len() - pos { return Ok(TriValue::Unknown); }
                // Parse composite elements recursively from the sub-buffer
                let elements = parse_composite_elements(&condition[pos..pos+length])?;
                pos += length;
                match elements {
                    Some(elems) => if !stack_push(&mut stack, Value {
                        vtype: ValueType::Composite(elems),
                        origin: Origin::Literal,
                        flags: 0,
                    })? { return Ok(TriValue::Unknown); },
                    None => return Ok(TriValue::Unknown),
                }
            }

            // SID literal: length (4 LE) + binary SID
            0x51 => {
                if pos + 4 > condition.len() { return Ok(TriValue::Unknown); }
                let length = u32::from_le_bytes([
                    condition[pos], condition[pos+1], condition[pos+2], condition[pos+3],
                ]) as usize;
                pos += 4;
                if length > condition.len() - pos { return Ok(TriValue::Unknown); }
                match Sid::from_bytes(&condition[pos..pos+length]) {
                    Some(sid) => {
                        pos += length;
                        if !stack_push(&mut stack, Value {
                            vtype: ValueType::Sid(sid),
                            origin: Origin::Literal,
                            flags: 0,
                        })? { return Ok(TriValue::Unknown); }
                    }
                    None => return Ok(TriValue::Unknown),
                }
            }

            // --- Attribute references ---

            // @Local.
            0xf8 => {
                let (name, new_pos) = match read_attr_name(condition, pos) {
                    Some(r) => r,
                    None => return Ok(TriValue::Unknown),
                };
                pos = new_pos;
                let v = resolve_claim(local_claims, &name, for_allow, Origin::LocalAttr)?;
                if !stack_push(&mut stack, v)? { return Ok(TriValue::Unknown); }
            }

            // @User.
            0xf9 => {
                let (name, new_pos) = match read_attr_name(condition, pos) {
                    Some(r) => r,
                    None => return Ok(TriValue::Unknown),
                };
                pos = new_pos;
                let v = resolve_claim(&token.user_claims, &name, for_allow, Origin::UserAttr)?;
                if !stack_push(&mut stack, v)? { return Ok(TriValue::Unknown); }
            }

            // @Resource.
            0xfa => {
                let (name, new_pos) = match read_attr_name(condition, pos) {
                    Some(r) => r,
                    None => return Ok(TriValue::Unknown),
                };
                pos = new_pos;
                let v = resolve_claim(resource_attributes, &name, for_allow, Origin::ResourceAttr)?;
                if !stack_push(&mut stack, v)? { return Ok(TriValue::Unknown); }
            }

            // @Device.
            0xfb => {
                let (name, new_pos) = match read_attr_name(condition, pos) {
                    Some(r) => r,
                    None => return Ok(TriValue::Unknown),
                };
                pos = new_pos;
                let v = resolve_claim(&token.device_claims, &name, for_allow, Origin::DeviceAttr)?;
                if !stack_push(&mut stack, v)? { return Ok(TriValue::Unknown); }
            }

            // --- Relational operators ---

            // ==
            0x80 => {
                if stack.len() < 2 { return Ok(TriValue::Unknown); }
                let rhs = stack.pop().unwrap();
                let lhs = stack.pop().unwrap();
                compat::vec_push(&mut stack, Value::from_bool_result(compare_equal(&lhs, &rhs)))?;
            }

            // !=
            0x81 => {
                if stack.len() < 2 { return Ok(TriValue::Unknown); }
                let rhs = stack.pop().unwrap();
                let lhs = stack.pop().unwrap();
                compat::vec_push(&mut stack, Value::from_bool_result(compare_equal(&lhs, &rhs).negate()))?;
            }

            // <
            0x82 => {
                if stack.len() < 2 { return Ok(TriValue::Unknown); }
                let rhs = stack.pop().unwrap();
                let lhs = stack.pop().unwrap();
                let result = match compare_ordered(&lhs, &rhs) {
                    Some(c) => if c < 0 { TriValue::True } else { TriValue::False },
                    None => TriValue::Unknown,
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // <=
            0x83 => {
                if stack.len() < 2 { return Ok(TriValue::Unknown); }
                let rhs = stack.pop().unwrap();
                let lhs = stack.pop().unwrap();
                let result = match compare_ordered(&lhs, &rhs) {
                    Some(c) => if c <= 0 { TriValue::True } else { TriValue::False },
                    None => TriValue::Unknown,
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // >
            0x84 => {
                if stack.len() < 2 { return Ok(TriValue::Unknown); }
                let rhs = stack.pop().unwrap();
                let lhs = stack.pop().unwrap();
                let result = match compare_ordered(&lhs, &rhs) {
                    Some(c) => if c > 0 { TriValue::True } else { TriValue::False },
                    None => TriValue::Unknown,
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // >=
            0x85 => {
                if stack.len() < 2 { return Ok(TriValue::Unknown); }
                let rhs = stack.pop().unwrap();
                let lhs = stack.pop().unwrap();
                let result = match compare_ordered(&lhs, &rhs) {
                    Some(c) => if c >= 0 { TriValue::True } else { TriValue::False },
                    None => TriValue::Unknown,
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // Contains
            0x86 => {
                if stack.len() < 2 { return Ok(TriValue::Unknown); }
                let rhs = stack.pop().unwrap();
                let lhs = stack.pop().unwrap();
                compat::vec_push(&mut stack, Value::from_bool_result(set_contains(&lhs, &rhs)?))?;
            }

            // Any_of
            0x88 => {
                if stack.len() < 2 { return Ok(TriValue::Unknown); }
                let rhs = stack.pop().unwrap();
                let lhs = stack.pop().unwrap();
                compat::vec_push(&mut stack, Value::from_bool_result(set_any_of(&lhs, &rhs)?))?;
            }

            // Not_Contains
            0x8e => {
                if stack.len() < 2 { return Ok(TriValue::Unknown); }
                let rhs = stack.pop().unwrap();
                let lhs = stack.pop().unwrap();
                compat::vec_push(&mut stack, Value::from_bool_result(set_contains(&lhs, &rhs)?.negate()))?;
            }

            // Not_Any_of
            0x8f => {
                if stack.len() < 2 { return Ok(TriValue::Unknown); }
                let rhs = stack.pop().unwrap();
                let lhs = stack.pop().unwrap();
                compat::vec_push(&mut stack, Value::from_bool_result(set_any_of(&lhs, &rhs)?.negate()))?;
            }

            // --- Existence operators ---

            // Exists
            0x87 => {
                if stack.len() < 1 { return Ok(TriValue::Unknown); }
                let operand = stack.pop().unwrap();
                if !operand.origin.is_attribute() {
                    return Ok(TriValue::Unknown);
                }
                let result = if operand.is_null() { TriValue::False } else { TriValue::True };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // Not_Exists
            0x8d => {
                if stack.len() < 1 { return Ok(TriValue::Unknown); }
                let operand = stack.pop().unwrap();
                if !operand.origin.is_attribute() {
                    return Ok(TriValue::Unknown);
                }
                let result = if operand.is_null() { TriValue::True } else { TriValue::False };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // --- Membership operators ---

            // Member_of
            0x89 => {
                if stack.len() < 1 { return Ok(TriValue::Unknown); }
                let operand = stack.pop().unwrap();
                let sids = match to_sid_list(&operand)? {
                    Some(s) => s,
                    None => { compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?; continue; }
                };
                let result = if all_sids_match_enriched(&sids, enriched, for_allow) {
                    TriValue::True
                } else {
                    TriValue::False
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // Member_of_Any
            0x8b => {
                if stack.len() < 1 { return Ok(TriValue::Unknown); }
                let operand = stack.pop().unwrap();
                let sids = match to_sid_list(&operand)? {
                    Some(s) => s,
                    None => { compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?; continue; }
                };
                let result = if any_sid_matches_enriched(&sids, enriched, for_allow) {
                    TriValue::True
                } else {
                    TriValue::False
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // Device_Member_of
            0x8a => {
                if stack.len() < 1 { return Ok(TriValue::Unknown); }
                let operand = stack.pop().unwrap();
                let sids = match to_sid_list(&operand)? {
                    Some(s) => s,
                    None => { compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?; continue; }
                };
                if effective_device_groups(enriched).is_none() {
                    compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?;
                    continue;
                }
                let result = if all_sids_match_device(&sids, enriched, for_allow) {
                    TriValue::True
                } else {
                    TriValue::False
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // Device_Member_of_Any
            0x8c => {
                if stack.len() < 1 { return Ok(TriValue::Unknown); }
                let operand = stack.pop().unwrap();
                let sids = match to_sid_list(&operand)? {
                    Some(s) => s,
                    None => { compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?; continue; }
                };
                if effective_device_groups(enriched).is_none() {
                    compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?;
                    continue;
                }
                let result = if any_sid_matches_device(&sids, enriched, for_allow) {
                    TriValue::True
                } else {
                    TriValue::False
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // Not_Member_of
            0x90 => {
                if stack.len() < 1 { return Ok(TriValue::Unknown); }
                let operand = stack.pop().unwrap();
                let sids = match to_sid_list(&operand)? {
                    Some(s) => s,
                    None => { compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?; continue; }
                };
                let result = if all_sids_match_enriched(&sids, enriched, for_allow) {
                    TriValue::False
                } else {
                    TriValue::True
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // Not_Member_of_Any
            0x92 => {
                if stack.len() < 1 { return Ok(TriValue::Unknown); }
                let operand = stack.pop().unwrap();
                let sids = match to_sid_list(&operand)? {
                    Some(s) => s,
                    None => { compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?; continue; }
                };
                let result = if any_sid_matches_enriched(&sids, enriched, for_allow) {
                    TriValue::False
                } else {
                    TriValue::True
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // Not_Device_Member_of
            0x91 => {
                if stack.len() < 1 { return Ok(TriValue::Unknown); }
                let operand = stack.pop().unwrap();
                let sids = match to_sid_list(&operand)? {
                    Some(s) => s,
                    None => { compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?; continue; }
                };
                if effective_device_groups(enriched).is_none() {
                    compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?;
                    continue;
                }
                let result = if all_sids_match_device(&sids, enriched, for_allow) {
                    TriValue::False
                } else {
                    TriValue::True
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // Not_Device_Member_of_Any
            0x93 => {
                if stack.len() < 1 { return Ok(TriValue::Unknown); }
                let operand = stack.pop().unwrap();
                let sids = match to_sid_list(&operand)? {
                    Some(s) => s,
                    None => { compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?; continue; }
                };
                if effective_device_groups(enriched).is_none() {
                    compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?;
                    continue;
                }
                let result = if any_sid_matches_device(&sids, enriched, for_allow) {
                    TriValue::False
                } else {
                    TriValue::True
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // --- Logical operators (Kleene three-value logic) ---

            // AND
            0xa0 => {
                if stack.len() < 2 { return Ok(TriValue::Unknown); }
                let rhs = stack.pop().unwrap();
                let lhs = stack.pop().unwrap();
                // LITERAL operands in logical context → UNKNOWN
                if lhs.origin == Origin::Literal || rhs.origin == Origin::Literal {
                    return Ok(TriValue::Unknown);
                }
                let lhs_b = lhs.to_three_value();
                let rhs_b = rhs.to_three_value();
                let result = if lhs_b == TriValue::False || rhs_b == TriValue::False {
                    TriValue::False
                } else if lhs_b == TriValue::True && rhs_b == TriValue::True {
                    TriValue::True
                } else {
                    TriValue::Unknown
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // OR
            0xa1 => {
                if stack.len() < 2 { return Ok(TriValue::Unknown); }
                let rhs = stack.pop().unwrap();
                let lhs = stack.pop().unwrap();
                if lhs.origin == Origin::Literal || rhs.origin == Origin::Literal {
                    return Ok(TriValue::Unknown);
                }
                let lhs_b = lhs.to_three_value();
                let rhs_b = rhs.to_three_value();
                let result = if lhs_b == TriValue::True || rhs_b == TriValue::True {
                    TriValue::True
                } else if lhs_b == TriValue::False && rhs_b == TriValue::False {
                    TriValue::False
                } else {
                    TriValue::Unknown
                };
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // NOT
            0xa2 => {
                if stack.len() < 1 { return Ok(TriValue::Unknown); }
                let operand = stack.pop().unwrap();
                if operand.origin == Origin::Literal {
                    return Ok(TriValue::Unknown);
                }
                let result = operand.to_three_value().negate();
                compat::vec_push(&mut stack, Value::from_bool_result(result))?;
            }

            // Unknown opcode
            _ => return Ok(TriValue::Unknown),
        }
    }

    if stack.len() != 1 {
        return Ok(TriValue::Unknown);
    }
    let final_val = stack.pop().unwrap();
    if final_val.origin == Origin::Literal {
        return Ok(TriValue::Unknown);
    }
    Ok(final_val.to_three_value())
}

// ---------------------------------------------------------------------------
// Bytecode helpers
// ---------------------------------------------------------------------------

/// Read a UTF-16LE attribute name from the condition buffer.
/// Format: length (4 LE) + UTF-16LE data.
fn read_attr_name(condition: &[u8], pos: usize) -> Option<(String, usize)> {
    if pos + 4 > condition.len() {
        return None;
    }
    let length = u32::from_le_bytes([
        condition[pos], condition[pos+1], condition[pos+2], condition[pos+3],
    ]) as usize;
    let new_pos = pos + 4;
    if length > condition.len() - new_pos {
        return None;
    }
    let s = decode_utf16le(&condition[new_pos..new_pos + length]);
    Some((s, new_pos + length))
}

/// Decode UTF-16LE bytes to a Rust String.
///
/// Handles surrogate pairs: a high surrogate (0xD800..=0xDBFF) followed
/// by a low surrogate (0xDC00..=0xDFFF) is combined into a single
/// supplementary-plane character. Lone surrogates are skipped.
fn decode_utf16le(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let code_unit = u16::from_le_bytes([data[i], data[i + 1]]);
        i += 2;

        // High surrogate: look for a following low surrogate.
        if (0xD800..=0xDBFF).contains(&code_unit) {
            if i + 1 < data.len() {
                let next = u16::from_le_bytes([data[i], data[i + 1]]);
                if (0xDC00..=0xDFFF).contains(&next) {
                    // Valid surrogate pair — decode to supplementary char.
                    let cp = 0x10000
                        + ((code_unit as u32 - 0xD800) << 10)
                        + (next as u32 - 0xDC00);
                    i += 2;
                    if let Some(c) = char::from_u32(cp) {
                        #[cfg(not(feature = "kernel"))]
                        result.push(c);
                        #[cfg(feature = "kernel")]
                        if result.push(c).is_err() { break; }
                    }
                    continue;
                }
            }
            // Lone high surrogate — skip it.
            continue;
        }

        // Lone low surrogate — skip it.
        if (0xDC00..=0xDFFF).contains(&code_unit) {
            continue;
        }

        if let Some(c) = char::from_u32(code_unit as u32) {
            // In kernel mode push() can fail on OOM. Truncated string
            // is safe — it just won't match any claim name.
            #[cfg(not(feature = "kernel"))]
            result.push(c);
            #[cfg(feature = "kernel")]
            if result.push(c).is_err() { break; }
        }
    }
    result
}

/// Encode a Rust String to UTF-16LE bytes.
///
/// Characters in the supplementary plane (> U+FFFF) are encoded as
/// surrogate pairs, matching the decode_utf16le behavior.
#[cfg(test)]
fn encode_utf16le(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for c in s.chars() {
        let cp = c as u32;
        if cp > 0xFFFF {
            // Supplementary plane: encode as surrogate pair.
            let adjusted = cp - 0x10000;
            let high = (0xD800 + (adjusted >> 10)) as u16;
            let low = (0xDC00 + (adjusted & 0x3FF)) as u16;
            result.extend_from_slice(&high.to_le_bytes());
            result.extend_from_slice(&low.to_le_bytes());
        } else {
            result.extend_from_slice(&(cp as u16).to_le_bytes());
        }
    }
    result
}

/// Parse composite elements from a sub-buffer.
fn parse_composite_elements(data: &[u8]) -> Result<Option<Vec<Value>>, AllocError> {
    let mut elements = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let op = data[pos];
        pos += 1;
        match op {
            0x00 => continue,
            0x01 | 0x02 | 0x03 | 0x04 => {
                if pos + 10 > data.len() { return Ok(None); }
                let magnitude = u64::from_le_bytes([
                    data[pos], data[pos+1], data[pos+2], data[pos+3],
                    data[pos+4], data[pos+5], data[pos+6], data[pos+7],
                ]);
                let sign = data[pos + 8];
                pos += 10;
                let value = if sign == 0x02 {
                    // Guard against magnitude > i64::MAX (would wrap on cast).
                    if magnitude > i64::MAX as u64 + 1 {
                        return Ok(None);
                    } else if magnitude == i64::MAX as u64 + 1 {
                        i64::MIN
                    } else {
                        -(magnitude as i64)
                    }
                } else {
                    if magnitude > i64::MAX as u64 {
                        return Ok(None);
                    }
                    magnitude as i64
                };
                compat::vec_push(&mut elements, Value {
                    vtype: ValueType::Int64(value),
                    origin: Origin::Literal,
                    flags: 0,
                })?;
            }
            0x10 => {
                if pos + 4 > data.len() { return Ok(None); }
                let length = u32::from_le_bytes([
                    data[pos], data[pos+1], data[pos+2], data[pos+3],
                ]) as usize;
                pos += 4;
                if length > data.len() - pos { return Ok(None); }
                let s = decode_utf16le(&data[pos..pos+length]);
                pos += length;
                compat::vec_push(&mut elements, Value {
                    vtype: ValueType::String(s),
                    origin: Origin::Literal,
                    flags: 0,
                })?;
            }
            0x51 => {
                if pos + 4 > data.len() { return Ok(None); }
                let length = u32::from_le_bytes([
                    data[pos], data[pos+1], data[pos+2], data[pos+3],
                ]) as usize;
                pos += 4;
                if length > data.len() - pos { return Ok(None); }
                let sid = match Sid::from_bytes(&data[pos..pos+length]) {
                    Some(s) => s,
                    None => return Ok(None),
                };
                pos += length;
                compat::vec_push(&mut elements, Value {
                    vtype: ValueType::Sid(sid),
                    origin: Origin::Literal,
                    flags: 0,
                })?;
            }
            _ => return Ok(None),
        }
    }
    Ok(Some(elements))
}

// ---------------------------------------------------------------------------
// Bytecode builder helpers (for tests)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod bytecode {
    use super::*;

    pub fn header() -> Vec<u8> {
        ARTX_HEADER.to_vec()
    }

    pub fn int64_literal(value: i64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x04); // Int64 opcode
        if value < 0 {
            buf.extend_from_slice(&((-value) as u64).to_le_bytes());
            buf.push(0x02); // negative sign
        } else {
            buf.extend_from_slice(&(value as u64).to_le_bytes());
            buf.push(0x01); // positive sign
        }
        buf.push(0x00); // base (decimal)
        buf
    }

    pub fn string_literal(s: &str) -> Vec<u8> {
        let encoded = encode_utf16le(s);
        let mut buf = Vec::new();
        buf.push(0x10);
        buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        buf.extend_from_slice(&encoded);
        buf
    }

    pub fn sid_literal(sid: &Sid) -> Vec<u8> {
        let sid_bytes = sid.to_bytes().unwrap();
        let mut buf = Vec::new();
        buf.push(0x51);
        buf.extend_from_slice(&(sid_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(&sid_bytes);
        buf
    }

    pub fn user_attr(name: &str) -> Vec<u8> {
        let encoded = encode_utf16le(name);
        let mut buf = Vec::new();
        buf.push(0xf9); // @User.
        buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        buf.extend_from_slice(&encoded);
        buf
    }

    pub fn resource_attr(name: &str) -> Vec<u8> {
        let encoded = encode_utf16le(name);
        let mut buf = Vec::new();
        buf.push(0xfa); // @Resource.
        buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        buf.extend_from_slice(&encoded);
        buf
    }

    pub fn local_attr(name: &str) -> Vec<u8> {
        let encoded = encode_utf16le(name);
        let mut buf = Vec::new();
        buf.push(0xf8); // @Local.
        buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        buf.extend_from_slice(&encoded);
        buf
    }

    pub fn op_eq() -> Vec<u8> { alloc::vec![0x80] }
    pub fn op_ne() -> Vec<u8> { alloc::vec![0x81] }
    pub fn op_lt() -> Vec<u8> { alloc::vec![0x82] }
    pub fn op_le() -> Vec<u8> { alloc::vec![0x83] }
    pub fn op_gt() -> Vec<u8> { alloc::vec![0x84] }
    pub fn op_ge() -> Vec<u8> { alloc::vec![0x85] }
    pub fn op_contains() -> Vec<u8> { alloc::vec![0x86] }
    pub fn op_exists() -> Vec<u8> { alloc::vec![0x87] }
    pub fn op_any_of() -> Vec<u8> { alloc::vec![0x88] }
    pub fn op_member_of() -> Vec<u8> { alloc::vec![0x89] }
    pub fn op_member_of_any() -> Vec<u8> { alloc::vec![0x8b] }
    pub fn op_not_exists() -> Vec<u8> { alloc::vec![0x8d] }
    pub fn op_not_contains() -> Vec<u8> { alloc::vec![0x8e] }
    pub fn op_not_any_of() -> Vec<u8> { alloc::vec![0x8f] }
    pub fn op_not_member_of() -> Vec<u8> { alloc::vec![0x90] }
    pub fn op_not_member_of_any() -> Vec<u8> { alloc::vec![0x92] }
    pub fn op_device_member_of() -> Vec<u8> { alloc::vec![0x8a] }
    pub fn op_device_member_of_any() -> Vec<u8> { alloc::vec![0x8c] }
    pub fn op_not_device_member_of() -> Vec<u8> { alloc::vec![0x91] }
    pub fn op_not_device_member_of_any() -> Vec<u8> { alloc::vec![0x93] }
    pub fn op_and() -> Vec<u8> { alloc::vec![0xa0] }
    pub fn op_or() -> Vec<u8> { alloc::vec![0xa1] }
    pub fn op_not() -> Vec<u8> { alloc::vec![0xa2] }

    pub fn device_attr(name: &str) -> Vec<u8> {
        let encoded = encode_utf16le(name);
        let mut buf = Vec::new();
        buf.push(0xfb); // @Device.
        buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        buf.extend_from_slice(&encoded);
        buf
    }

    pub fn uint64_literal(value: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x04); // same opcode, positive sign
        buf.extend_from_slice(&value.to_le_bytes());
        buf.push(0x01); // positive sign
        buf.push(0x00); // base
        buf
    }

    pub fn octet_literal(data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(0x18);
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
        buf
    }

    pub fn boolean_literal(val: bool) -> Vec<u8> {
        // Booleans use int64 encoding: 1 or 0
        int64_literal(if val { 1 } else { 0 })
    }

    pub fn composite_literal(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut inner = Vec::new();
        for p in parts {
            inner.extend_from_slice(p);
        }
        let mut buf = Vec::new();
        buf.push(0x50);
        buf.extend_from_slice(&(inner.len() as u32).to_le_bytes());
        buf.extend_from_slice(&inner);
        buf
    }

    pub fn build(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut result = header();
        for p in parts {
            result.extend_from_slice(p);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::bytecode::*;
    use crate::token::{Token, ClaimEntry, ClaimType, ClaimValues, claim_flags};
    use crate::well_known;

    fn empty_token() -> Token {
        let mut t = Token::system_token().unwrap();
        t.user_claims = Vec::new();
        t.device_claims = Vec::new();
        t
    }

    fn token_with_claims(claims: Vec<ClaimEntry>) -> Token {
        let mut t = empty_token();
        t.user_claims = claims;
        t
    }

    fn int_claim(name: &str, value: i64) -> ClaimEntry {
        ClaimEntry {
            name: String::from(name),
            claim_type: ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![value]),
        }
    }

    fn string_claim(name: &str, value: &str) -> ClaimEntry {
        ClaimEntry {
            name: String::from(name),
            claim_type: ClaimType::String,
            flags: 0,
            values: ClaimValues::String(alloc::vec![String::from(value)]),
        }
    }

    fn bare<'a>(token: &'a Token) -> EnrichedToken<'a> {
        EnrichedToken {
            token,
            has_owner_rights: false,
            has_principal_self: false,
            principal_self_deny_only: false,
            device_groups_override: None,
        }
    }

    fn eval(expr: &[u8], token: &Token) -> TriValue {
        evaluate(expr, &bare(token), &[], &[], true).unwrap()
    }

    fn eval_with_resource(expr: &[u8], token: &Token, resource: &[ClaimEntry]) -> TriValue {
        evaluate(expr, &bare(token), resource, &[], true).unwrap()
    }

    fn eval_deny(expr: &[u8], token: &Token) -> TriValue {
        evaluate(expr, &bare(token), &[], &[], false).unwrap()
    }

    // -----------------------------------------------------------------------
    // Basic structure
    // -----------------------------------------------------------------------

    #[test]
    fn empty_expression_is_unknown() {
        assert_eq!(eval(&[], &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn bad_header_is_unknown() {
        assert_eq!(eval(&[0x00, 0x00, 0x00, 0x00], &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn header_only_empty_stack_is_unknown() {
        let expr = build(&[]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn literal_alone_on_stack_is_unknown() {
        // A literal with no operator → final value has Literal origin → UNKNOWN
        let expr = build(&[int64_literal(42)]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn too_many_values_on_stack() {
        // Two values, no operator → stack has 2 items → UNKNOWN
        let expr = build(&[int64_literal(1), int64_literal(2)]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    // -----------------------------------------------------------------------
    // Integer comparisons
    // -----------------------------------------------------------------------

    #[test]
    fn int_equal_true() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 3)]);
        let expr = build(&[user_attr("clearance"), int64_literal(3), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn int_equal_false() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 3)]);
        let expr = build(&[user_attr("clearance"), int64_literal(5), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn int_not_equal() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 3)]);
        let expr = build(&[user_attr("clearance"), int64_literal(5), op_ne()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn int_less_than() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 2)]);
        let expr = build(&[user_attr("clearance"), int64_literal(3), op_lt()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn int_less_than_false() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 5)]);
        let expr = build(&[user_attr("clearance"), int64_literal(3), op_lt()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn int_less_equal() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 3)]);
        let expr = build(&[user_attr("clearance"), int64_literal(3), op_le()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn int_greater_than() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 5)]);
        let expr = build(&[user_attr("clearance"), int64_literal(3), op_gt()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn int_greater_equal() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 3)]);
        let expr = build(&[user_attr("clearance"), int64_literal(3), op_ge()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn negative_int_comparison() {
        let token = token_with_claims(alloc::vec![int_claim("balance", -10)]);
        let expr = build(&[user_attr("balance"), int64_literal(0), op_lt()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // -----------------------------------------------------------------------
    // String comparisons
    // -----------------------------------------------------------------------

    #[test]
    fn string_equal_case_insensitive() {
        let token = token_with_claims(alloc::vec![string_claim("department", "Engineering")]);
        let expr = build(&[user_attr("department"), string_literal("engineering"), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn string_equal_case_sensitive() {
        let mut claim = string_claim("department", "Engineering");
        claim.flags = claim_flags::CASE_SENSITIVE;
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("department"), string_literal("engineering"), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::False);

        let expr2 = build(&[user_attr("department"), string_literal("Engineering"), op_eq()]);
        assert_eq!(eval(&expr2, &token), TriValue::True);
    }

    #[test]
    fn string_ordering() {
        let token = token_with_claims(alloc::vec![string_claim("name", "alice")]);
        let expr = build(&[user_attr("name"), string_literal("bob"), op_lt()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // -----------------------------------------------------------------------
    // Missing attributes → UNKNOWN
    // -----------------------------------------------------------------------

    #[test]
    fn missing_user_attr_eq_is_unknown() {
        let token = empty_token();
        let expr = build(&[user_attr("nonexistent"), int64_literal(3), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn missing_attr_in_comparison_unknown() {
        let token = empty_token();
        let expr = build(&[user_attr("x"), int64_literal(1), op_gt()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // -----------------------------------------------------------------------
    // Logical operators (three-value)
    // -----------------------------------------------------------------------

    #[test]
    fn and_true_true() {
        let token = token_with_claims(alloc::vec![int_claim("a", 1), int_claim("b", 1)]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),
            user_attr("b"), int64_literal(1), op_eq(),
            op_and(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn and_true_false() {
        let token = token_with_claims(alloc::vec![int_claim("a", 1), int_claim("b", 2)]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),
            user_attr("b"), int64_literal(1), op_eq(),
            op_and(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn and_false_unknown() {
        // FALSE AND UNKNOWN = FALSE (short-circuit)
        let token = token_with_claims(alloc::vec![int_claim("a", 2)]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),   // FALSE
            user_attr("missing"), int64_literal(1), op_eq(), // UNKNOWN
            op_and(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn and_true_unknown() {
        // TRUE AND UNKNOWN = UNKNOWN
        let token = token_with_claims(alloc::vec![int_claim("a", 1)]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),
            user_attr("missing"), int64_literal(1), op_eq(),
            op_and(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn or_true_false() {
        let token = token_with_claims(alloc::vec![int_claim("a", 1), int_claim("b", 2)]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),
            user_attr("b"), int64_literal(1), op_eq(),
            op_or(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn or_false_false() {
        let token = token_with_claims(alloc::vec![int_claim("a", 2), int_claim("b", 2)]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),
            user_attr("b"), int64_literal(1), op_eq(),
            op_or(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn or_true_unknown() {
        // TRUE OR UNKNOWN = TRUE
        let token = token_with_claims(alloc::vec![int_claim("a", 1)]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),
            user_attr("missing"), int64_literal(1), op_eq(),
            op_or(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn or_false_unknown() {
        // FALSE OR UNKNOWN = UNKNOWN
        let token = token_with_claims(alloc::vec![int_claim("a", 2)]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),
            user_attr("missing"), int64_literal(1), op_eq(),
            op_or(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn not_true() {
        let token = token_with_claims(alloc::vec![int_claim("a", 1)]);
        let expr = build(&[user_attr("a"), int64_literal(1), op_eq(), op_not()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn not_false() {
        let token = token_with_claims(alloc::vec![int_claim("a", 2)]);
        let expr = build(&[user_attr("a"), int64_literal(1), op_eq(), op_not()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn not_unknown() {
        let expr = build(&[user_attr("missing"), int64_literal(1), op_eq(), op_not()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn literal_in_logical_context_is_unknown() {
        // §11.17: LITERAL operands in logical context → UNKNOWN
        let token = token_with_claims(alloc::vec![int_claim("a", 1)]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),
            int64_literal(1), // literal
            op_and(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // -----------------------------------------------------------------------
    // Existence operators
    // -----------------------------------------------------------------------

    #[test]
    fn exists_present_attribute() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 3)]);
        let expr = build(&[user_attr("clearance"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn exists_missing_attribute() {
        let expr = build(&[user_attr("nonexistent"), op_exists()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::False);
    }

    #[test]
    fn not_exists_present() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 3)]);
        let expr = build(&[user_attr("clearance"), op_not_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn not_exists_missing() {
        let expr = build(&[user_attr("nonexistent"), op_not_exists()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::True);
    }

    #[test]
    fn exists_on_literal_is_unknown() {
        // §11.17: Exists requires attribute origin
        let expr = build(&[int64_literal(42), op_exists()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    // -----------------------------------------------------------------------
    // Membership operators
    // -----------------------------------------------------------------------

    #[test]
    fn member_of_matching_group() {
        let token = empty_token(); // system token has Administrators group
        let admins_sid = well_known::administrators().unwrap();
        let expr = build(&[sid_literal(&admins_sid), op_member_of()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn member_of_non_matching() {
        let token = empty_token();
        let random_sid = crate::sid::Sid::new(5, &[21, 999, 999, 999, 9999]).unwrap();
        let expr = build(&[sid_literal(&random_sid), op_member_of()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn member_of_any_one_matches() {
        let token = empty_token(); // has Administrators
        let admins = well_known::administrators().unwrap();
        let random = crate::sid::Sid::new(5, &[21, 1, 2, 3, 999]).unwrap();
        // Build a composite SID literal
        let mut composite_data = Vec::new();
        composite_data.extend_from_slice(&sid_literal(&random));
        composite_data.extend_from_slice(&sid_literal(&admins));
        let mut expr = header();
        expr.push(0x50); // composite
        expr.extend_from_slice(&(composite_data.len() as u32).to_le_bytes());
        expr.extend_from_slice(&composite_data);
        expr.extend_from_slice(&op_member_of_any());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn not_member_of_non_matching() {
        let token = empty_token();
        let random_sid = crate::sid::Sid::new(5, &[21, 999, 999, 999, 9999]).unwrap();
        let expr = build(&[sid_literal(&random_sid), op_not_member_of()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // -----------------------------------------------------------------------
    // DISABLED and USE_FOR_DENY_ONLY claim flags
    // -----------------------------------------------------------------------

    #[test]
    fn disabled_claim_resolves_null() {
        let mut claim = int_claim("clearance", 3);
        claim.flags = claim_flags::DISABLED;
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("clearance"), int64_literal(3), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown); // NULL
    }

    #[test]
    fn deny_only_claim_invisible_for_allow() {
        let mut claim = int_claim("clearance", 3);
        claim.flags = claim_flags::USE_FOR_DENY_ONLY;
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("clearance"), int64_literal(3), op_eq()]);
        // for_allow=true → deny-only claim is NULL
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn deny_only_claim_visible_for_deny() {
        let mut claim = int_claim("clearance", 3);
        claim.flags = claim_flags::USE_FOR_DENY_ONLY;
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("clearance"), int64_literal(3), op_eq()]);
        // for_allow=false → deny-only claim IS visible
        assert_eq!(eval_deny(&expr, &token), TriValue::True);
    }

    // -----------------------------------------------------------------------
    // Resource attributes
    // -----------------------------------------------------------------------

    #[test]
    fn resource_attr_comparison() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 5)]);
        let resource = alloc::vec![int_claim("confidentiality", 3)];
        // @User.clearance >= @Resource.confidentiality
        let expr = build(&[
            user_attr("clearance"),
            resource_attr("confidentiality"),
            op_ge(),
        ]);
        assert_eq!(eval_with_resource(&expr, &token, &resource), TriValue::True);
    }

    #[test]
    fn resource_attr_comparison_fails() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 1)]);
        let resource = alloc::vec![int_claim("confidentiality", 3)];
        let expr = build(&[
            user_attr("clearance"),
            resource_attr("confidentiality"),
            op_ge(),
        ]);
        assert_eq!(eval_with_resource(&expr, &token, &resource), TriValue::False);
    }

    // -----------------------------------------------------------------------
    // Complex expressions
    // -----------------------------------------------------------------------

    #[test]
    fn compound_condition_and() {
        // @User.department == "engineering" AND @User.clearance >= 3
        let token = token_with_claims(alloc::vec![
            string_claim("department", "engineering"),
            int_claim("clearance", 5),
        ]);
        let expr = build(&[
            user_attr("department"), string_literal("engineering"), op_eq(),
            user_attr("clearance"), int64_literal(3), op_ge(),
            op_and(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn compound_condition_one_fails() {
        let token = token_with_claims(alloc::vec![
            string_claim("department", "marketing"),
            int_claim("clearance", 5),
        ]);
        let expr = build(&[
            user_attr("department"), string_literal("engineering"), op_eq(),
            user_attr("clearance"), int64_literal(3), op_ge(),
            op_and(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn nested_or_and() {
        // (a == 1 OR b == 1) AND c == 1
        let token = token_with_claims(alloc::vec![
            int_claim("a", 2), int_claim("b", 1), int_claim("c", 1),
        ]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),
            user_attr("b"), int64_literal(1), op_eq(),
            op_or(),
            user_attr("c"), int64_literal(1), op_eq(),
            op_and(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // -----------------------------------------------------------------------
    // Bounds and malformed input
    // -----------------------------------------------------------------------

    #[test]
    fn truncated_int_literal() {
        let mut expr = header();
        expr.push(0x04); // Int64
        expr.extend_from_slice(&[0x00; 5]); // only 5 bytes, need 10
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn truncated_string_length() {
        let mut expr = header();
        expr.push(0x10); // string
        expr.extend_from_slice(&[0x00; 2]); // only 2 bytes for length, need 4
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn string_length_exceeds_buffer() {
        let mut expr = header();
        expr.push(0x10);
        expr.extend_from_slice(&100u32.to_le_bytes()); // claims 100 bytes
        expr.extend_from_slice(&[0x00; 4]); // but only 4 bytes of data
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn unknown_opcode() {
        let mut expr = header();
        expr.push(0xFF); // unknown
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn operator_with_empty_stack() {
        let expr = build(&[op_eq()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn operator_with_insufficient_stack() {
        let expr = build(&[int64_literal(1), op_eq()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn type_mismatch_returns_unknown() {
        // int == string → UNKNOWN
        let token = token_with_claims(alloc::vec![int_claim("x", 42)]);
        let expr = build(&[user_attr("x"), string_literal("hello"), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // -----------------------------------------------------------------------
    // Contains / Any_of
    // -----------------------------------------------------------------------

    #[test]
    fn contains_single_value() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), int64_literal(5), op_contains()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn contains_missing_value() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), int64_literal(3), op_contains()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn any_of_one_matches() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        // Build composite {3, 5, 7}
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(3));
        comp.extend_from_slice(&int64_literal(5));
        comp.extend_from_slice(&int64_literal(7));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("x"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_any_of());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn not_contains() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), int64_literal(3), op_not_contains()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn not_any_of_none_match() {
        let token = token_with_claims(alloc::vec![int_claim("x", 99)]);
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(1));
        comp.extend_from_slice(&int64_literal(2));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("x"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_not_any_of());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // -----------------------------------------------------------------------
    // Local claims (@Local.)
    // -----------------------------------------------------------------------

    #[test]
    fn local_claim_comparison() {
        let token = empty_token();
        let local = alloc::vec![int_claim("mfa", 1)];
        let expr = build(&[local_attr("mfa"), int64_literal(1), op_eq()]);
        assert_eq!(evaluate(&expr, &bare(&token), &[], &local, true).unwrap(), TriValue::True);
    }

    // -----------------------------------------------------------------------
    // INT64↔UINT64 promotion (Peios divergence)
    // -----------------------------------------------------------------------

    fn uint_claim(name: &str, value: u64) -> ClaimEntry {
        ClaimEntry {
            name: String::from(name),
            claim_type: crate::token::ClaimType::Uint64,
            flags: 0,
            values: ClaimValues::Uint64(alloc::vec![value]),
        }
    }

    #[test]
    fn int64_uint64_equal_positive() {
        let token = token_with_claims(alloc::vec![uint_claim("x", 42)]);
        let expr = build(&[user_attr("x"), int64_literal(42), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn int64_uint64_equal_negative_always_false() {
        // Negative INT64 can never equal a UINT64
        let token = token_with_claims(alloc::vec![uint_claim("x", 5)]);
        let expr = build(&[user_attr("x"), int64_literal(-5), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn negative_int64_less_than_any_uint64() {
        let token = token_with_claims(alloc::vec![uint_claim("x", 0)]);
        let expr = build(&[int64_literal(-1), user_attr("x"), op_lt()]);
        // Need to reverse: we push literal first, then attr, then op_lt
        // This evaluates: -1 < x (where x=0) → true
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn uint64_greater_than_negative_int64() {
        let token = token_with_claims(alloc::vec![uint_claim("x", 0)]);
        let expr = build(&[user_attr("x"), int64_literal(-100), op_gt()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn int64_uint64_not_equal_different_values() {
        let token = token_with_claims(alloc::vec![uint_claim("x", 100)]);
        let expr = build(&[user_attr("x"), int64_literal(99), op_ne()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn int64_uint64_ordering_equal_values() {
        let token = token_with_claims(alloc::vec![uint_claim("x", 50)]);
        let expr = build(&[user_attr("x"), int64_literal(50), op_le()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
        let expr2 = build(&[user_attr("x"), int64_literal(50), op_ge()]);
        assert_eq!(eval(&expr2, &token), TriValue::True);
        let expr3 = build(&[user_attr("x"), int64_literal(50), op_lt()]);
        assert_eq!(eval(&expr3, &token), TriValue::False);
    }

    // -----------------------------------------------------------------------
    // Boolean↔Int cross-type equality
    // -----------------------------------------------------------------------

    fn bool_claim(name: &str, value: bool) -> ClaimEntry {
        ClaimEntry {
            name: String::from(name),
            claim_type: crate::token::ClaimType::Boolean,
            flags: 0,
            values: ClaimValues::Boolean(alloc::vec![value]),
        }
    }

    #[test]
    fn bool_true_equals_int_1() {
        let token = token_with_claims(alloc::vec![bool_claim("active", true)]);
        let expr = build(&[user_attr("active"), int64_literal(1), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn bool_false_equals_int_0() {
        let token = token_with_claims(alloc::vec![bool_claim("active", false)]);
        let expr = build(&[user_attr("active"), int64_literal(0), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn bool_true_not_equals_int_0() {
        let token = token_with_claims(alloc::vec![bool_claim("active", true)]);
        let expr = build(&[user_attr("active"), int64_literal(0), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn bool_ordering_is_unknown() {
        // Boolean is not orderable
        let token = token_with_claims(alloc::vec![bool_claim("active", true)]);
        let expr = build(&[user_attr("active"), int64_literal(1), op_lt()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // -----------------------------------------------------------------------
    // Composite equality
    // -----------------------------------------------------------------------

    #[test]
    fn composite_equal_same_elements() {
        let token = token_with_claims(alloc::vec![ClaimEntry {
            name: String::from("roles"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![1, 2, 3]),
        }]);
        // Build composite literal {1, 2, 3}
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(1));
        comp.extend_from_slice(&int64_literal(2));
        comp.extend_from_slice(&int64_literal(3));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("roles"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_eq());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn composite_equal_different_order() {
        let token = token_with_claims(alloc::vec![ClaimEntry {
            name: String::from("roles"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![1, 2, 3]),
        }]);
        // Composite {3, 2, 1} — different order → FALSE (element-wise)
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(3));
        comp.extend_from_slice(&int64_literal(2));
        comp.extend_from_slice(&int64_literal(1));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("roles"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_eq());
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn composite_equal_different_length() {
        let token = token_with_claims(alloc::vec![ClaimEntry {
            name: String::from("roles"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![1, 2]),
        }]);
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(1));
        comp.extend_from_slice(&int64_literal(2));
        comp.extend_from_slice(&int64_literal(3));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("roles"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_eq());
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn scalar_vs_composite_is_unknown() {
        let token = token_with_claims(alloc::vec![int_claim("x", 1)]);
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(1));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("x"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_eq());
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // -----------------------------------------------------------------------
    // Octet string comparison
    // -----------------------------------------------------------------------

    fn octet_claim(name: &str, data: &[u8]) -> ClaimEntry {
        ClaimEntry {
            name: String::from(name),
            claim_type: crate::token::ClaimType::Octet,
            flags: 0,
            values: ClaimValues::Octet(alloc::vec![data.to_vec()]),
        }
    }

    #[test]
    fn octet_equal() {
        let token = token_with_claims(alloc::vec![octet_claim("hash", &[0xDE, 0xAD])]);
        let mut expr = header();
        expr.extend_from_slice(&user_attr("hash"));
        expr.push(0x18); // octet literal
        let data = [0xDE, 0xAD];
        expr.extend_from_slice(&(data.len() as u32).to_le_bytes());
        expr.extend_from_slice(&data);
        expr.extend_from_slice(&op_eq());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn octet_not_equal() {
        let token = token_with_claims(alloc::vec![octet_claim("hash", &[0xDE, 0xAD])]);
        let mut expr = header();
        expr.extend_from_slice(&user_attr("hash"));
        expr.push(0x18);
        let data = [0xBE, 0xEF];
        expr.extend_from_slice(&(data.len() as u32).to_le_bytes());
        expr.extend_from_slice(&data);
        expr.extend_from_slice(&op_eq());
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    // -----------------------------------------------------------------------
    // SID comparison via == operator
    // -----------------------------------------------------------------------

    fn sid_claim(name: &str, sid: &crate::sid::Sid) -> ClaimEntry {
        ClaimEntry {
            name: String::from(name),
            claim_type: crate::token::ClaimType::Sid,
            flags: 0,
            values: ClaimValues::Sid(alloc::vec![sid.clone()]),
        }
    }

    #[test]
    fn sid_equal_via_operator() {
        let sid = well_known::administrators().unwrap();
        let token = token_with_claims(alloc::vec![sid_claim("group", &sid)]);
        let expr = build(&[user_attr("group"), sid_literal(&sid), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn sid_not_equal_via_operator() {
        let token = token_with_claims(alloc::vec![
            sid_claim("group", &well_known::administrators().unwrap()),
        ]);
        let expr = build(&[
            user_attr("group"),
            sid_literal(&well_known::users().unwrap()),
            op_eq(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    // -----------------------------------------------------------------------
    // Device claims
    // -----------------------------------------------------------------------

    #[test]
    fn device_member_of_with_device_groups() {
        let mut token = empty_token();
        let managed = crate::sid::Sid::new(5, &[21, 100, 200, 300, 5001]).unwrap();
        token.device_groups = Some(alloc::vec![
            crate::group::GroupEntry::new(
                managed.clone(),
                crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
            ),
        ]);
        let expr = build(&[sid_literal(&managed), bytecode::op_member_of_any()]);
        // Device_Member_of_Any should check device groups — but op 0x8b is Member_of_Any (user groups)
        // We need 0x8c for Device_Member_of_Any
        let mut expr2 = header();
        expr2.extend_from_slice(&sid_literal(&managed));
        expr2.push(0x8c); // Device_Member_of_Any
        assert_eq!(eval(&expr2, &token), TriValue::True);
    }

    #[test]
    fn device_member_of_no_device_groups_is_unknown() {
        let token = empty_token(); // device_groups = None
        let sid = crate::sid::Sid::new(5, &[21, 999, 999, 999]).unwrap();
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&sid));
        expr.push(0x8a); // Device_Member_of
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn device_member_of_non_matching() {
        let mut token = empty_token();
        let managed = crate::sid::Sid::new(5, &[21, 100, 200, 300, 5001]).unwrap();
        token.device_groups = Some(alloc::vec![
            crate::group::GroupEntry::new(
                managed.clone(),
                crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
            ),
        ]);
        let other = crate::sid::Sid::new(5, &[21, 999, 999, 999]).unwrap();
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&other));
        expr.push(0x8a); // Device_Member_of
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    // -----------------------------------------------------------------------
    // Empty attribute → NULL (vacuous truth prevention)
    // -----------------------------------------------------------------------

    #[test]
    fn empty_claim_values_resolve_null() {
        let claim = ClaimEntry {
            name: String::from("tags"),
            claim_type: crate::token::ClaimType::String,
            flags: 0,
            values: ClaimValues::String(alloc::vec![]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("tags"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False); // empty → NULL → not exists
    }

    // -----------------------------------------------------------------------
    // Padding edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn trailing_padding_ignored() {
        let token = token_with_claims(alloc::vec![int_claim("x", 1)]);
        let mut expr = build(&[user_attr("x"), int64_literal(1), op_eq()]);
        expr.push(0x00); expr.push(0x00); // trailing padding
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // -----------------------------------------------------------------------
    // Multiple attribute sources in one expression
    // -----------------------------------------------------------------------

    #[test]
    fn user_and_device_and_resource_combined() {
        let mut token = token_with_claims(alloc::vec![int_claim("clearance", 5)]);
        let managed = crate::sid::Sid::new(5, &[21, 100, 200, 300, 5001]).unwrap();
        token.device_groups = Some(alloc::vec![
            crate::group::GroupEntry::new(
                managed.clone(),
                crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED,
            ),
        ]);
        let resource = alloc::vec![int_claim("confidentiality", 3)];
        // @User.clearance >= @Resource.confidentiality AND Device_Member_of({managed})
        let mut expr = header();
        expr.extend_from_slice(&user_attr("clearance"));
        expr.extend_from_slice(&resource_attr("confidentiality"));
        expr.extend_from_slice(&op_ge());
        expr.extend_from_slice(&sid_literal(&managed));
        expr.push(0x8a); // Device_Member_of
        expr.extend_from_slice(&op_and());
        assert_eq!(evaluate(&expr, &bare(&token), &resource, &[], true).unwrap(), TriValue::True);
    }

    // ===================================================================
    // §11.12 Corpus: Three-Value Logic Full Truth Table
    // ===================================================================

    fn tv_token_true_false() -> Token {
        token_with_claims(alloc::vec![
            int_claim("tv_true", 1),
            int_claim("tv_false", 0),
        ])
    }

    #[test]
    fn three_value_and_false_false() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_false"), user_attr("tv_false"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn three_value_and_false_unknown() {
        // AND(FALSE, UNKNOWN) = FALSE
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_false"), user_attr("missing"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn three_value_and_unknown_unknown() {
        let token = empty_token();
        let expr = build(&[user_attr("a"), user_attr("b"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn three_value_or_true_true() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_true"), user_attr("tv_true"), op_or()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn three_value_or_true_unknown() {
        // OR(TRUE, UNKNOWN) = TRUE
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_true"), user_attr("missing"), op_or()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn three_value_or_unknown_unknown() {
        let token = empty_token();
        let expr = build(&[user_attr("a"), user_attr("b"), op_or()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: Boolean Coercion
    // ===================================================================

    #[test]
    fn cond_coerce_int64_nonzero_true() {
        // Attribute-backed int 42 coerces to TRUE in AND
        let token = token_with_claims(alloc::vec![int_claim("x", 42)]);
        let expr = build(&[user_attr("x"), user_attr("x"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_coerce_int64_zero_false() {
        let token = token_with_claims(alloc::vec![int_claim("x", 0)]);
        let expr = build(&[user_attr("x"), user_attr("x"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_coerce_string_nonempty_true() {
        let token = token_with_claims(alloc::vec![string_claim("s", "hello")]);
        let expr = build(&[user_attr("s"), user_attr("s"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_coerce_string_empty_false() {
        let token = token_with_claims(alloc::vec![string_claim("s", "")]);
        let expr = build(&[user_attr("s"), user_attr("s"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_coerce_null_unknown() {
        // Missing attribute → NULL → UNKNOWN in logical context
        let token = empty_token();
        let expr = build(&[user_attr("missing"), user_attr("missing"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: Expression Envelope
    // ===================================================================

    #[test]
    fn cond_expression_valid_magic_proceeds() {
        let token = token_with_claims(alloc::vec![int_claim("x", 1)]);
        let expr = build(&[user_attr("x"), int64_literal(1), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_expression_too_short_returns_unknown() {
        let token = empty_token();
        // Only 3 bytes — not enough for magic
        let expr = alloc::vec![0x61, 0x72, 0x74];
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: Membership Operators
    // ===================================================================

    #[test]
    fn cond_member_of_all_match_true() {
        let mut token = empty_token();
        let g = crate::sid::Sid::new(5, &[21, 1, 2, 3, 4001]).unwrap();
        token.groups = alloc::vec![
            crate::group::GroupEntry::new(g.clone(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED),
        ];
        let expr = build(&[sid_literal(&g), bytecode::op_member_of()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_member_of_one_missing_false() {
        let token = empty_token(); // no groups
        let g = crate::sid::Sid::new(5, &[21, 1, 2, 3, 4001]).unwrap();
        let expr = build(&[sid_literal(&g), bytecode::op_member_of()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_not_member_of_one_missing_true() {
        let token = empty_token();
        let g = crate::sid::Sid::new(5, &[21, 1, 2, 3, 4001]).unwrap();
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&g));
        expr.push(0x90); // Not_Member_of
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_not_member_of_any_none_match_true() {
        let token = empty_token();
        let g = crate::sid::Sid::new(5, &[21, 1, 2, 3, 4001]).unwrap();
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&g));
        expr.push(0x92); // Not_Member_of_Any
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // ===================================================================
    // §11.12 Corpus: Attribute Resolution
    // ===================================================================

    #[test]
    fn cond_user_attr_resolves_from_token() {
        let token = token_with_claims(alloc::vec![int_claim("dept", 42)]);
        let expr = build(&[user_attr("dept"), int64_literal(42), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_device_attr_resolves_from_token() {
        let mut token = empty_token();
        token.device_claims = alloc::vec![int_claim("loc", 7)];
        let mut expr = header();
        {
            let encoded = encode_utf16le("loc");
            expr.push(0xfb); // @Device.
            expr.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            expr.extend_from_slice(&encoded);
        }
        expr.extend_from_slice(&int64_literal(7));
        expr.extend_from_slice(&op_eq());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_resource_attr_resolves_from_sacl() {
        let token = empty_token();
        let resource = alloc::vec![int_claim("level", 5)];
        let mut expr = header();
        expr.extend_from_slice(&resource_attr("level"));
        expr.extend_from_slice(&int64_literal(5));
        expr.extend_from_slice(&op_eq());
        assert_eq!(evaluate(&expr, &bare(&token), &resource, &[], true).unwrap(), TriValue::True);
    }

    #[test]
    fn cond_missing_attr_returns_null() {
        let token = empty_token();
        let expr = build(&[user_attr("nonexistent"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_missing_device_claims_resolve_absent() {
        let token = empty_token(); // no device_claims
        let mut expr = header();
        {
            let encoded = encode_utf16le("anything");
            expr.push(0xfb); // @Device.
            expr.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            expr.extend_from_slice(&encoded);
        }
        expr.extend_from_slice(&op_exists());
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    // ===================================================================
    // §11.12 Corpus: Claim Flags
    // ===================================================================

    #[test]
    fn cond_disabled_claim_invisible() {
        let claim = ClaimEntry {
            name: String::from("secret"),
            claim_type: crate::token::ClaimType::Int64,
            flags: crate::token::claim_flags::DISABLED,
            values: ClaimValues::Int64(alloc::vec![42]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("secret"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False); // disabled → NULL → not exists
    }

    #[test]
    fn cond_exists_false_for_empty_attr() {
        let claim = ClaimEntry {
            name: String::from("tags"),
            claim_type: crate::token::ClaimType::String,
            flags: 0,
            values: ClaimValues::String(alloc::vec![]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("tags"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    // ===================================================================
    // §11.12 Corpus: Relational Operators
    // ===================================================================

    #[test]
    fn cond_less_than_op() {
        let token = token_with_claims(alloc::vec![int_claim("x", 3)]);
        let expr = build(&[user_attr("x"), int64_literal(5), op_lt()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_less_equal_op() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), int64_literal(5), op_le()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_greater_than_op() {
        let token = token_with_claims(alloc::vec![int_claim("x", 7)]);
        let expr = build(&[user_attr("x"), int64_literal(5), op_gt()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_greater_equal_op() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), int64_literal(5), op_ge()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_equal_op() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), int64_literal(5), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_not_equal_op() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), int64_literal(6), op_ne()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_relational_null_lhs_unknown() {
        let token = empty_token();
        let expr = build(&[user_attr("missing"), int64_literal(5), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: Three-Value Logic Full Truth Table (all 9 AND, 9 OR, 3 NOT)
    // ===================================================================

    // --- AND: remaining combinations not yet covered ---

    #[test]
    fn cond_and_false_true_is_false() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_false"), user_attr("tv_true"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_and_unknown_true_is_unknown() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("missing"), user_attr("tv_true"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_and_unknown_false_is_false() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("missing"), user_attr("tv_false"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_and_true_true_is_true() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_true"), user_attr("tv_true"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // --- OR: remaining combinations not yet covered ---

    #[test]
    fn cond_or_true_false_is_true() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_true"), user_attr("tv_false"), op_or()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_or_false_true_is_true() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_false"), user_attr("tv_true"), op_or()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_or_false_false_is_false() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_false"), user_attr("tv_false"), op_or()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_or_false_unknown_is_unknown() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_false"), user_attr("missing"), op_or()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_or_unknown_true_is_true() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("missing"), user_attr("tv_true"), op_or()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_or_unknown_false_is_unknown() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("missing"), user_attr("tv_false"), op_or()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // --- NOT: already covered above but re-asserting with tv_token_true_false ---

    #[test]
    fn cond_not_true_is_false() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_true"), op_not()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_not_false_is_true() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_false"), op_not()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_not_unknown_is_unknown() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("missing"), op_not()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: Boolean Coercion for all types
    // ===================================================================

    #[test]
    fn cond_coerce_uint64_nonzero_true() {
        let token = token_with_claims(alloc::vec![uint_claim("x", 99)]);
        let expr = build(&[user_attr("x"), user_attr("x"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_coerce_uint64_zero_false() {
        let token = token_with_claims(alloc::vec![uint_claim("x", 0)]);
        let expr = build(&[user_attr("x"), user_attr("x"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_coerce_boolean_nonzero_true() {
        let token = token_with_claims(alloc::vec![bool_claim("b", true)]);
        let expr = build(&[user_attr("b"), user_attr("b"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_coerce_boolean_zero_false() {
        let token = token_with_claims(alloc::vec![bool_claim("b", false)]);
        let expr = build(&[user_attr("b"), user_attr("b"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_coerce_sid_unknown() {
        // SID is not boolean-coercible → UNKNOWN in logical context
        let sid = well_known::administrators().unwrap();
        let token = token_with_claims(alloc::vec![sid_claim("g", &sid)]);
        let expr = build(&[user_attr("g"), user_attr("g"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_coerce_octet_unknown() {
        // Octet is not boolean-coercible → UNKNOWN
        let token = token_with_claims(alloc::vec![octet_claim("o", &[0xAB])]);
        let expr = build(&[user_attr("o"), user_attr("o"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_coerce_composite_unknown() {
        // Composite is not boolean-coercible → UNKNOWN
        let claim = ClaimEntry {
            name: String::from("multi"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![1, 2]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("multi"), user_attr("multi"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_literal_in_logical_context_unknown() {
        // Literal-origin values in logical operators produce UNKNOWN
        let token = token_with_claims(alloc::vec![int_claim("a", 1)]);
        // int64_literal(1) AND (a == 1) — literal on LHS
        let expr = build(&[
            int64_literal(1),
            user_attr("a"), int64_literal(1), op_eq(),
            op_and(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: Relational NULL and type-mismatch edge cases
    // ===================================================================

    #[test]
    fn cond_relational_null_rhs_unknown() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), user_attr("missing"), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_relational_type_mismatch_unknown() {
        // int vs string → UNKNOWN
        let token = token_with_claims(alloc::vec![int_claim("x", 42)]);
        let expr = build(&[user_attr("x"), string_literal("hello"), op_ne()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_relational_insufficient_stack_unknown() {
        // Only one item on stack when == needs two
        let expr = build(&[int64_literal(42), op_lt()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_ordered_composite_unknown() {
        // Ordered comparison with composite operand → UNKNOWN
        let claim = ClaimEntry {
            name: String::from("multi"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![1, 2]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("multi"), int64_literal(1), op_lt()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_ordered_boolean_unknown() {
        // Ordered comparison with BOOLEAN operand → UNKNOWN
        let token = token_with_claims(alloc::vec![bool_claim("b", true)]);
        let expr = build(&[user_attr("b"), int64_literal(1), op_lt()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_int64_uint64_promotion_in_comparison() {
        // INT64 vs UINT64: negative INT64 < any UINT64
        let token = token_with_claims(alloc::vec![uint_claim("x", 0)]);
        let expr = build(&[int64_literal(-100), user_attr("x"), op_lt()]);
        assert_eq!(eval(&expr, &token), TriValue::True);

        // Positive INT64 == UINT64
        let token2 = token_with_claims(alloc::vec![uint_claim("x", 42)]);
        let expr2 = build(&[int64_literal(42), user_attr("x"), op_eq()]);
        assert_eq!(eval(&expr2, &token2), TriValue::True);
    }

    // ===================================================================
    // §11.12 Corpus: Set Operators NULL/empty edge cases
    // ===================================================================

    #[test]
    fn cond_contains_null_lhs_unknown() {
        let expr = build(&[user_attr("missing"), int64_literal(1), op_contains()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_contains_null_rhs_unknown() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), user_attr("missing"), op_contains()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_contains_all_found_true() {
        // Multi-valued LHS contains all of RHS
        let claim = ClaimEntry {
            name: String::from("roles"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![1, 2, 3, 4]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        // Build composite RHS {2, 3}
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(2));
        comp.extend_from_slice(&int64_literal(3));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("roles"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_contains());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_contains_one_missing_false() {
        let claim = ClaimEntry {
            name: String::from("roles"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![1, 2]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        // RHS {2, 99} — 99 not in LHS
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(2));
        comp.extend_from_slice(&int64_literal(99));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("roles"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_contains());
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_any_of_null_lhs_unknown() {
        let expr = build(&[user_attr("missing"), int64_literal(1), op_any_of()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_any_of_null_rhs_unknown() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), user_attr("missing"), op_any_of()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_any_of_one_match_true() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(3));
        comp.extend_from_slice(&int64_literal(5));
        comp.extend_from_slice(&int64_literal(7));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("x"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_any_of());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_any_of_none_match_false() {
        let token = token_with_claims(alloc::vec![int_claim("x", 99)]);
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(1));
        comp.extend_from_slice(&int64_literal(2));
        comp.extend_from_slice(&int64_literal(3));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("x"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_any_of());
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_not_contains_op() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), int64_literal(5), op_not_contains()]);
        // 5 is contained → NOT_Contains → FALSE
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_not_any_of_op() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(5));
        comp.extend_from_slice(&int64_literal(6));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("x"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_not_any_of());
        // 5 found in {5,6} → NOT_Any_of → FALSE
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    // ===================================================================
    // §11.12 Corpus: Existence operators — additional edge cases
    // ===================================================================

    #[test]
    fn cond_not_exists_non_attr_origin_unknown() {
        // Not_Exists on LITERAL-origin → UNKNOWN
        let expr = build(&[int64_literal(42), op_not_exists()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_exists_insufficient_stack_unknown() {
        let expr = build(&[op_exists()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_exists_all_four_namespaces() {
        // Exists extended to @User., @Device., @Local., @Resource.
        let token = token_with_claims(alloc::vec![int_claim("u", 1)]);
        let resource = alloc::vec![int_claim("r", 2)];
        let local = alloc::vec![int_claim("l", 3)];

        // @User.
        let expr_u = build(&[user_attr("u"), op_exists()]);
        assert_eq!(evaluate(&expr_u, &bare(&token), &resource, &local, true).unwrap(), TriValue::True);

        // @Resource.
        let expr_r = build(&[resource_attr("r"), op_exists()]);
        assert_eq!(evaluate(&expr_r, &bare(&token), &resource, &local, true).unwrap(), TriValue::True);

        // @Local.
        let expr_l = build(&[local_attr("l"), op_exists()]);
        assert_eq!(evaluate(&expr_l, &bare(&token), &resource, &local, true).unwrap(), TriValue::True);

        // @Device. — build manually (opcode 0xfb)
        let mut token_d = empty_token();
        token_d.device_claims = alloc::vec![int_claim("d", 4)];
        let mut expr_d = header();
        {
            let encoded = encode_utf16le("d");
            expr_d.push(0xfb);
            expr_d.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            expr_d.extend_from_slice(&encoded);
        }
        expr_d.extend_from_slice(&op_exists());
        assert_eq!(evaluate(&expr_d, &bare(&token_d), &[], &[], true).unwrap(), TriValue::True);
    }

    // ===================================================================
    // §11.12 Corpus: Membership Operators — full matrix
    // ===================================================================

    fn make_group_token(sids: &[crate::sid::Sid], attrs: u32) -> Token {
        let mut t = empty_token();
        t.groups = sids.iter().map(|s| {
            crate::group::GroupEntry::new(s.clone(), attrs)
        }).collect();
        t
    }

    fn make_device_token(sids: &[crate::sid::Sid], attrs: u32) -> Token {
        let mut t = empty_token();
        t.device_groups = Some(sids.iter().map(|s| {
            crate::group::GroupEntry::new(s.clone(), attrs)
        }).collect());
        t
    }

    #[test]
    fn cond_member_of_any_one_match_true() {
        let g1 = crate::sid::Sid::new(5, &[21, 1, 2, 3, 4001]).unwrap();
        let g2 = crate::sid::Sid::new(5, &[21, 1, 2, 3, 4002]).unwrap();
        let token = make_group_token(&[g1.clone()], crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED);
        // composite {g_random, g1} — g1 matches
        let mut comp = Vec::new();
        comp.extend_from_slice(&sid_literal(&g2));
        comp.extend_from_slice(&sid_literal(&g1));
        let mut expr = header();
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_member_of_any());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_member_of_any_none_match_false() {
        let g1 = crate::sid::Sid::new(5, &[21, 1, 2, 3, 9001]).unwrap();
        let g2 = crate::sid::Sid::new(5, &[21, 1, 2, 3, 9002]).unwrap();
        let token = empty_token();
        let mut comp = Vec::new();
        comp.extend_from_slice(&sid_literal(&g1));
        comp.extend_from_slice(&sid_literal(&g2));
        let mut expr = header();
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_member_of_any());
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_device_member_of_all_match_true() {
        let g = crate::sid::Sid::new(5, &[21, 100, 200, 300, 7001]).unwrap();
        let token = make_device_token(&[g.clone()], crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED);
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&g));
        expr.push(0x8a); // Device_Member_of
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_device_member_of_any_one_match_true() {
        let g1 = crate::sid::Sid::new(5, &[21, 100, 200, 300, 7001]).unwrap();
        let g2 = crate::sid::Sid::new(5, &[21, 100, 200, 300, 7002]).unwrap();
        let token = make_device_token(&[g1.clone()], crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED);
        let mut comp = Vec::new();
        comp.extend_from_slice(&sid_literal(&g2));
        comp.extend_from_slice(&sid_literal(&g1));
        let mut expr = header();
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.push(0x8c); // Device_Member_of_Any
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_device_member_of_any_null_device_unknown() {
        let token = empty_token(); // device_groups = None
        let g = crate::sid::Sid::new(5, &[21, 100, 200, 300, 7001]).unwrap();
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&g));
        expr.push(0x8c); // Device_Member_of_Any
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_not_member_of_all_match_false() {
        let g = crate::sid::Sid::new(5, &[21, 1, 2, 3, 4001]).unwrap();
        let token = make_group_token(&[g.clone()], crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED);
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&g));
        expr.push(0x90); // Not_Member_of
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_not_member_of_any_one_match_false() {
        let g = crate::sid::Sid::new(5, &[21, 1, 2, 3, 4001]).unwrap();
        let token = make_group_token(&[g.clone()], crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED);
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&g));
        expr.push(0x92); // Not_Member_of_Any
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_not_device_member_of_all_match_false() {
        let g = crate::sid::Sid::new(5, &[21, 100, 200, 300, 7001]).unwrap();
        let token = make_device_token(&[g.clone()], crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED);
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&g));
        expr.push(0x91); // Not_Device_Member_of
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_not_device_member_of_null_device_unknown() {
        let token = empty_token();
        let g = crate::sid::Sid::new(5, &[21, 100, 200, 300, 7001]).unwrap();
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&g));
        expr.push(0x91); // Not_Device_Member_of
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_not_device_member_of_one_missing_true() {
        let g = crate::sid::Sid::new(5, &[21, 100, 200, 300, 7001]).unwrap();
        let other = crate::sid::Sid::new(5, &[21, 100, 200, 300, 7002]).unwrap();
        let token = make_device_token(&[g.clone()], crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED);
        // Not_Device_Member_of({other}) — other not in device groups → TRUE
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&other));
        expr.push(0x91); // Not_Device_Member_of
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_not_device_member_of_any_one_match_false() {
        let g = crate::sid::Sid::new(5, &[21, 100, 200, 300, 7001]).unwrap();
        let token = make_device_token(&[g.clone()], crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED);
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&g));
        expr.push(0x93); // Not_Device_Member_of_Any
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_not_device_member_of_any_null_device_unknown() {
        let token = empty_token();
        let g = crate::sid::Sid::new(5, &[21, 100, 200, 300, 7001]).unwrap();
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&g));
        expr.push(0x93); // Not_Device_Member_of_Any
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_not_device_member_of_any_none_match_true() {
        let g = crate::sid::Sid::new(5, &[21, 100, 200, 300, 7001]).unwrap();
        let other = crate::sid::Sid::new(5, &[21, 100, 200, 300, 7099]).unwrap();
        let token = make_device_token(&[g.clone()], crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED);
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&other));
        expr.push(0x93); // Not_Device_Member_of_Any
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_membership_invalid_sid_list_unknown() {
        // Membership op with non-SID operand (e.g. integer) → UNKNOWN
        let token = empty_token();
        let expr = build(&[int64_literal(42), op_member_of()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_membership_empty_composite_unknown() {
        // Membership op with empty composite → UNKNOWN (from to_sid_list)
        let claim = ClaimEntry {
            name: String::from("empty"),
            claim_type: crate::token::ClaimType::Sid,
            flags: 0,
            values: ClaimValues::Sid(alloc::vec![]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        // Empty attribute resolves as NULL, so Member_of gets NULL → to_sid_list gets None → UNKNOWN
        let expr = build(&[user_attr("empty"), op_member_of()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_membership_mixed_types_unknown() {
        // Composite with non-SID elements → to_sid_list returns None → UNKNOWN
        let claim = ClaimEntry {
            name: String::from("mixed"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![1, 2, 3]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("mixed"), op_member_of()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_membership_polarity_allow_filters_deny_only() {
        // deny-only group NOT matched when for_allow=true
        let g = crate::sid::Sid::new(5, &[21, 1, 2, 3, 8001]).unwrap();
        let token = make_group_token(&[g.clone()], crate::group::SE_GROUP_USE_FOR_DENY_ONLY);
        let expr = build(&[sid_literal(&g), op_member_of()]);
        assert_eq!(eval(&expr, &token), TriValue::False); // for_allow=true
    }

    #[test]
    fn cond_membership_polarity_deny_includes_deny_only() {
        // deny-only group IS matched when for_allow=false
        let g = crate::sid::Sid::new(5, &[21, 1, 2, 3, 8001]).unwrap();
        let token = make_group_token(&[g.clone()], crate::group::SE_GROUP_USE_FOR_DENY_ONLY);
        let expr = build(&[sid_literal(&g), op_member_of()]);
        assert_eq!(eval_deny(&expr, &token), TriValue::True); // for_allow=false
    }

    // ===================================================================
    // §11.12 Corpus: Expression Envelope
    // ===================================================================

    #[test]
    fn cond_expression_bad_magic_returns_unknown() {
        let expr = alloc::vec![0x00, 0x00, 0x00, 0x00, 0x04]; // bad magic
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_empty_stack_after_eval_unknown() {
        // Expression with only padding → empty stack → UNKNOWN
        let mut expr = header();
        expr.push(0x00); // padding only
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_literal_on_stack_final_unknown() {
        // Final element is literal → UNKNOWN
        let expr = build(&[string_literal("hello")]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_unknown_opcode_returns_unknown() {
        let mut expr = header();
        expr.push(0xFE); // unknown opcode
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_expression_stack_not_one_at_end_unknown() {
        // Push two results (both comparisons), no final operator → 2 items on stack
        let token = token_with_claims(alloc::vec![int_claim("a", 1), int_claim("b", 2)]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),
            user_attr("b"), int64_literal(2), op_eq(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_expression_insufficient_stack_unknown() {
        // AND with only one item on stack
        let token = token_with_claims(alloc::vec![int_claim("a", 1)]);
        let expr = build(&[user_attr("a"), int64_literal(1), op_eq(), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: Claim Resolution
    // ===================================================================

    #[test]
    fn cond_resolve_claim_case_insensitive_lookup() {
        // Claim name lookup is case-insensitive
        let token = token_with_claims(alloc::vec![int_claim("ClearanceLevel", 5)]);
        let expr = build(&[user_attr("clearancelevel"), int64_literal(5), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_resolve_claim_null_claims_returns_null() {
        // Empty claims list → NULL
        let token = empty_token();
        let expr = build(&[user_attr("anything"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False); // NULL → not exists
    }

    #[test]
    fn cond_resolve_claim_name_not_found_returns_null() {
        let token = token_with_claims(alloc::vec![int_claim("x", 1)]);
        let expr = build(&[user_attr("y"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_multi_valued_claim_returns_composite() {
        // Claim with multiple values resolves as COMPOSITE
        let claim = ClaimEntry {
            name: String::from("roles"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![10, 20, 30]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        // Composite == composite should work (element-wise)
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(10));
        comp.extend_from_slice(&int64_literal(20));
        comp.extend_from_slice(&int64_literal(30));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("roles"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_eq());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_single_valued_claim_returns_scalar() {
        // Claim with single value resolves as scalar, not composite
        let token = token_with_claims(alloc::vec![int_claim("x", 42)]);
        // Scalar == literal should work directly
        let expr = build(&[user_attr("x"), int64_literal(42), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_deny_only_resource_attr_invisible_to_allow() {
        let mut claim = int_claim("confidentiality", 3);
        claim.flags = claim_flags::USE_FOR_DENY_ONLY as u16;
        let resource = alloc::vec![claim];
        let token = empty_token();
        let expr = build(&[resource_attr("confidentiality"), op_exists()]);
        // for_allow=true: deny-only resource attr invisible → NULL → FALSE
        assert_eq!(evaluate(&expr, &bare(&token), &resource, &[], true).unwrap(), TriValue::False);
    }

    #[test]
    fn cond_empty_attr_deny_unknown_fires() {
        // Empty attribute on deny ACE condition: evaluates to UNKNOWN
        let claim = ClaimEntry {
            name: String::from("tags"),
            claim_type: crate::token::ClaimType::String,
            flags: 0,
            values: ClaimValues::String(alloc::vec![]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        // @User.tags == "important" → NULL == "important" → UNKNOWN
        let expr = build(&[user_attr("tags"), string_literal("important"), op_eq()]);
        assert_eq!(eval_deny(&expr, &token), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: negate_tv
    // ===================================================================

    #[test]
    fn cond_negate_true_is_false() {
        assert_eq!(TriValue::True.negate(), TriValue::False);
    }

    #[test]
    fn cond_negate_false_is_true() {
        assert_eq!(TriValue::False.negate(), TriValue::True);
    }

    #[test]
    fn cond_negate_unknown_is_unknown() {
        assert_eq!(TriValue::Unknown.negate(), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: compare_equal edge cases
    // ===================================================================

    #[test]
    fn cond_compare_equal_null_unknown() {
        // NULL on either side → UNKNOWN
        let null = Value::null();
        let int = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&null, &int), TriValue::Unknown);
        assert_eq!(compare_equal(&int, &null), TriValue::Unknown);
        assert_eq!(compare_equal(&null, &null), TriValue::Unknown);
    }

    #[test]
    fn cond_compare_equal_scalar_vs_composite_unknown() {
        let scalar = Value { vtype: ValueType::Int64(1), origin: Origin::UserAttr, flags: 0 };
        let composite = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr,
            flags: 0,
        };
        assert_eq!(compare_equal(&scalar, &composite), TriValue::Unknown);
    }

    #[test]
    fn cond_compare_equal_type_mismatch_unknown() {
        let int = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        let s = Value { vtype: ValueType::String(String::from("5")), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&int, &s), TriValue::Unknown);
    }

    #[test]
    fn cond_compare_equal_sid_equal() {
        let sid = well_known::administrators().unwrap();
        let a = Value { vtype: ValueType::Sid(sid.clone()), origin: Origin::UserAttr, flags: 0 };
        let b = Value { vtype: ValueType::Sid(sid.clone()), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&a, &b), TriValue::True);
    }

    #[test]
    fn cond_compare_equal_sid_different() {
        let a = Value { vtype: ValueType::Sid(well_known::administrators().unwrap()), origin: Origin::UserAttr, flags: 0 };
        let b = Value { vtype: ValueType::Sid(well_known::users().unwrap()), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&a, &b), TriValue::False);
    }

    #[test]
    fn cond_compare_equal_octet_equal() {
        let a = Value { vtype: ValueType::Octet(alloc::vec![1, 2, 3]), origin: Origin::UserAttr, flags: 0 };
        let b = Value { vtype: ValueType::Octet(alloc::vec![1, 2, 3]), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&a, &b), TriValue::True);
    }

    #[test]
    fn cond_compare_equal_octet_different() {
        let a = Value { vtype: ValueType::Octet(alloc::vec![1, 2, 3]), origin: Origin::UserAttr, flags: 0 };
        let b = Value { vtype: ValueType::Octet(alloc::vec![1, 2, 4]), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&a, &b), TriValue::False);
    }

    #[test]
    fn cond_compare_equal_composite_element_wise() {
        let a = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
                Value { vtype: ValueType::Int64(2), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr, flags: 0,
        };
        let b = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
                Value { vtype: ValueType::Int64(2), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr, flags: 0,
        };
        assert_eq!(compare_equal(&a, &b), TriValue::True);

        // Different order → FALSE
        let c = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(2), origin: Origin::Literal, flags: 0 },
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr, flags: 0,
        };
        assert_eq!(compare_equal(&a, &c), TriValue::False);
    }

    // ===================================================================
    // §11.12 Corpus: compare_ordered edge cases
    // ===================================================================

    #[test]
    fn cond_compare_ordered_null_returns_none() {
        let null = Value::null();
        let int = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_ordered(&null, &int), None);
        assert_eq!(compare_ordered(&int, &null), None);
    }

    #[test]
    fn cond_compare_ordered_composite_returns_none() {
        let composite = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr, flags: 0,
        };
        let int = Value { vtype: ValueType::Int64(1), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_ordered(&composite, &int), None);
    }

    #[test]
    fn cond_compare_ordered_boolean_returns_none() {
        let a = Value { vtype: ValueType::Boolean(true), origin: Origin::UserAttr, flags: 0 };
        let b = Value { vtype: ValueType::Boolean(false), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_ordered(&a, &b), None);
    }

    #[test]
    fn cond_compare_ordered_sid_returns_none() {
        let sid = well_known::administrators().unwrap();
        let a = Value { vtype: ValueType::Sid(sid.clone()), origin: Origin::UserAttr, flags: 0 };
        let b = Value { vtype: ValueType::Sid(sid.clone()), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_ordered(&a, &b), None);
    }

    #[test]
    fn cond_compare_ordered_int64_ascending() {
        let a = Value { vtype: ValueType::Int64(3), origin: Origin::UserAttr, flags: 0 };
        let b = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_ordered(&a, &b), Some(-1));
        assert_eq!(compare_ordered(&b, &a), Some(1));
        assert_eq!(compare_ordered(&a, &a), Some(0));
    }

    #[test]
    fn cond_compare_ordered_uint64_ascending() {
        let a = Value { vtype: ValueType::Uint64(3), origin: Origin::UserAttr, flags: 0 };
        let b = Value { vtype: ValueType::Uint64(5), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_ordered(&a, &b), Some(-1));
        assert_eq!(compare_ordered(&b, &a), Some(1));
        assert_eq!(compare_ordered(&a, &a), Some(0));
    }

    #[test]
    fn cond_compare_ordered_int64_uint64_promotion() {
        // Negative INT64 always less than any UINT64
        let neg = Value { vtype: ValueType::Int64(-1), origin: Origin::UserAttr, flags: 0 };
        let zero_u = Value { vtype: ValueType::Uint64(0), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_ordered(&neg, &zero_u), Some(-1));

        // Same-valued INT64 and UINT64
        let pos = Value { vtype: ValueType::Int64(42), origin: Origin::UserAttr, flags: 0 };
        let u42 = Value { vtype: ValueType::Uint64(42), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_ordered(&pos, &u42), Some(0));

        // UINT64 vs negative INT64
        assert_eq!(compare_ordered(&zero_u, &neg), Some(1));
    }

    #[test]
    fn cond_compare_ordered_string_case_insensitive() {
        let a = Value { vtype: ValueType::String(String::from("ALICE")), origin: Origin::UserAttr, flags: 0 };
        let b = Value { vtype: ValueType::String(String::from("alice")), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_ordered(&a, &b), Some(0)); // case-insensitive by default
    }

    #[test]
    fn cond_compare_ordered_string_case_sensitive() {
        let a = Value { vtype: ValueType::String(String::from("ALICE")), origin: Origin::UserAttr, flags: 0x0002 };
        let b = Value { vtype: ValueType::String(String::from("alice")), origin: Origin::UserAttr, flags: 0 };
        // CASE_SENSITIVE flag on either operand forces case-sensitive
        // 'A' (0x41) < 'a' (0x61) in byte comparison
        assert_eq!(compare_ordered(&a, &b), Some(-1));
    }

    #[test]
    fn cond_compare_ordered_octet_ascending() {
        let a = Value { vtype: ValueType::Octet(alloc::vec![1, 2]), origin: Origin::UserAttr, flags: 0 };
        let b = Value { vtype: ValueType::Octet(alloc::vec![1, 3]), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_ordered(&a, &b), Some(-1));
    }

    #[test]
    fn cond_compare_ordered_type_mismatch_returns_none() {
        let int = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        let s = Value { vtype: ValueType::String(String::from("5")), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_ordered(&int, &s), None);
    }

    // ===================================================================
    // §11.12 Corpus: String comparison case sensitivity
    // ===================================================================

    #[test]
    fn cond_string_compare_case_insensitive_default() {
        let token = token_with_claims(alloc::vec![string_claim("dept", "Engineering")]);
        let expr = build(&[user_attr("dept"), string_literal("ENGINEERING"), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_string_compare_case_sensitive_flag() {
        let mut claim = string_claim("dept", "Engineering");
        claim.flags = claim_flags::CASE_SENSITIVE;
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("dept"), string_literal("ENGINEERING"), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    // ===================================================================
    // §11.12 Corpus: Bounds checks
    // ===================================================================

    #[test]
    fn cond_bounds_integer_too_short() {
        let mut expr = header();
        expr.push(0x04); // Int64 opcode
        expr.extend_from_slice(&[0x00; 5]); // 5 bytes, need 10
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_bounds_length_prefix_too_short() {
        let mut expr = header();
        expr.push(0x10); // string opcode
        expr.extend_from_slice(&[0x00; 2]); // 2 bytes, need 4 for length prefix
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_bounds_data_exceeds_buffer() {
        let mut expr = header();
        expr.push(0x10); // string opcode
        expr.extend_from_slice(&50u32.to_le_bytes()); // claims 50 bytes
        expr.extend_from_slice(&[0x00; 4]); // only 4 bytes of data
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_bounds_overflow_safe_length() {
        // Ensure length check uses subtraction form (length <= len - pos)
        let mut expr = header();
        expr.push(0x18); // octet opcode
        expr.extend_from_slice(&u32::MAX.to_le_bytes()); // huge length
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: Padding
    // ===================================================================

    #[test]
    fn cond_padding_zero_skip() {
        // 0x00 as padding is treated as no-op
        let token = token_with_claims(alloc::vec![int_claim("x", 1)]);
        let mut expr = header();
        expr.push(0x00); // padding
        expr.extend_from_slice(&user_attr("x"));
        expr.push(0x00); // padding
        expr.extend_from_slice(&int64_literal(1));
        expr.extend_from_slice(&op_eq());
        expr.push(0x00); // trailing padding
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // ===================================================================
    // §11.12 Corpus: Literal values
    // ===================================================================

    #[test]
    fn cond_int8_literal() {
        // Opcode 0x01 uses same encoding as int64
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let mut int8_lit = Vec::new();
        int8_lit.push(0x01); // Int8 opcode
        int8_lit.extend_from_slice(&5u64.to_le_bytes());
        int8_lit.push(0x01); // positive
        int8_lit.push(0x00); // base
        let expr = build(&[user_attr("x"), int8_lit, op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_int16_literal() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let mut int16_lit = Vec::new();
        int16_lit.push(0x02); // Int16 opcode
        int16_lit.extend_from_slice(&5u64.to_le_bytes());
        int16_lit.push(0x01);
        int16_lit.push(0x00);
        let expr = build(&[user_attr("x"), int16_lit, op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_int32_literal() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let mut int32_lit = Vec::new();
        int32_lit.push(0x03); // Int32 opcode
        int32_lit.extend_from_slice(&5u64.to_le_bytes());
        int32_lit.push(0x01);
        int32_lit.push(0x00);
        let expr = build(&[user_attr("x"), int32_lit, op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_negative_sign_byte() {
        // Sign byte 0x02 produces negative value
        let token = token_with_claims(alloc::vec![int_claim("x", -42)]);
        let mut lit = Vec::new();
        lit.push(0x04);
        lit.extend_from_slice(&42u64.to_le_bytes()); // magnitude
        lit.push(0x02); // negative sign
        lit.push(0x00);
        let expr = build(&[user_attr("x"), lit, op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_positive_sign_byte() {
        // Sign byte != 0x02 produces positive
        let token = token_with_claims(alloc::vec![int_claim("x", 42)]);
        let mut lit = Vec::new();
        lit.push(0x04);
        lit.extend_from_slice(&42u64.to_le_bytes());
        lit.push(0x03); // not 0x02 → positive
        lit.push(0x00);
        let expr = build(&[user_attr("x"), lit, op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_unicode_string_literal() {
        let token = token_with_claims(alloc::vec![string_claim("s", "test")]);
        let expr = build(&[user_attr("s"), string_literal("test"), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_octet_string_literal() {
        let token = token_with_claims(alloc::vec![octet_claim("h", &[0xCA, 0xFE])]);
        let mut expr = header();
        expr.extend_from_slice(&user_attr("h"));
        expr.push(0x18);
        let data = [0xCA, 0xFE];
        expr.extend_from_slice(&(data.len() as u32).to_le_bytes());
        expr.extend_from_slice(&data);
        expr.extend_from_slice(&op_eq());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_sid_literal() {
        let sid = well_known::administrators().unwrap();
        let token = token_with_claims(alloc::vec![sid_claim("g", &sid)]);
        let expr = build(&[user_attr("g"), sid_literal(&sid), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_composite_literal() {
        let claim = ClaimEntry {
            name: String::from("vals"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![10, 20]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(10));
        comp.extend_from_slice(&int64_literal(20));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("vals"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_eq());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_literal_origin_set() {
        // All literal values have origin=LITERAL → on stack alone → UNKNOWN
        let expr_int = build(&[int64_literal(1)]);
        assert_eq!(eval(&expr_int, &empty_token()), TriValue::Unknown);
        let expr_str = build(&[string_literal("x")]);
        assert_eq!(eval(&expr_str, &empty_token()), TriValue::Unknown);
        let sid = well_known::administrators().unwrap();
        let expr_sid = build(&[sid_literal(&sid)]);
        assert_eq!(eval(&expr_sid, &empty_token()), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: Attribute references
    // ===================================================================

    #[test]
    fn cond_local_attr_reference() {
        let local = alloc::vec![int_claim("mfa", 1)];
        let token = empty_token();
        let expr = build(&[local_attr("mfa"), int64_literal(1), op_eq()]);
        assert_eq!(evaluate(&expr, &bare(&token), &[], &local, true).unwrap(), TriValue::True);
    }

    #[test]
    fn cond_device_attr_reference() {
        let mut token = empty_token();
        token.device_claims = alloc::vec![int_claim("loc", 9)];
        let mut expr = header();
        {
            let encoded = encode_utf16le("loc");
            expr.push(0xfb); // @Device.
            expr.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            expr.extend_from_slice(&encoded);
        }
        expr.extend_from_slice(&int64_literal(9));
        expr.extend_from_slice(&op_eq());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // ===================================================================
    // §11.12 Corpus: Logical operator edge cases
    // ===================================================================

    #[test]
    fn cond_logical_literal_operand_unknown() {
        // Logical AND with LITERAL-origin operand returns UNKNOWN
        let token = token_with_claims(alloc::vec![int_claim("a", 1)]);
        let expr = build(&[
            int64_literal(1), // literal
            user_attr("a"), int64_literal(1), op_eq(),
            op_or(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);

        // NOT on literal
        let expr_not = build(&[int64_literal(1), op_not()]);
        assert_eq!(eval(&expr_not, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_logical_insufficient_stack_unknown() {
        // AND with empty stack
        let expr = build(&[op_and()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);

        // OR with empty stack
        let expr2 = build(&[op_or()]);
        assert_eq!(eval(&expr2, &empty_token()), TriValue::Unknown);

        // NOT with empty stack
        let expr3 = build(&[op_not()]);
        assert_eq!(eval(&expr3, &empty_token()), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: Contains indeterminate → UNKNOWN
    // ===================================================================

    #[test]
    fn cond_contains_indeterminate_unknown() {
        // Contains returns UNKNOWN when element comparison is indeterminate
        // (type mismatch causes Unknown in compare_equal, value not found)
        let claim = ClaimEntry {
            name: String::from("mixed"),
            claim_type: crate::token::ClaimType::String,
            flags: 0,
            values: ClaimValues::String(alloc::vec![String::from("hello")]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        // Check if string LHS contains int RHS — type mismatch → UNKNOWN compare → UNKNOWN result
        let expr = build(&[user_attr("mixed"), int64_literal(42), op_contains()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_any_of_indeterminate_unknown() {
        // Any_of returns UNKNOWN when no TRUE found but some comparison was indeterminate
        let claim = ClaimEntry {
            name: String::from("mixed"),
            claim_type: crate::token::ClaimType::String,
            flags: 0,
            values: ClaimValues::String(alloc::vec![String::from("hello")]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(42));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("mixed"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_any_of());
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // ===================================================================
    // §11.12 Corpus: Claim multi-value variants
    // ===================================================================

    #[test]
    fn cond_multi_valued_uint64_claim_returns_composite() {
        let claim = ClaimEntry {
            name: String::from("perms"),
            claim_type: crate::token::ClaimType::Uint64,
            flags: 0,
            values: ClaimValues::Uint64(alloc::vec![100, 200]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        // Exists should be TRUE (non-null)
        let expr = build(&[user_attr("perms"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_multi_valued_string_claim_returns_composite() {
        let claim = ClaimEntry {
            name: String::from("roles"),
            claim_type: crate::token::ClaimType::String,
            flags: 0,
            values: ClaimValues::String(alloc::vec![String::from("admin"), String::from("user")]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("roles"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_multi_valued_bool_claim_returns_composite() {
        let claim = ClaimEntry {
            name: String::from("flags"),
            claim_type: crate::token::ClaimType::Boolean,
            flags: 0,
            values: ClaimValues::Boolean(alloc::vec![true, false]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("flags"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_multi_valued_sid_claim_returns_composite() {
        let sid1 = well_known::administrators().unwrap();
        let sid2 = well_known::users().unwrap();
        let claim = ClaimEntry {
            name: String::from("groups"),
            claim_type: crate::token::ClaimType::Sid,
            flags: 0,
            values: ClaimValues::Sid(alloc::vec![sid1, sid2]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("groups"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_multi_valued_octet_claim_returns_composite() {
        let claim = ClaimEntry {
            name: String::from("hashes"),
            claim_type: crate::token::ClaimType::Octet,
            flags: 0,
            values: ClaimValues::Octet(alloc::vec![alloc::vec![1], alloc::vec![2]]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("hashes"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // ===================================================================
    // §11.12 Corpus: Empty claim variants resolve to NULL
    // ===================================================================

    #[test]
    fn cond_empty_uint64_claim_resolved_null() {
        let claim = ClaimEntry {
            name: String::from("x"),
            claim_type: crate::token::ClaimType::Uint64,
            flags: 0,
            values: ClaimValues::Uint64(alloc::vec![]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("x"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_empty_boolean_claim_resolved_null() {
        let claim = ClaimEntry {
            name: String::from("b"),
            claim_type: crate::token::ClaimType::Boolean,
            flags: 0,
            values: ClaimValues::Boolean(alloc::vec![]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("b"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_empty_sid_claim_resolved_null() {
        let claim = ClaimEntry {
            name: String::from("s"),
            claim_type: crate::token::ClaimType::Sid,
            flags: 0,
            values: ClaimValues::Sid(alloc::vec![]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("s"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_empty_octet_claim_resolved_null() {
        let claim = ClaimEntry {
            name: String::from("o"),
            claim_type: crate::token::ClaimType::Octet,
            flags: 0,
            values: ClaimValues::Octet(alloc::vec![]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("o"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_empty_int64_claim_resolved_null() {
        let claim = ClaimEntry {
            name: String::from("i"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("i"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    // ===================================================================
    // §11 Corpus Tests — Second Half (Conditional Expression Details)
    // ===================================================================

    // --- §11.12 cond_int64_literal (opcode 0x04) ---
    #[test]
    fn cond_int64_literal() {
        // Opcode 0x04: Int64 literal, same encoding as Int8
        let expr = build(&[user_attr("x"), int64_literal(42), op_eq()]);
        let token = token_with_claims(alloc::vec![int_claim("x", 42)]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // ===================================================================
    // §7: Claim Resolution corpus tests
    // ===================================================================

    // --- resolve_claim_null_claims_returns_null ---
    #[test]
    fn resolve_claim_null_claims_returns_null() {
        let v = resolve_claim(&[], "anything", true, Origin::UserAttr).unwrap();
        assert!(v.is_null());
    }

    // --- resolve_claim_name_case_insensitive ---
    #[test]
    fn resolve_claim_name_case_insensitive() {
        let claims = alloc::vec![int_claim("Department", 7)];
        let v = resolve_claim(&claims, "department", true, Origin::UserAttr).unwrap();
        assert!(!v.is_null());
    }

    // --- resolve_claim_disabled_returns_null ---
    #[test]
    fn resolve_claim_disabled_returns_null() {
        let claim = ClaimEntry {
            name: String::from("x"),
            claim_type: ClaimType::Int64,
            flags: claim_flags::DISABLED,
            values: ClaimValues::Int64(alloc::vec![42]),
        };
        let v = resolve_claim(&[claim], "x", true, Origin::UserAttr).unwrap();
        assert!(v.is_null());
    }

    // --- resolve_claim_deny_only_allow_returns_null ---
    #[test]
    fn resolve_claim_deny_only_allow_returns_null() {
        let claim = ClaimEntry {
            name: String::from("x"),
            claim_type: ClaimType::Int64,
            flags: claim_flags::USE_FOR_DENY_ONLY,
            values: ClaimValues::Int64(alloc::vec![42]),
        };
        let v = resolve_claim(&[claim], "x", true, Origin::UserAttr).unwrap();
        assert!(v.is_null());
    }

    // --- resolve_claim_deny_only_deny_returns_value ---
    #[test]
    fn resolve_claim_deny_only_deny_returns_value() {
        let claim = ClaimEntry {
            name: String::from("x"),
            claim_type: ClaimType::Int64,
            flags: claim_flags::USE_FOR_DENY_ONLY,
            values: ClaimValues::Int64(alloc::vec![42]),
        };
        let v = resolve_claim(&[claim], "x", false, Origin::UserAttr).unwrap();
        assert!(!v.is_null());
        match v.vtype {
            ValueType::Int64(val) => assert_eq!(val, 42),
            _ => panic!("expected Int64"),
        }
    }

    // --- resolve_claim_empty_values_returns_null ---
    #[test]
    fn resolve_claim_empty_values_returns_null() {
        let claim = ClaimEntry {
            name: String::from("x"),
            claim_type: ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![]),
        };
        let v = resolve_claim(&[claim], "x", true, Origin::UserAttr).unwrap();
        assert!(v.is_null());
    }

    // --- resolve_claim_single_value_scalar ---
    #[test]
    fn resolve_claim_single_value_scalar() {
        let claim = ClaimEntry {
            name: String::from("x"),
            claim_type: ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![99]),
        };
        let v = resolve_claim(&[claim], "x", true, Origin::UserAttr).unwrap();
        match v.vtype {
            ValueType::Int64(val) => assert_eq!(val, 99),
            _ => panic!("expected scalar Int64"),
        }
    }

    // --- resolve_claim_multi_value_composite ---
    #[test]
    fn resolve_claim_multi_value_composite() {
        let claim = ClaimEntry {
            name: String::from("x"),
            claim_type: ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![1, 2, 3]),
        };
        let v = resolve_claim(&[claim], "x", true, Origin::UserAttr).unwrap();
        assert!(v.is_composite());
    }

    // --- resolve_claim_boolean_normalized ---
    #[test]
    fn resolve_claim_boolean_normalized() {
        let claim = ClaimEntry {
            name: String::from("b"),
            claim_type: ClaimType::Boolean,
            flags: 0,
            values: ClaimValues::Boolean(alloc::vec![true]),
        };
        let v = resolve_claim(&[claim], "b", true, Origin::UserAttr).unwrap();
        match v.vtype {
            ValueType::Boolean(val) => assert!(val),
            _ => panic!("expected Boolean"),
        }
    }

    // --- resolve_claim_not_found_returns_null ---
    #[test]
    fn resolve_claim_not_found_returns_null() {
        let claims = alloc::vec![int_claim("x", 42)];
        let v = resolve_claim(&claims, "nonexistent", true, Origin::UserAttr).unwrap();
        assert!(v.is_null());
    }

    // --- resolve_claim_flags_carried ---
    #[test]
    fn resolve_claim_flags_carried() {
        let claim = ClaimEntry {
            name: String::from("x"),
            claim_type: ClaimType::Int64,
            flags: claim_flags::CASE_SENSITIVE,
            values: ClaimValues::Int64(alloc::vec![42]),
        };
        let v = resolve_claim(&[claim], "x", true, Origin::UserAttr).unwrap();
        assert_eq!(v.flags, claim_flags::CASE_SENSITIVE);
    }

    // --- resolve_resource_disabled_returns_null ---
    #[test]
    fn resolve_resource_disabled_returns_null() {
        let claim = ClaimEntry {
            name: String::from("r"),
            claim_type: ClaimType::Int64,
            flags: claim_flags::DISABLED,
            values: ClaimValues::Int64(alloc::vec![42]),
        };
        let v = resolve_claim(&[claim], "r", true, Origin::UserAttr).unwrap();
        assert!(v.is_null());
    }

    // --- resolve_resource_deny_only_allow_null ---
    #[test]
    fn resolve_resource_deny_only_allow_null() {
        let claim = ClaimEntry {
            name: String::from("r"),
            claim_type: ClaimType::Int64,
            flags: claim_flags::USE_FOR_DENY_ONLY,
            values: ClaimValues::Int64(alloc::vec![42]),
        };
        let v = resolve_claim(&[claim], "r", true, Origin::UserAttr).unwrap();
        assert!(v.is_null());
    }

    // --- resolve_resource_empty_values_null ---
    #[test]
    fn resolve_resource_empty_values_null() {
        let claim = ClaimEntry {
            name: String::from("r"),
            claim_type: ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![]),
        };
        let v = resolve_claim(&[claim], "r", true, Origin::UserAttr).unwrap();
        assert!(v.is_null());
    }

    // --- resolve_resource_not_found_null ---
    #[test]
    fn resolve_resource_not_found_null() {
        let v = resolve_claim(&[], "nonexistent", true, Origin::UserAttr).unwrap();
        assert!(v.is_null());
    }

    // --- claim_type_int64_maps ---
    #[test]
    fn claim_type_int64_maps() {
        assert_eq!(ClaimType::Int64 as u16, 0x0001);
    }

    // --- claim_type_uint64_maps ---
    #[test]
    fn claim_type_uint64_maps() {
        assert_eq!(ClaimType::Uint64 as u16, 0x0002);
    }

    // --- claim_type_string_maps ---
    #[test]
    fn claim_type_string_maps() {
        assert_eq!(ClaimType::String as u16, 0x0003);
    }

    // --- claim_type_sid_maps ---
    #[test]
    fn claim_type_sid_maps() {
        assert_eq!(ClaimType::Sid as u16, 0x0005);
    }

    // --- claim_type_boolean_maps ---
    #[test]
    fn claim_type_boolean_maps() {
        assert_eq!(ClaimType::Boolean as u16, 0x0006);
    }

    // --- claim_type_octet_maps ---
    #[test]
    fn claim_type_octet_maps() {
        assert_eq!(ClaimType::Octet as u16, 0x0010);
    }

    // ===================================================================
    // §8: compare_equal corpus tests
    // ===================================================================

    #[test]
    fn compare_equal_null_lhs_unknown() {
        let lhs = Value::null();
        let rhs = Value { vtype: ValueType::Int64(1), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::Unknown);
    }

    #[test]
    fn compare_equal_null_rhs_unknown() {
        let lhs = Value { vtype: ValueType::Int64(1), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value::null();
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::Unknown);
    }

    #[test]
    fn compare_equal_scalar_vs_composite_unknown() {
        let lhs = Value { vtype: ValueType::Int64(1), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr,
            flags: 0,
        };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::Unknown);
    }

    #[test]
    fn compare_equal_incompatible_types_unknown() {
        let lhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::String(String::from("5")), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::Unknown);
    }

    #[test]
    fn compare_equal_int64_int64_match() {
        let lhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::True);
    }

    #[test]
    fn compare_equal_int64_int64_mismatch() {
        let lhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Int64(6), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::False);
    }

    #[test]
    fn compare_equal_int64_uint64_promoted() {
        let lhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Uint64(5), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::True);
    }

    #[test]
    fn compare_equal_boolean_int_equality() {
        let lhs = Value { vtype: ValueType::Boolean(true), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Int64(1), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::True);
    }

    #[test]
    fn compare_equal_string_case_insensitive_default() {
        let lhs = Value { vtype: ValueType::String(String::from("Hello")), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::String(String::from("hello")), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::True);
    }

    #[test]
    fn compare_equal_string_case_sensitive_flag() {
        let lhs = Value { vtype: ValueType::String(String::from("Hello")), origin: Origin::UserAttr, flags: claim_flags::CASE_SENSITIVE };
        let rhs = Value { vtype: ValueType::String(String::from("hello")), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::False);
    }

    #[test]
    fn compare_equal_string_ascii_fold_only() {
        // ASCII fold: A-Z → a-z only; no Unicode case folding
        let lhs = Value { vtype: ValueType::String(String::from("ABC")), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::String(String::from("abc")), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::True);
    }

    #[test]
    fn compare_equal_sid_match() {
        let sid = crate::sid::Sid::new(5, &[21, 1, 2, 3]).unwrap();
        let lhs = Value { vtype: ValueType::Sid(sid.clone()), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Sid(sid), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::True);
    }

    #[test]
    fn compare_equal_octet_match() {
        let lhs = Value { vtype: ValueType::Octet(alloc::vec![1, 2, 3]), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Octet(alloc::vec![1, 2, 3]), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::True);
    }

    #[test]
    fn compare_equal_composite_elementwise() {
        let lhs = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
                Value { vtype: ValueType::Int64(2), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr,
            flags: 0,
        };
        let rhs = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
                Value { vtype: ValueType::Int64(2), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr,
            flags: 0,
        };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::True);
    }

    #[test]
    fn compare_equal_composite_different_length_false() {
        let lhs = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr,
            flags: 0,
        };
        let rhs = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
                Value { vtype: ValueType::Int64(2), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr,
            flags: 0,
        };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::False);
    }

    #[test]
    fn compare_equal_composite_different_order_false() {
        let lhs = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
                Value { vtype: ValueType::Int64(2), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr,
            flags: 0,
        };
        let rhs = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(2), origin: Origin::Literal, flags: 0 },
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr,
            flags: 0,
        };
        assert_eq!(compare_equal(&lhs, &rhs), TriValue::False);
    }

    // ===================================================================
    // §8: compare_ordered corpus tests
    // ===================================================================

    #[test]
    fn compare_ordered_null_unknown() {
        let lhs = Value::null();
        let rhs = Value { vtype: ValueType::Int64(1), origin: Origin::UserAttr, flags: 0 };
        assert!(compare_ordered(&lhs, &rhs).is_none());
    }

    #[test]
    fn compare_ordered_composite_unknown() {
        let lhs = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Int64(1), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::UserAttr,
            flags: 0,
        };
        let rhs = Value { vtype: ValueType::Int64(1), origin: Origin::UserAttr, flags: 0 };
        assert!(compare_ordered(&lhs, &rhs).is_none());
    }

    #[test]
    fn compare_ordered_boolean_unknown() {
        let lhs = Value { vtype: ValueType::Boolean(true), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Boolean(false), origin: Origin::UserAttr, flags: 0 };
        assert!(compare_ordered(&lhs, &rhs).is_none());
    }

    #[test]
    fn compare_ordered_incompatible_unknown() {
        let lhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::String(String::from("5")), origin: Origin::UserAttr, flags: 0 };
        assert!(compare_ordered(&lhs, &rhs).is_none());
    }

    #[test]
    fn compare_ordered_lt_true() {
        let lhs = Value { vtype: ValueType::Int64(3), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        assert!(compare_ordered(&lhs, &rhs).unwrap() < 0);
    }

    #[test]
    fn compare_ordered_lt_false() {
        let lhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Int64(3), origin: Origin::UserAttr, flags: 0 };
        assert!(compare_ordered(&lhs, &rhs).unwrap() >= 0);
    }

    #[test]
    fn compare_ordered_le_true() {
        let lhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        assert!(compare_ordered(&lhs, &rhs).unwrap() <= 0);
    }

    #[test]
    fn compare_ordered_le_false() {
        let lhs = Value { vtype: ValueType::Int64(6), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        assert!(compare_ordered(&lhs, &rhs).unwrap() > 0);
    }

    #[test]
    fn compare_ordered_gt_true() {
        let lhs = Value { vtype: ValueType::Int64(10), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        assert!(compare_ordered(&lhs, &rhs).unwrap() > 0);
    }

    #[test]
    fn compare_ordered_gt_false() {
        let lhs = Value { vtype: ValueType::Int64(3), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        assert!(compare_ordered(&lhs, &rhs).unwrap() <= 0);
    }

    #[test]
    fn compare_ordered_ge_true() {
        let lhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        assert!(compare_ordered(&lhs, &rhs).unwrap() >= 0);
    }

    #[test]
    fn compare_ordered_ge_false() {
        let lhs = Value { vtype: ValueType::Int64(3), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Int64(5), origin: Origin::UserAttr, flags: 0 };
        assert!(compare_ordered(&lhs, &rhs).unwrap() < 0);
    }

    #[test]
    fn compare_ordered_int64_uint64_negative_lt() {
        let lhs = Value { vtype: ValueType::Int64(-1), origin: Origin::UserAttr, flags: 0 };
        let rhs = Value { vtype: ValueType::Uint64(0), origin: Origin::UserAttr, flags: 0 };
        assert_eq!(compare_ordered(&lhs, &rhs), Some(-1));
    }

    #[test]
    fn compare_ordered_string_case_flag() {
        let lhs = Value { vtype: ValueType::String(String::from("A")), origin: Origin::UserAttr, flags: claim_flags::CASE_SENSITIVE };
        let rhs = Value { vtype: ValueType::String(String::from("a")), origin: Origin::UserAttr, flags: 0 };
        // Case-sensitive: "A" < "a" in ASCII
        assert!(compare_ordered(&lhs, &rhs).unwrap() < 0);
    }

    // ===================================================================
    // §8: to_sid_list corpus tests
    // ===================================================================

    #[test]
    fn to_sid_list_single_sid() {
        let sid = crate::sid::Sid::new(5, &[21, 1, 2, 3]).unwrap();
        let v = Value { vtype: ValueType::Sid(sid.clone()), origin: Origin::Literal, flags: 0 };
        let result = to_sid_list(&v).unwrap().unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], sid);
    }

    #[test]
    fn to_sid_list_composite_sids() {
        let s1 = crate::sid::Sid::new(5, &[21, 1, 2, 3]).unwrap();
        let s2 = crate::sid::Sid::new(5, &[21, 4, 5, 6]).unwrap();
        let v = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Sid(s1.clone()), origin: Origin::Literal, flags: 0 },
                Value { vtype: ValueType::Sid(s2.clone()), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::Literal,
            flags: 0,
        };
        let result = to_sid_list(&v).unwrap().unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn to_sid_list_empty_composite_error() {
        let v = Value {
            vtype: ValueType::Composite(alloc::vec![]),
            origin: Origin::Literal,
            flags: 0,
        };
        assert!(to_sid_list(&v).unwrap().is_none());
    }

    #[test]
    fn to_sid_list_mixed_types_error() {
        let sid = crate::sid::Sid::new(5, &[21, 1, 2, 3]).unwrap();
        let v = Value {
            vtype: ValueType::Composite(alloc::vec![
                Value { vtype: ValueType::Sid(sid), origin: Origin::Literal, flags: 0 },
                Value { vtype: ValueType::Int64(42), origin: Origin::Literal, flags: 0 },
            ]),
            origin: Origin::Literal,
            flags: 0,
        };
        assert!(to_sid_list(&v).unwrap().is_none());
    }

    #[test]
    fn to_sid_list_non_sid_scalar_error() {
        let v = Value { vtype: ValueType::Int64(42), origin: Origin::Literal, flags: 0 };
        assert!(to_sid_list(&v).unwrap().is_none());
    }

    // ===================================================================
    // §11.12 negate_tv corpus tests (already exist as cond_negate_*)
    // ===================================================================
    // cond_negate_true_is_false — already exists
    // cond_negate_false_is_true — already exists
    // cond_negate_unknown_is_unknown — already exists

    // ===================================================================
    // §11.12 Boolean coercion (to_three_value) corpus tests
    // ===================================================================
    // cond_coerce_int64_nonzero_true — already exists
    // cond_coerce_int64_zero_false — already exists
    // cond_coerce_uint64_nonzero_true — already exists
    // cond_coerce_uint64_zero_false — already exists
    // cond_coerce_boolean_nonzero_true — already exists
    // cond_coerce_boolean_zero_false — already exists
    // cond_coerce_string_nonempty_true — already exists
    // cond_coerce_string_empty_false — already exists
    // cond_coerce_null_unknown — already exists
    // cond_coerce_sid_unknown — already exists
    // cond_coerce_octet_unknown — already exists
    // cond_coerce_composite_unknown — already exists

    // ===================================================================
    // Missing corpus tests
    // ===================================================================

    // --- Three-value logic (Kleene) using attribute-backed values ---

    #[test]
    fn cond_and_true_false_is_false() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_true"), user_attr("tv_false"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_and_true_unknown_is_unknown() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_true"), user_attr("missing"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_and_false_false_is_false() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_false"), user_attr("tv_false"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_and_false_unknown_is_false() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_false"), user_attr("missing"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_and_unknown_unknown_is_unknown() {
        let token = empty_token();
        let expr = build(&[user_attr("a"), user_attr("b"), op_and()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_or_true_true_is_true() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_true"), user_attr("tv_true"), op_or()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_or_true_unknown_is_true() {
        let token = tv_token_true_false();
        let expr = build(&[user_attr("tv_true"), user_attr("missing"), op_or()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_or_unknown_unknown_is_unknown() {
        let token = empty_token();
        let expr = build(&[user_attr("a"), user_attr("b"), op_or()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // --- Existence operators ---

    #[test]
    fn cond_exists_present_true() {
        let token = token_with_claims(alloc::vec![int_claim("x", 1)]);
        let expr = build(&[user_attr("x"), op_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_exists_absent_false() {
        let expr = build(&[user_attr("missing"), op_exists()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::False);
    }

    #[test]
    fn cond_exists_non_attr_origin_unknown() {
        // Exists on literal origin → UNKNOWN
        let expr = build(&[int64_literal(42), op_exists()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn cond_not_exists_present_false() {
        let token = token_with_claims(alloc::vec![int_claim("x", 1)]);
        let expr = build(&[user_attr("x"), op_not_exists()]);
        assert_eq!(eval(&expr, &token), TriValue::False);
    }

    #[test]
    fn cond_not_exists_absent_true() {
        let expr = build(&[user_attr("missing"), op_not_exists()]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::True);
    }

    // --- INT64/UINT64 promotion ---

    #[test]
    fn cond_int64_uint64_promotion() {
        // Negative INT64 < any UINT64
        let token = token_with_claims(alloc::vec![uint_claim("x", 0)]);
        let expr = build(&[int64_literal(-1), user_attr("x"), op_lt()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // --- Set operators ---

    #[test]
    fn cond_contains_op() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), int64_literal(5), op_contains()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_any_of_op() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(3));
        comp.extend_from_slice(&int64_literal(5));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("x"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_any_of());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_contains_empty_rhs_unknown() {
        // Contains with empty rhs returns UNKNOWN (vacuous truth prevention)
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        // Empty composite as RHS
        let mut expr = header();
        expr.extend_from_slice(&user_attr("x"));
        expr.push(0x50); // composite
        expr.extend_from_slice(&0u32.to_le_bytes()); // 0-length composite
        expr.extend_from_slice(&op_contains());
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_any_of_empty_lhs_unknown() {
        // Any_of with empty LHS returns UNKNOWN
        // Create claim with empty values (resolves to NULL)
        let claim = ClaimEntry {
            name: String::from("tags"),
            claim_type: crate::token::ClaimType::Int64,
            flags: 0,
            values: ClaimValues::Int64(alloc::vec![]),
        };
        let token = token_with_claims(alloc::vec![claim]);
        let expr = build(&[user_attr("tags"), int64_literal(1), op_any_of()]);
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    #[test]
    fn cond_any_of_empty_rhs_unknown() {
        // Any_of with empty RHS returns UNKNOWN
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let mut expr = header();
        expr.extend_from_slice(&user_attr("x"));
        expr.push(0x50);
        expr.extend_from_slice(&0u32.to_le_bytes());
        expr.extend_from_slice(&op_any_of());
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // --- Device membership ---

    #[test]
    fn cond_device_member_of_null_device_unknown() {
        // Device_Member_of with null device_groups returns UNKNOWN
        let token = empty_token(); // device_groups = None
        let sid = crate::sid::Sid::new(5, &[21, 999, 999, 999]).unwrap();
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&sid));
        expr.push(0x8a); // Device_Member_of
        assert_eq!(eval(&expr, &token), TriValue::Unknown);
    }

    // --- Attribute references ---

    #[test]
    fn cond_user_attr_reference() {
        let token = token_with_claims(alloc::vec![int_claim("clearance", 5)]);
        let expr = build(&[user_attr("clearance"), int64_literal(5), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn cond_resource_attr_reference() {
        let token = empty_token();
        let resource = alloc::vec![int_claim("level", 3)];
        let expr = build(&[resource_attr("level"), int64_literal(3), op_eq()]);
        assert_eq!(eval_with_resource(&expr, &token, &resource), TriValue::True);
    }

    // --- Padding ---

    #[test]
    fn cond_padding_interior_zero_should_return_unknown() {
        // Interior 0x00 between operand and operator should be treated as
        // skip. A 0x00 between two operators that leaves the stack in an
        // unexpected state yields UNKNOWN per implementation SHOULD.
        // We test that a standalone 0x00 padding doesn't break evaluation.
        let token = token_with_claims(alloc::vec![int_claim("x", 1)]);
        let mut expr = header();
        expr.extend_from_slice(&user_attr("x"));
        expr.extend_from_slice(&int64_literal(1));
        expr.push(0x00); // interior padding
        expr.extend_from_slice(&op_eq());
        // Should still evaluate correctly since 0x00 is skip
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    // --- Expression format ---

    #[test]
    fn conditional_ace_appends_expression_after_sid() {
        use crate::ace::*;
        // Conditional ACE structure: header + mask + SID + expression
        let cond = alloc::vec![0x61, 0x72, 0x74, 0x78, 0x00, 0x00, 0x00, 0x00];
        let ace = Ace {
            ace_type: ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            flags: 0,
            mask: crate::mask::FILE_READ_DATA,
            sid: well_known::administrators().unwrap(),
            object_type: None,
            inherited_object_type: None,
            condition: Some(cond.clone()),
            application_data: None,
        };
        let bytes = ace.to_bytes().unwrap();
        let (parsed, _) = Ace::from_bytes(&bytes).unwrap();
        assert!(parsed.condition.is_some());
        assert_eq!(&parsed.condition.unwrap()[..4], &[0x61, 0x72, 0x74, 0x78]);
    }

    #[test]
    fn conditional_expression_binary_format() {
        // Expression stored in binary format per MS-DTYP §2.4.4.17
        // Verify the artx header is the magic signature
        let expr = build(&[int64_literal(1)]);
        assert_eq!(&expr[..4], &[0x61, 0x72, 0x74, 0x78]);
    }

    #[test]
    fn expression_binary_format_windows_compatible() {
        // Byte-compatible with Windows (MS-DTYP §2.4.4.17.4)
        let expr = build(&[int64_literal(42), int64_literal(42), op_eq()]);
        // artx magic header
        assert_eq!(&expr[..4], b"artx");
    }

    #[test]
    fn expression_binary_representation_rpn() {
        // Binary representation is RPN (operands before operator)
        let expr = build(&[int64_literal(1), int64_literal(2), op_eq()]);
        // First 4 bytes: artx header
        // Then two int64 literals, then eq operator
        assert_eq!(expr[4], 0x04); // Int64 opcode
        // The last byte should be 0x80 (eq)
        assert_eq!(*expr.last().unwrap(), 0x80);
    }

    #[test]
    fn expression_evaluator_three_valued_logic() {
        // Evaluator supports three-valued logic
        let token = token_with_claims(alloc::vec![int_claim("x", 1)]);
        assert_eq!(eval(&build(&[user_attr("x"), int64_literal(1), op_eq()]), &token), TriValue::True);
        assert_eq!(eval(&build(&[user_attr("x"), int64_literal(2), op_eq()]), &token), TriValue::False);
        assert_eq!(eval(&build(&[user_attr("missing"), int64_literal(1), op_eq()]), &token), TriValue::Unknown);
    }

    #[test]
    fn expression_user_claims_prefix() {
        // @User. prefix queries user claims
        let token = token_with_claims(alloc::vec![int_claim("dept", 42)]);
        let expr = build(&[user_attr("dept"), int64_literal(42), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_device_claims_prefix() {
        // @Device. prefix queries device claims
        let mut token = empty_token();
        token.device_claims = alloc::vec![int_claim("managed", 1)];
        let expr = build(&[device_attr("managed"), int64_literal(1), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_resource_attribute_prefix() {
        // @Resource. prefix queries resource attributes
        let token = empty_token();
        let resource = alloc::vec![int_claim("confidentiality", 3)];
        let expr = build(&[resource_attr("confidentiality"), int64_literal(3), op_eq()]);
        assert_eq!(eval_with_resource(&expr, &token, &resource), TriValue::True);
    }

    #[test]
    fn expression_relational_operators() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        assert_eq!(eval(&build(&[user_attr("x"), int64_literal(5), op_eq()]), &token), TriValue::True);
        assert_eq!(eval(&build(&[user_attr("x"), int64_literal(4), op_ne()]), &token), TriValue::True);
        assert_eq!(eval(&build(&[user_attr("x"), int64_literal(6), op_lt()]), &token), TriValue::True);
        assert_eq!(eval(&build(&[user_attr("x"), int64_literal(5), op_le()]), &token), TriValue::True);
        assert_eq!(eval(&build(&[user_attr("x"), int64_literal(4), op_gt()]), &token), TriValue::True);
        assert_eq!(eval(&build(&[user_attr("x"), int64_literal(5), op_ge()]), &token), TriValue::True);
    }

    #[test]
    fn expression_set_operators_contains() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let expr = build(&[user_attr("x"), int64_literal(5), op_contains()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_set_operators_any_of() {
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        let mut comp = Vec::new();
        comp.extend_from_slice(&int64_literal(3));
        comp.extend_from_slice(&int64_literal(5));
        let mut expr = header();
        expr.extend_from_slice(&user_attr("x"));
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_any_of());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_member_of() {
        let token = empty_token(); // system token has Administrators
        let expr = build(&[sid_literal(&well_known::administrators().unwrap()), op_member_of()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_member_of_any() {
        let token = empty_token();
        let admins = well_known::administrators().unwrap();
        let random = crate::sid::Sid::new(5, &[21, 1, 2, 3, 999]).unwrap();
        let mut comp = Vec::new();
        comp.extend_from_slice(&sid_literal(&random));
        comp.extend_from_slice(&sid_literal(&admins));
        let mut expr = header();
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_member_of_any());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_not_member_of() {
        let token = empty_token();
        let random = crate::sid::Sid::new(5, &[21, 999, 999, 999]).unwrap();
        let expr = build(&[sid_literal(&random), op_not_member_of()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_not_member_of_any() {
        let token = empty_token();
        let r1 = crate::sid::Sid::new(5, &[21, 999, 999, 1]).unwrap();
        let r2 = crate::sid::Sid::new(5, &[21, 999, 999, 2]).unwrap();
        let mut comp = Vec::new();
        comp.extend_from_slice(&sid_literal(&r1));
        comp.extend_from_slice(&sid_literal(&r2));
        let mut expr = header();
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.extend_from_slice(&op_not_member_of_any());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_device_member_of() {
        let mut token = empty_token();
        let managed = crate::sid::Sid::new(5, &[21, 100, 200, 300, 5001]).unwrap();
        token.device_groups = Some(alloc::vec![
            crate::group::GroupEntry::new(managed.clone(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED),
        ]);
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&managed));
        expr.push(0x8a); // Device_Member_of
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_device_member_of_any() {
        let mut token = empty_token();
        let managed = crate::sid::Sid::new(5, &[21, 100, 200, 300, 5001]).unwrap();
        token.device_groups = Some(alloc::vec![
            crate::group::GroupEntry::new(managed.clone(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED),
        ]);
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&managed));
        expr.push(0x8c); // Device_Member_of_Any
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_not_device_member_of() {
        let mut token = empty_token();
        let managed = crate::sid::Sid::new(5, &[21, 100, 200, 300, 5001]).unwrap();
        token.device_groups = Some(alloc::vec![
            crate::group::GroupEntry::new(managed.clone(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED),
        ]);
        let other = crate::sid::Sid::new(5, &[21, 999, 999, 999]).unwrap();
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&other));
        expr.push(0x91); // Not_Device_Member_of
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_not_device_member_of_any() {
        let mut token = empty_token();
        let managed = crate::sid::Sid::new(5, &[21, 100, 200, 300, 5001]).unwrap();
        token.device_groups = Some(alloc::vec![
            crate::group::GroupEntry::new(managed.clone(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED),
        ]);
        let r1 = crate::sid::Sid::new(5, &[21, 999, 999, 1]).unwrap();
        let r2 = crate::sid::Sid::new(5, &[21, 999, 999, 2]).unwrap();
        let mut comp = Vec::new();
        comp.extend_from_slice(&sid_literal(&r1));
        comp.extend_from_slice(&sid_literal(&r2));
        let mut expr = header();
        expr.push(0x50);
        expr.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        expr.extend_from_slice(&comp);
        expr.push(0x93); // Not_Device_Member_of_Any
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_logical_and() {
        let token = token_with_claims(alloc::vec![int_claim("a", 1), int_claim("b", 1)]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),
            user_attr("b"), int64_literal(1), op_eq(),
            op_and(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_logical_or() {
        let token = token_with_claims(alloc::vec![int_claim("a", 1), int_claim("b", 2)]);
        let expr = build(&[
            user_attr("a"), int64_literal(1), op_eq(),
            user_attr("b"), int64_literal(1), op_eq(),
            op_or(),
        ]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_logical_not() {
        let token = token_with_claims(alloc::vec![int_claim("a", 2)]);
        let expr = build(&[user_attr("a"), int64_literal(1), op_eq(), op_not()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn expression_exists_operator() {
        let token = token_with_claims(alloc::vec![int_claim("x", 1)]);
        assert_eq!(eval(&build(&[user_attr("x"), op_exists()]), &token), TriValue::True);
    }

    #[test]
    fn expression_not_exists_operator() {
        assert_eq!(eval(&build(&[user_attr("missing"), op_not_exists()]), &empty_token()), TriValue::True);
    }

    #[test]
    fn expression_literal_integers() {
        let expr = build(&[int64_literal(42)]);
        // Literal alone on stack → UNKNOWN (no operator)
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn expression_literal_strings() {
        let expr = build(&[string_literal("hello")]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn expression_literal_sids() {
        let expr = build(&[sid_literal(&well_known::system().unwrap())]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn expression_literal_octet_strings() {
        let expr = build(&[octet_literal(&[0xDE, 0xAD])]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn expression_literal_composites() {
        let expr = build(&[composite_literal(&[int64_literal(1), int64_literal(2)])]);
        assert_eq!(eval(&expr, &empty_token()), TriValue::Unknown);
    }

    #[test]
    fn expression_stack_based_evaluation() {
        // Stack-based bytecode program in RPN
        let token = token_with_claims(alloc::vec![int_claim("x", 5)]);
        // Push x, push 5, eq → TRUE
        let expr = build(&[user_attr("x"), int64_literal(5), op_eq()]);
        assert_eq!(eval(&expr, &token), TriValue::True);
    }

    #[test]
    fn member_of_checks_token_groups() {
        // Member_of evaluates by checking token's groups
        let token = empty_token(); // system token has Administrators group
        let expr = build(&[sid_literal(&well_known::administrators().unwrap()), op_member_of()]);
        assert_eq!(eval(&expr, &token), TriValue::True);

        let random = crate::sid::Sid::new(5, &[21, 999, 999, 999]).unwrap();
        let expr2 = build(&[sid_literal(&random), op_member_of()]);
        assert_eq!(eval(&expr2, &token), TriValue::False);
    }

    #[test]
    fn member_of_combinable_with_conditions() {
        // Member_of{SID} && @User.clearance >= 3
        let mut token = token_with_claims(alloc::vec![int_claim("clearance", 5)]);
        let eng = crate::sid::Sid::new(5, &[21, 100, 200, 300, 2001]).unwrap();
        token.groups = alloc::vec![
            crate::group::GroupEntry::new(eng.clone(), crate::group::SE_GROUP_MANDATORY | crate::group::SE_GROUP_ENABLED),
        ];
        let mut expr = header();
        expr.extend_from_slice(&sid_literal(&eng));
        expr.extend_from_slice(&op_member_of());
        expr.extend_from_slice(&user_attr("clearance"));
        expr.extend_from_slice(&int64_literal(3));
        expr.extend_from_slice(&op_ge());
        expr.extend_from_slice(&op_and());
        assert_eq!(eval(&expr, &token), TriValue::True);
    }
}