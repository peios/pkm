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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriValue {
    True,
    False,
    Unknown,
}

impl TriValue {
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
    Literal,
    UserAttr,
    DeviceAttr,
    ResourceAttr,
    LocalAttr,
    Result,
}

impl Origin {
    pub fn is_attribute(self) -> bool {
        matches!(self, Origin::UserAttr | Origin::DeviceAttr | Origin::ResourceAttr | Origin::LocalAttr)
    }
}

/// A value on the evaluation stack.
#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub struct Value {
    pub vtype: ValueType,
    pub origin: Origin,
    /// Flags from the source claim (CASE_SENSITIVE, USE_FOR_DENY_ONLY, DISABLED).
    pub flags: u16,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug)]
pub enum ValueType {
    Null,
    Int64(i64),
    Uint64(u64),
    Boolean(bool),
    String(String),
    Sid(Sid),
    Octet(Vec<u8>),
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
) -> Result<Value, AllocError> {
    use crate::token::{ClaimType, ClaimValues, claim_flags};

    for attr in claims {
        if attr.name.eq_ignore_ascii_case(name) {
            if attr.flags & claim_flags::DISABLED != 0 {
                return Ok(Value::null());
            }
            if (attr.flags & claim_flags::USE_FOR_DENY_ONLY != 0) && for_allow {
                return Ok(Value::null());
            }

            let flags = attr.flags;
            match &attr.values {
                ClaimValues::Int64(vals) => {
                    if vals.is_empty() { return Ok(Value::null()); }
                    if vals.len() == 1 {
                        return Ok(Value { vtype: ValueType::Int64(vals[0]), origin: Origin::UserAttr, flags });
                    }
                    let mut elements = Vec::new();
                    for v in vals {
                        compat::vec_push(&mut elements, Value {
                            vtype: ValueType::Int64(*v), origin: Origin::UserAttr, flags,
                        })?;
                    }
                    return Ok(Value { vtype: ValueType::Composite(elements), origin: Origin::UserAttr, flags });
                }
                ClaimValues::Uint64(vals) => {
                    if vals.is_empty() { return Ok(Value::null()); }
                    if vals.len() == 1 {
                        return Ok(Value { vtype: ValueType::Uint64(vals[0]), origin: Origin::UserAttr, flags });
                    }
                    let mut elements = Vec::new();
                    for v in vals {
                        compat::vec_push(&mut elements, Value {
                            vtype: ValueType::Uint64(*v), origin: Origin::UserAttr, flags,
                        })?;
                    }
                    return Ok(Value { vtype: ValueType::Composite(elements), origin: Origin::UserAttr, flags });
                }
                ClaimValues::String(vals) => {
                    if vals.is_empty() { return Ok(Value::null()); }
                    if vals.len() == 1 {
                        return Ok(Value { vtype: ValueType::String(vals[0].try_clone()?), origin: Origin::UserAttr, flags });
                    }
                    let mut elements = Vec::new();
                    for v in vals {
                        compat::vec_push(&mut elements, Value {
                            vtype: ValueType::String(v.try_clone()?), origin: Origin::UserAttr, flags,
                        })?;
                    }
                    return Ok(Value { vtype: ValueType::Composite(elements), origin: Origin::UserAttr, flags });
                }
                ClaimValues::Boolean(vals) => {
                    if vals.is_empty() { return Ok(Value::null()); }
                    if vals.len() == 1 {
                        return Ok(Value { vtype: ValueType::Boolean(vals[0]), origin: Origin::UserAttr, flags });
                    }
                    let mut elements = Vec::new();
                    for v in vals {
                        compat::vec_push(&mut elements, Value {
                            vtype: ValueType::Boolean(*v), origin: Origin::UserAttr, flags,
                        })?;
                    }
                    return Ok(Value { vtype: ValueType::Composite(elements), origin: Origin::UserAttr, flags });
                }
                ClaimValues::Sid(vals) => {
                    if vals.is_empty() { return Ok(Value::null()); }
                    if vals.len() == 1 {
                        return Ok(Value { vtype: ValueType::Sid(vals[0].try_clone()?), origin: Origin::UserAttr, flags });
                    }
                    let mut elements = Vec::new();
                    for v in vals {
                        compat::vec_push(&mut elements, Value {
                            vtype: ValueType::Sid(v.try_clone()?), origin: Origin::UserAttr, flags,
                        })?;
                    }
                    return Ok(Value { vtype: ValueType::Composite(elements), origin: Origin::UserAttr, flags });
                }
                ClaimValues::Octet(vals) => {
                    if vals.is_empty() { return Ok(Value::null()); }
                    if vals.len() == 1 {
                        return Ok(Value { vtype: ValueType::Octet(vals[0].try_clone()?), origin: Origin::UserAttr, flags });
                    }
                    let mut elements = Vec::new();
                    for v in vals {
                        compat::vec_push(&mut elements, Value {
                            vtype: ValueType::Octet(v.try_clone()?), origin: Origin::UserAttr, flags,
                        })?;
                    }
                    return Ok(Value { vtype: ValueType::Composite(elements), origin: Origin::UserAttr, flags });
                }
            }
        }
    }
    Ok(Value::null())
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

/// Check if ALL SIDs in needles match the token (user or groups).
fn all_sids_match_token(needles: &[Sid], token: &Token, for_allow: bool) -> bool {
    needles.iter().all(|sid| crate::access_check::sid_matches_token(sid, token, for_allow))
}

fn any_sid_matches_token(needles: &[Sid], token: &Token, for_allow: bool) -> bool {
    needles.iter().any(|sid| crate::access_check::sid_matches_token(sid, token, for_allow))
}

fn all_sids_match_device(needles: &[Sid], token: &Token, for_allow: bool) -> bool {
    let dg = match &token.device_groups {
        Some(groups) => groups,
        None => return false,
    };
    needles.iter().all(|sid| {
        dg.iter().any(|g| g.sid == *sid && g.matches_for(for_allow))
    })
}

fn any_sid_matches_device(needles: &[Sid], token: &Token, for_allow: bool) -> bool {
    let dg = match &token.device_groups {
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
/// `token`: the calling thread's token.
/// `user_claims`, `device_claims`: from the token.
/// `resource_attributes`: from the object's SACL.
/// `local_claims`: per-call context provided by the caller.
/// `for_allow`: whether this is an allow ACE (affects claim resolution).
pub fn evaluate(
    condition: &[u8],
    token: &Token,
    resource_attributes: &[crate::token::ClaimEntry],
    local_claims: &[crate::token::ClaimEntry],
    for_allow: bool,
) -> Result<TriValue, AllocError> {
    if condition.len() < 4 || condition[0..4] != ARTX_HEADER {
        return Ok(TriValue::Unknown);
    }

    let mut stack: Vec<Value> = Vec::new();
    let mut pos: usize = 4;

    while pos < condition.len() {
        let op = condition[pos];
        pos += 1;

        match op {
            // Padding
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
                    // Negative: interpret as negative int64
                    -(magnitude as i64)
                } else {
                    magnitude as i64
                };
                compat::vec_push(&mut stack, Value {
                    vtype: ValueType::Int64(value),
                    origin: Origin::Literal,
                    flags: 0,
                })?;
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
                compat::vec_push(&mut stack, Value {
                    vtype: ValueType::String(s),
                    origin: Origin::Literal,
                    flags: 0,
                })?;
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
                compat::vec_push(&mut stack, Value {
                    vtype: ValueType::Octet(data),
                    origin: Origin::Literal,
                    flags: 0,
                })?;
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
                    Some(elems) => compat::vec_push(&mut stack, Value {
                        vtype: ValueType::Composite(elems),
                        origin: Origin::Literal,
                        flags: 0,
                    })?,
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
                        compat::vec_push(&mut stack, Value {
                            vtype: ValueType::Sid(sid),
                            origin: Origin::Literal,
                            flags: 0,
                        })?;
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
                let mut v = resolve_claim(local_claims, &name, for_allow)?;
                v.origin = Origin::LocalAttr;
                compat::vec_push(&mut stack, v)?;
            }

            // @User.
            0xf9 => {
                let (name, new_pos) = match read_attr_name(condition, pos) {
                    Some(r) => r,
                    None => return Ok(TriValue::Unknown),
                };
                pos = new_pos;
                let mut v = resolve_claim(&token.user_claims, &name, for_allow)?;
                v.origin = Origin::UserAttr;
                compat::vec_push(&mut stack, v)?;
            }

            // @Resource.
            0xfa => {
                let (name, new_pos) = match read_attr_name(condition, pos) {
                    Some(r) => r,
                    None => return Ok(TriValue::Unknown),
                };
                pos = new_pos;
                let mut v = resolve_claim(resource_attributes, &name, for_allow)?;
                v.origin = Origin::ResourceAttr;
                compat::vec_push(&mut stack, v)?;
            }

            // @Device.
            0xfb => {
                let (name, new_pos) = match read_attr_name(condition, pos) {
                    Some(r) => r,
                    None => return Ok(TriValue::Unknown),
                };
                pos = new_pos;
                let mut v = resolve_claim(&token.device_claims, &name, for_allow)?;
                v.origin = Origin::DeviceAttr;
                compat::vec_push(&mut stack, v)?;
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
                let result = if all_sids_match_token(&sids, token, for_allow) {
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
                let result = if any_sid_matches_token(&sids, token, for_allow) {
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
                if token.device_groups.is_none() {
                    compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?;
                    continue;
                }
                let result = if all_sids_match_device(&sids, token, for_allow) {
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
                if token.device_groups.is_none() {
                    compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?;
                    continue;
                }
                let result = if any_sid_matches_device(&sids, token, for_allow) {
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
                let result = if all_sids_match_token(&sids, token, for_allow) {
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
                let result = if any_sid_matches_token(&sids, token, for_allow) {
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
                if token.device_groups.is_none() {
                    compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?;
                    continue;
                }
                let result = if all_sids_match_device(&sids, token, for_allow) {
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
                if token.device_groups.is_none() {
                    compat::vec_push(&mut stack, Value::from_bool_result(TriValue::Unknown))?;
                    continue;
                }
                let result = if any_sid_matches_device(&sids, token, for_allow) {
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
fn decode_utf16le(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let code_unit = u16::from_le_bytes([data[i], data[i + 1]]);
        if let Some(c) = char::from_u32(code_unit as u32) {
            result.push(c);
        }
        i += 2;
    }
    result
}

/// Encode a Rust String to UTF-16LE bytes.
#[cfg(test)]
fn encode_utf16le(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    for c in s.chars() {
        let code = c as u16;
        result.extend_from_slice(&code.to_le_bytes());
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
                    -(magnitude as i64)
                } else {
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
    pub fn op_and() -> Vec<u8> { alloc::vec![0xa0] }
    pub fn op_or() -> Vec<u8> { alloc::vec![0xa1] }
    pub fn op_not() -> Vec<u8> { alloc::vec![0xa2] }

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

    fn eval(expr: &[u8], token: &Token) -> TriValue {
        evaluate(expr, token, &[], &[], true).unwrap()
    }

    fn eval_with_resource(expr: &[u8], token: &Token, resource: &[ClaimEntry]) -> TriValue {
        evaluate(expr, token, resource, &[], true).unwrap()
    }

    fn eval_deny(expr: &[u8], token: &Token) -> TriValue {
        evaluate(expr, token, &[], &[], false).unwrap()
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
        assert_eq!(evaluate(&expr, &token, &[], &local, true).unwrap(), TriValue::True);
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
        assert_eq!(evaluate(&expr, &token, &resource, &[], true).unwrap(), TriValue::True);
    }
}