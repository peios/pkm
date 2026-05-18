use core::cmp::Ordering;

use crate::claims::{
    ClaimAttribute, ClaimValue, CLAIM_SECURITY_ATTRIBUTE_DISABLED,
    CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY, CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE,
};
use crate::pkm_alloc::{slice_to_vec, String, TryClone, Vec};
use crate::sid::{Sid, SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY};
use crate::token::{IdentityView, SidAndAttributes, TokenView};

const OWNER_RIGHTS_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];
const PRINCIPAL_SELF_SID_BYTES: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 10, 0, 0, 0];
const MAX_STACK_DEPTH: usize = 1024;
const MAX_COMPOSITE_LITERAL_DEPTH: usize = 64;

/// Tri-state result for conditional ACE evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConditionalResult {
    /// The expression evaluated to true.
    True,
    /// The expression evaluated to false.
    False,
    /// The expression could not be determined and must be treated as unknown.
    Unknown,
}

/// Claim, identity, and virtual-SID inputs used while evaluating a conditional
/// ACE expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConditionalContext<'a> {
    /// Optional caller-provided `PRINCIPAL_SELF` substitution SID.
    pub self_sid: Option<Sid<'a>>,
    /// Precomputed `PRINCIPAL_SELF` match outcome when the caller needs to
    /// override default matching.
    pub principal_self_matches: Option<bool>,
    /// Whether the caller is considered the owner for this evaluation.
    pub caller_is_owner: bool,
    /// Optional identity view used for restricted or synthetic membership
    /// checks.
    pub identity: Option<IdentityView<'a>>,
    /// Whether `identity` membership should ignore SID attributes and match by
    /// presence only.
    pub identity_membership_is_presence_based: bool,
    /// Device-group SIDs visible to `Device_Member_of*` operators.
    pub device_groups: &'a [SidAndAttributes<'a>],
    /// Whether device membership operators also see caller/owner virtual
    /// groups injected by a synthetic pass.
    pub device_membership_uses_virtual_groups: bool,
    /// Whether SID membership operators may inspect token or device-group
    /// membership. CAAP `applies_to` disables this while still allowing claim
    /// predicates.
    pub membership_allowed: bool,
    /// User claim set visible to `@User.*` references.
    pub user_claims: &'a [ClaimAttribute],
    /// Device claim set visible to `@Device.*` references.
    pub device_claims: &'a [ClaimAttribute],
    /// Resource claim set visible to `@Resource.*` references.
    pub resource_claims: &'a [ClaimAttribute],
    /// Local claim set visible to `@Local.*` references.
    pub local_claims: &'a [ClaimAttribute],
}

impl<'a> Default for ConditionalContext<'a> {
    fn default() -> Self {
        Self {
            self_sid: None,
            principal_self_matches: None,
            caller_is_owner: false,
            identity: None,
            identity_membership_is_presence_based: false,
            device_groups: &[],
            device_membership_uses_virtual_groups: false,
            membership_allowed: true,
            user_claims: &[],
            device_claims: &[],
            resource_claims: &[],
            local_claims: &[],
        }
    }
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
enum Value {
    Null,
    Int64(i64),
    UInt64(u64),
    String(String),
    Octet(Vec<u8>),
    Sid(Vec<u8>),
    Composite(Vec<Value>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValueOrigin {
    Literal,
    Attribute,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
struct OperandValue {
    value: Value,
    origin: ValueOrigin,
    flags: u32,
}

#[cfg_attr(not(feature = "kernel"), derive(Clone))]
#[derive(Debug, Eq, PartialEq)]
enum StackEntry {
    Value(OperandValue),
    Result(ConditionalResult),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogicalOperand {
    Result(ConditionalResult),
    LiteralOrigin,
}

/// Evaluates one conditional ACE bytecode program and returns a tri-state
/// result. Malformed inputs, bounds violations, and stack overflows return
/// `Unknown`.
pub fn evaluate_conditional_expression(
    bytes: &[u8],
    token: &TokenView<'_>,
    context: &ConditionalContext<'_>,
    for_allow: bool,
) -> ConditionalResult {
    if bytes.len() < 4 || &bytes[..4] != b"artx" {
        return ConditionalResult::Unknown;
    }

    let mut offset = 4usize;
    let mut stack = Vec::new();

    while offset < bytes.len() {
        if stack.len() > MAX_STACK_DEPTH {
            return ConditionalResult::Unknown;
        }

        let token_type = bytes[offset];
        offset += 1;

        if token_type == 0x00 {
            if bytes[offset..].iter().any(|byte| *byte != 0) {
                return ConditionalResult::Unknown;
            }
            break;
        }

        let entry = match token_type {
            0x01..=0x04 => parse_int_literal(bytes, &mut offset),
            0x10 => parse_string_literal(bytes, &mut offset),
            0x18 => parse_octet_literal(bytes, &mut offset),
            0x50 => parse_composite_literal(bytes, &mut offset, 0),
            0x51 => parse_sid_literal(bytes, &mut offset),
            0x80 => binary_compare(&mut stack, compare_eq),
            0x81 => binary_compare(&mut stack, compare_ne),
            0x82 => binary_compare(&mut stack, compare_lt),
            0x83 => binary_compare(&mut stack, compare_le),
            0x84 => binary_compare(&mut stack, compare_gt),
            0x85 => binary_compare(&mut stack, compare_ge),
            0x86 => binary_compare(&mut stack, compare_contains),
            0x87 => unary_exists(&mut stack),
            0x88 => binary_compare(&mut stack, compare_any_of),
            0x89 => unary_membership(&mut stack, token, context, for_allow, false, false),
            0x8a => unary_membership(&mut stack, token, context, for_allow, true, false),
            0x8b => unary_membership(&mut stack, token, context, for_allow, false, true),
            0x8c => unary_membership(&mut stack, token, context, for_allow, true, true),
            0x8d => unary_not_exists(&mut stack),
            0x8e => binary_compare(&mut stack, compare_not_contains),
            0x8f => binary_compare(&mut stack, compare_not_any_of),
            0x90 => unary_membership(&mut stack, token, context, for_allow, false, false)
                .map(invert_result_entry),
            0x91 => unary_membership(&mut stack, token, context, for_allow, true, false)
                .map(invert_result_entry),
            0x92 => unary_membership(&mut stack, token, context, for_allow, false, true)
                .map(invert_result_entry),
            0x93 => unary_membership(&mut stack, token, context, for_allow, true, true)
                .map(invert_result_entry),
            0xa0 => binary_logical(&mut stack, logical_and),
            0xa1 => binary_logical(&mut stack, logical_or),
            0xa2 => unary_logical_not(&mut stack),
            0xf8 => parse_attribute_ref(bytes, &mut offset, context.local_claims, for_allow),
            0xf9 => parse_attribute_ref(bytes, &mut offset, context.user_claims, for_allow),
            0xfa => parse_attribute_ref(bytes, &mut offset, context.resource_claims, for_allow),
            0xfb => parse_attribute_ref(bytes, &mut offset, context.device_claims, for_allow),
            _ => None,
        };

        let Some(entry) = entry else {
            return ConditionalResult::Unknown;
        };
        if stack.push(entry).is_err() {
            return ConditionalResult::Unknown;
        }
        if stack.len() > MAX_STACK_DEPTH {
            return ConditionalResult::Unknown;
        }
    }

    if stack.len() != 1 {
        return ConditionalResult::Unknown;
    }

    match stack.pop().expect("checked len") {
        StackEntry::Result(result) => result,
        StackEntry::Value(_) => ConditionalResult::Unknown,
    }
}

pub(crate) fn validate_conditional_expression_structure(bytes: &[u8]) -> bool {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum StructuralEntry {
        Value,
        Result,
    }

    fn pop_kind(stack: &mut Vec<StructuralEntry>, expected: StructuralEntry) -> bool {
        matches!(stack.pop(), Some(kind) if kind == expected)
    }

    fn pop_logical_operand(stack: &mut Vec<StructuralEntry>) -> bool {
        matches!(
            stack.pop(),
            Some(StructuralEntry::Value | StructuralEntry::Result)
        )
    }

    if bytes.len() < 4 || &bytes[..4] != b"artx" {
        return false;
    }

    let mut offset = 4usize;
    let mut stack = Vec::new();

    while offset < bytes.len() {
        if stack.len() > MAX_STACK_DEPTH {
            return false;
        }

        let token_type = bytes[offset];
        offset += 1;

        if token_type == 0x00 {
            if bytes[offset..].iter().any(|byte| *byte != 0) {
                return false;
            }
            break;
        }

        match token_type {
            0x01..=0x04 => {
                if parse_int_literal(bytes, &mut offset).is_none() {
                    return false;
                }
                if stack.push(StructuralEntry::Value).is_err() {
                    return false;
                }
            }
            0x10 => {
                if parse_string_literal(bytes, &mut offset).is_none() {
                    return false;
                }
                if stack.push(StructuralEntry::Value).is_err() {
                    return false;
                }
            }
            0x18 => {
                if parse_octet_literal(bytes, &mut offset).is_none() {
                    return false;
                }
                if stack.push(StructuralEntry::Value).is_err() {
                    return false;
                }
            }
            0x50 => {
                if parse_composite_literal(bytes, &mut offset, 0).is_none() {
                    return false;
                }
                if stack.push(StructuralEntry::Value).is_err() {
                    return false;
                }
            }
            0x51 => {
                if parse_sid_literal(bytes, &mut offset).is_none() {
                    return false;
                }
                if stack.push(StructuralEntry::Value).is_err() {
                    return false;
                }
            }
            0x80..=0x86 | 0x88 | 0x8e | 0x8f => {
                if !pop_kind(&mut stack, StructuralEntry::Value)
                    || !pop_kind(&mut stack, StructuralEntry::Value)
                {
                    return false;
                }
                if stack.push(StructuralEntry::Result).is_err() {
                    return false;
                }
            }
            0x87 | 0x89..=0x8d | 0x90..=0x93 => {
                if !pop_kind(&mut stack, StructuralEntry::Value) {
                    return false;
                }
                if stack.push(StructuralEntry::Result).is_err() {
                    return false;
                }
            }
            0xa0 | 0xa1 => {
                if !pop_logical_operand(&mut stack) || !pop_logical_operand(&mut stack) {
                    return false;
                }
                if stack.push(StructuralEntry::Result).is_err() {
                    return false;
                }
            }
            0xa2 => {
                if !pop_logical_operand(&mut stack) {
                    return false;
                }
                if stack.push(StructuralEntry::Result).is_err() {
                    return false;
                }
            }
            0xf8..=0xfb => {
                if parse_attribute_ref(bytes, &mut offset, &[], false).is_none() {
                    return false;
                }
                if stack.push(StructuralEntry::Value).is_err() {
                    return false;
                }
            }
            _ => return false,
        }

        if stack.len() > MAX_STACK_DEPTH {
            return false;
        }
    }

    stack.len() == 1 && matches!(stack.pop(), Some(StructuralEntry::Result))
}

fn parse_int_literal(bytes: &[u8], offset: &mut usize) -> Option<StackEntry> {
    let raw = read_array::<8>(bytes, offset)?;
    let sign = read_u8(bytes, offset)?;
    let base = read_u8(bytes, offset)?;
    if !matches!(sign, 0x01..=0x03) || !matches!(base, 0x01..=0x03) {
        return None;
    }
    let raw_value = i64::from_le_bytes(raw);
    let value = normalize_signed_literal(raw_value, sign)?;
    if !literal_fits_declared_width(value, bytes[*offset - 11]) {
        return None;
    }

    Some(StackEntry::Value(OperandValue {
        value: Value::Int64(value),
        origin: ValueOrigin::Literal,
        flags: 0,
    }))
}

fn parse_string_literal(bytes: &[u8], offset: &mut usize) -> Option<StackEntry> {
    let len = read_u32(bytes, offset)? as usize;
    if len % 2 != 0 {
        return None;
    }
    let raw = read_slice(bytes, offset, len)?;
    let string = decode_utf16_string(raw)?;
    Some(StackEntry::Value(OperandValue {
        value: Value::String(string),
        origin: ValueOrigin::Literal,
        flags: 0,
    }))
}

fn parse_octet_literal(bytes: &[u8], offset: &mut usize) -> Option<StackEntry> {
    let len = read_u32(bytes, offset)? as usize;
    let raw = read_slice(bytes, offset, len)?;
    Some(StackEntry::Value(OperandValue {
        value: Value::Octet(slice_to_vec(raw).ok()?),
        origin: ValueOrigin::Literal,
        flags: 0,
    }))
}

fn parse_composite_literal(bytes: &[u8], offset: &mut usize, depth: usize) -> Option<StackEntry> {
    if depth >= MAX_COMPOSITE_LITERAL_DEPTH {
        return None;
    }

    let len = read_u32(bytes, offset)? as usize;
    let end = offset.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }

    let mut values = Vec::new();
    while *offset < end {
        let token_type = read_u8(bytes, offset)?;
        if token_type == 0x00 {
            return None;
        }

        let entry = match token_type {
            0x01..=0x04 => parse_int_literal(bytes, offset),
            0x10 => parse_string_literal(bytes, offset),
            0x18 => parse_octet_literal(bytes, offset),
            0x50 => parse_composite_literal(bytes, offset, depth + 1),
            0x51 => parse_sid_literal(bytes, offset),
            _ => None,
        }?;

        match entry {
            StackEntry::Value(value) => values.push(value.value).ok()?,
            StackEntry::Result(_) => return None,
        }
    }

    Some(StackEntry::Value(OperandValue {
        value: Value::Composite(values),
        origin: ValueOrigin::Literal,
        flags: 0,
    }))
}

#[cfg(test)]
mod tests {
    use super::{parse_composite_literal, validate_conditional_expression_structure, StackEntry};

    fn string_payload(value: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let utf16: std::vec::Vec<u16> = value.encode_utf16().collect();
        bytes.extend_from_slice(&((utf16.len() * 2) as u32).to_le_bytes());
        for code_unit in utf16 {
            bytes.extend_from_slice(&code_unit.to_le_bytes());
        }
        bytes
    }

    fn attr_ref(opcode: u8, name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(opcode);
        bytes.extend_from_slice(&string_payload(name));
        bytes
    }

    fn nested_composite(depth: usize) -> Vec<u8> {
        let mut inner = vec![0x10, 0, 0, 0, 0];
        for _ in 0..depth {
            let mut next = Vec::with_capacity(5 + inner.len());
            next.push(0x50);
            next.extend_from_slice(&(inner.len() as u32).to_le_bytes());
            next.extend_from_slice(&inner);
            inner = next;
        }
        inner
    }

    #[test]
    fn composite_literal_depth_limit_fails_closed() {
        let mut offset = 1usize;
        let bytes = nested_composite(65);

        let parsed = parse_composite_literal(&bytes, &mut offset, 0);

        assert!(parsed.is_none());
    }

    #[test]
    fn bounded_composite_literal_still_parses() {
        let mut offset = 1usize;
        let bytes = nested_composite(2);

        let parsed = parse_composite_literal(&bytes, &mut offset, 0);

        assert!(matches!(parsed, Some(StackEntry::Value(_))));
    }

    #[test]
    fn structural_validator_accepts_logical_attribute_operands() {
        let mut bytes = b"artx".to_vec();
        bytes.extend_from_slice(&attr_ref(0xf9, "enabled"));
        bytes.extend_from_slice(&attr_ref(0xfa, "allowed"));
        bytes.push(0xa0);

        assert!(validate_conditional_expression_structure(&bytes));
    }
}

fn parse_sid_literal(bytes: &[u8], offset: &mut usize) -> Option<StackEntry> {
    let len = read_u32(bytes, offset)? as usize;
    let raw = read_slice(bytes, offset, len)?;
    Sid::parse(raw).ok()?;
    Some(StackEntry::Value(OperandValue {
        value: Value::Sid(slice_to_vec(raw).ok()?),
        origin: ValueOrigin::Literal,
        flags: 0,
    }))
}

fn parse_attribute_ref(
    bytes: &[u8],
    offset: &mut usize,
    namespace: &[ClaimAttribute],
    for_allow: bool,
) -> Option<StackEntry> {
    let len = read_u32(bytes, offset)? as usize;
    if len % 2 != 0 {
        return None;
    }
    let raw = read_slice(bytes, offset, len)?;
    let name = decode_utf16_string(raw)?;
    let value = lookup_attribute(namespace, &name, for_allow);
    Some(StackEntry::Value(value))
}

fn lookup_attribute(namespace: &[ClaimAttribute], name: &str, for_allow: bool) -> OperandValue {
    let Some(folded_name) = fold_string(name) else {
        return attribute_null();
    };
    let Some(attribute) = namespace.iter().find(|attribute| {
        fold_string(&attribute.name)
            .as_ref()
            .is_some_and(|folded| folded == &folded_name)
    }) else {
        return attribute_null();
    };

    if (attribute.flags & CLAIM_SECURITY_ATTRIBUTE_DISABLED) != 0 {
        return attribute_null();
    }
    if for_allow && (attribute.flags & CLAIM_SECURITY_ATTRIBUTE_USE_FOR_DENY_ONLY) != 0 {
        return attribute_null();
    }
    if attribute.values.is_empty() {
        return attribute_null();
    }

    let value = if attribute.values.len() == 1 {
        let Some(value) = claim_value_to_value(&attribute.values[0]) else {
            return attribute_null();
        };
        value
    } else {
        let mut values = Vec::with_capacity(attribute.values.len()).ok();
        let Some(values_vec) = values.as_mut() else {
            return attribute_null();
        };
        for value in attribute.values.iter().filter_map(claim_value_to_value) {
            if values_vec.push(value).is_err() {
                return attribute_null();
            }
        }
        if values_vec.len() != attribute.values.len() {
            return attribute_null();
        }
        Value::Composite(values.take().expect("checked Some"))
    };

    OperandValue {
        value,
        origin: ValueOrigin::Attribute,
        flags: attribute.flags,
    }
}

fn attribute_null() -> OperandValue {
    OperandValue {
        value: Value::Null,
        origin: ValueOrigin::Attribute,
        flags: 0,
    }
}

fn claim_value_to_value(value: &ClaimValue) -> Option<Value> {
    match value {
        ClaimValue::Int64(value) => Some(Value::Int64(*value)),
        ClaimValue::UInt64(value) => Some(Value::UInt64(*value)),
        ClaimValue::String(value) => Some(Value::String(value.try_clone().ok()?)),
        ClaimValue::Sid(value) => Some(Value::Sid(value.try_clone().ok()?)),
        ClaimValue::Octet(value) => Some(Value::Octet(value.try_clone().ok()?)),
        ClaimValue::Boolean(value) => Some(Value::Int64(if *value != 0 { 1 } else { 0 })),
        ClaimValue::Composite(values) => {
            let mut converted = Vec::with_capacity(values.len()).ok()?;
            for value in values {
                converted.push(claim_value_to_value(value)?).ok()?;
            }
            Some(Value::Composite(converted))
        }
    }
}

fn binary_compare(
    stack: &mut Vec<StackEntry>,
    op: fn(&OperandValue, &OperandValue) -> ConditionalResult,
) -> Option<StackEntry> {
    let rhs = pop_value(stack)?;
    let lhs = pop_value(stack)?;
    Some(StackEntry::Result(op(&lhs, &rhs)))
}

fn unary_exists(stack: &mut Vec<StackEntry>) -> Option<StackEntry> {
    let value = pop_value(stack)?;
    Some(StackEntry::Result(match value.origin {
        ValueOrigin::Literal => ConditionalResult::Unknown,
        ValueOrigin::Attribute => {
            if value.value == Value::Null {
                ConditionalResult::False
            } else {
                ConditionalResult::True
            }
        }
    }))
}

fn unary_not_exists(stack: &mut Vec<StackEntry>) -> Option<StackEntry> {
    Some(invert_result_entry(unary_exists(stack)?))
}

fn unary_membership(
    stack: &mut Vec<StackEntry>,
    token: &TokenView<'_>,
    context: &ConditionalContext<'_>,
    for_allow: bool,
    device: bool,
    any: bool,
) -> Option<StackEntry> {
    let value = pop_value(stack)?;
    let sids = extract_sid_values(&value.value)?;
    let mut saw_unknown = false;
    let mut matched_any = false;

    for sid_bytes in &sids {
        match sid_in_membership_set(token, context, sid_bytes, for_allow, device) {
            Some(true) => matched_any = true,
            Some(false) => {}
            None => saw_unknown = true,
        }
    }

    let result = if any {
        if matched_any {
            ConditionalResult::True
        } else if saw_unknown {
            ConditionalResult::Unknown
        } else {
            ConditionalResult::False
        }
    } else if saw_unknown {
        ConditionalResult::Unknown
    } else if matched_any || sids.is_empty() {
        if sids
            .iter()
            .all(|sid| sid_in_membership_set(token, context, sid, for_allow, device) == Some(true))
        {
            ConditionalResult::True
        } else {
            ConditionalResult::False
        }
    } else {
        ConditionalResult::False
    };

    Some(StackEntry::Result(result))
}

fn binary_logical(
    stack: &mut Vec<StackEntry>,
    op: fn(ConditionalResult, ConditionalResult) -> ConditionalResult,
) -> Option<StackEntry> {
    let rhs = pop_logical_operand(stack)?;
    let lhs = pop_logical_operand(stack)?;
    let result = match (lhs, rhs) {
        (LogicalOperand::LiteralOrigin, _) | (_, LogicalOperand::LiteralOrigin) => {
            ConditionalResult::Unknown
        }
        (LogicalOperand::Result(lhs), LogicalOperand::Result(rhs)) => op(lhs, rhs),
    };
    Some(StackEntry::Result(result))
}

fn unary_logical_not(stack: &mut Vec<StackEntry>) -> Option<StackEntry> {
    let value = pop_logical_operand(stack)?;
    let result = match value {
        LogicalOperand::LiteralOrigin => ConditionalResult::Unknown,
        LogicalOperand::Result(result) => invert_result(result),
    };
    Some(StackEntry::Result(result))
}

fn pop_value(stack: &mut Vec<StackEntry>) -> Option<OperandValue> {
    match stack.pop()? {
        StackEntry::Value(value) => Some(value),
        StackEntry::Result(_) => None,
    }
}

fn pop_logical_operand(stack: &mut Vec<StackEntry>) -> Option<LogicalOperand> {
    match stack.pop()? {
        StackEntry::Result(result) => Some(LogicalOperand::Result(result)),
        StackEntry::Value(value) => coerce_logical_value(&value),
    }
}

fn coerce_logical_value(value: &OperandValue) -> Option<LogicalOperand> {
    match value.origin {
        ValueOrigin::Literal => Some(LogicalOperand::LiteralOrigin),
        ValueOrigin::Attribute => Some(LogicalOperand::Result(match &value.value {
            Value::Null => ConditionalResult::Unknown,
            Value::Int64(value) => {
                if *value == 0 {
                    ConditionalResult::False
                } else {
                    ConditionalResult::True
                }
            }
            Value::UInt64(value) => {
                if *value == 0 {
                    ConditionalResult::False
                } else {
                    ConditionalResult::True
                }
            }
            Value::String(value) => {
                if value.is_empty() {
                    ConditionalResult::False
                } else {
                    ConditionalResult::True
                }
            }
            Value::Octet(_) | Value::Sid(_) | Value::Composite(_) => ConditionalResult::Unknown,
        })),
    }
}

fn compare_eq(lhs: &OperandValue, rhs: &OperandValue) -> ConditionalResult {
    compare_set_relation(lhs, rhs, SetRelation::Equal)
}

fn compare_ne(lhs: &OperandValue, rhs: &OperandValue) -> ConditionalResult {
    invert_result(compare_eq(lhs, rhs))
}

fn compare_lt(lhs: &OperandValue, rhs: &OperandValue) -> ConditionalResult {
    compare_order(lhs, rhs, |ordering| ordering == Ordering::Less)
}

fn compare_le(lhs: &OperandValue, rhs: &OperandValue) -> ConditionalResult {
    compare_order(lhs, rhs, |ordering| ordering != Ordering::Greater)
}

fn compare_gt(lhs: &OperandValue, rhs: &OperandValue) -> ConditionalResult {
    compare_order(lhs, rhs, |ordering| ordering == Ordering::Greater)
}

fn compare_ge(lhs: &OperandValue, rhs: &OperandValue) -> ConditionalResult {
    compare_order(lhs, rhs, |ordering| ordering != Ordering::Less)
}

fn compare_contains(lhs: &OperandValue, rhs: &OperandValue) -> ConditionalResult {
    compare_set_relation(lhs, rhs, SetRelation::Contains)
}

fn compare_not_contains(lhs: &OperandValue, rhs: &OperandValue) -> ConditionalResult {
    invert_result(compare_contains(lhs, rhs))
}

fn compare_any_of(lhs: &OperandValue, rhs: &OperandValue) -> ConditionalResult {
    compare_set_relation(lhs, rhs, SetRelation::AnyOf)
}

fn compare_not_any_of(lhs: &OperandValue, rhs: &OperandValue) -> ConditionalResult {
    invert_result(compare_any_of(lhs, rhs))
}

#[derive(Clone, Copy)]
enum SetRelation {
    Equal,
    Contains,
    AnyOf,
}

fn compare_set_relation(
    lhs: &OperandValue,
    rhs: &OperandValue,
    relation: SetRelation,
) -> ConditionalResult {
    let case_sensitive =
        ((lhs.flags | rhs.flags) & CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE) != 0;
    let lhs_values = as_set(&lhs.value);
    let rhs_values = as_set(&rhs.value);

    match relation {
        SetRelation::Equal => {
            if lhs_values.len() != rhs_values.len() {
                return ConditionalResult::False;
            }
            let lhs_contains_rhs = contains_all(lhs_values, rhs_values, case_sensitive);
            let rhs_contains_lhs = contains_all(rhs_values, lhs_values, case_sensitive);
            combine_pair(lhs_contains_rhs, rhs_contains_lhs)
        }
        SetRelation::Contains => contains_all(lhs_values, rhs_values, case_sensitive),
        SetRelation::AnyOf => contains_any(rhs_values, lhs_values, case_sensitive),
    }
}

fn compare_order(
    lhs: &OperandValue,
    rhs: &OperandValue,
    predicate: fn(Ordering) -> bool,
) -> ConditionalResult {
    let case_sensitive =
        ((lhs.flags | rhs.flags) & CLAIM_SECURITY_ATTRIBUTE_VALUE_CASE_SENSITIVE) != 0;
    let lhs_scalar = scalar_only(&lhs.value);
    let rhs_scalar = scalar_only(&rhs.value);
    let (Some(lhs_scalar), Some(rhs_scalar)) = (lhs_scalar, rhs_scalar) else {
        return ConditionalResult::Unknown;
    };

    match compare_scalar(lhs_scalar, rhs_scalar, case_sensitive) {
        Some(ordering) => {
            if predicate(ordering) {
                ConditionalResult::True
            } else {
                ConditionalResult::False
            }
        }
        None => ConditionalResult::Unknown,
    }
}

fn scalar_only(value: &Value) -> Option<&Value> {
    match value {
        Value::Composite(values) if values.len() == 1 => values.first(),
        Value::Composite(_) => None,
        other => Some(other),
    }
}

fn as_set(value: &Value) -> &[Value] {
    match value {
        Value::Composite(values) => values,
        _ => core::slice::from_ref(value),
    }
}

fn contains_all(lhs: &[Value], rhs: &[Value], case_sensitive: bool) -> ConditionalResult {
    let mut saw_unknown = false;
    for rhs_value in rhs {
        let mut matched = false;
        let mut local_unknown = false;
        for lhs_value in lhs {
            match values_equal(lhs_value, rhs_value, case_sensitive) {
                Some(true) => {
                    matched = true;
                    break;
                }
                Some(false) => {}
                None => local_unknown = true,
            }
        }

        if !matched {
            if local_unknown {
                saw_unknown = true;
            } else {
                return ConditionalResult::False;
            }
        }
    }

    if saw_unknown {
        ConditionalResult::Unknown
    } else {
        ConditionalResult::True
    }
}

fn contains_any(lhs: &[Value], rhs: &[Value], case_sensitive: bool) -> ConditionalResult {
    let mut saw_unknown = false;
    for rhs_value in rhs {
        for lhs_value in lhs {
            match values_equal(lhs_value, rhs_value, case_sensitive) {
                Some(true) => return ConditionalResult::True,
                Some(false) => {}
                None => saw_unknown = true,
            }
        }
    }

    if saw_unknown {
        ConditionalResult::Unknown
    } else {
        ConditionalResult::False
    }
}

fn combine_pair(lhs: ConditionalResult, rhs: ConditionalResult) -> ConditionalResult {
    match (lhs, rhs) {
        (ConditionalResult::True, ConditionalResult::True) => ConditionalResult::True,
        (ConditionalResult::False, _) | (_, ConditionalResult::False) => ConditionalResult::False,
        _ => ConditionalResult::Unknown,
    }
}

fn values_equal(lhs: &Value, rhs: &Value, case_sensitive: bool) -> Option<bool> {
    match (lhs, rhs) {
        (Value::Null, Value::Null) => None,
        (Value::Int64(lhs), Value::Int64(rhs)) => Some(lhs == rhs),
        (Value::UInt64(lhs), Value::UInt64(rhs)) => Some(lhs == rhs),
        (Value::Int64(lhs), Value::UInt64(rhs)) => {
            Some(compare_int64_uint64(*lhs, *rhs) == Ordering::Equal)
        }
        (Value::UInt64(lhs), Value::Int64(rhs)) => {
            Some(compare_int64_uint64(*rhs, *lhs) == Ordering::Equal)
        }
        (Value::String(lhs), Value::String(rhs)) => {
            compare_strings(lhs, rhs, case_sensitive).map(|ordering| ordering == Ordering::Equal)
        }
        (Value::Octet(lhs), Value::Octet(rhs)) => {
            compare_octets(lhs, rhs, case_sensitive).map(|ordering| ordering == Ordering::Equal)
        }
        (Value::Sid(lhs), Value::Sid(rhs)) => Some(lhs == rhs),
        (Value::Composite(_), Value::Composite(_))
        | (Value::Composite(_), _)
        | (_, Value::Composite(_)) => {
            let lhs_contains_rhs = contains_all(as_set(lhs), as_set(rhs), case_sensitive);
            let rhs_contains_lhs = contains_all(as_set(rhs), as_set(lhs), case_sensitive);
            match combine_pair(lhs_contains_rhs, rhs_contains_lhs) {
                ConditionalResult::True => Some(true),
                ConditionalResult::False => Some(false),
                ConditionalResult::Unknown => None,
            }
        }
        _ => None,
    }
}

fn compare_scalar(lhs: &Value, rhs: &Value, case_sensitive: bool) -> Option<Ordering> {
    match (lhs, rhs) {
        (Value::Int64(lhs), Value::Int64(rhs)) => Some(lhs.cmp(rhs)),
        (Value::UInt64(lhs), Value::UInt64(rhs)) => Some(lhs.cmp(rhs)),
        (Value::Int64(lhs), Value::UInt64(rhs)) => Some(compare_int64_uint64(*lhs, *rhs)),
        (Value::UInt64(lhs), Value::Int64(rhs)) => Some(compare_int64_uint64(*rhs, *lhs).reverse()),
        (Value::String(lhs), Value::String(rhs)) => compare_strings(lhs, rhs, case_sensitive),
        (Value::Octet(lhs), Value::Octet(rhs)) => compare_octets(lhs, rhs, case_sensitive),
        _ => None,
    }
}

fn compare_int64_uint64(lhs: i64, rhs: u64) -> Ordering {
    if lhs < 0 {
        Ordering::Less
    } else {
        (lhs as u64).cmp(&rhs)
    }
}

fn compare_strings(lhs: &str, rhs: &str, case_sensitive: bool) -> Option<Ordering> {
    let lhs_bytes = utf16le_bytes(lhs)?;
    let rhs_bytes = utf16le_bytes(rhs)?;

    compare_octets(lhs_bytes.as_slice(), rhs_bytes.as_slice(), case_sensitive)
}

fn fold_string(value: &str) -> Option<String> {
    let mut folded = String::new();
    for character in value.chars() {
        for lowered in character.to_lowercase() {
            folded.push(lowered).ok()?;
        }
    }
    Some(folded)
}

fn utf16le_bytes(value: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    for code_unit in value.encode_utf16() {
        bytes.push((code_unit & 0x00ff) as u8).ok()?;
        bytes.push((code_unit >> 8) as u8).ok()?;
    }
    Some(bytes)
}

fn compare_octets(lhs: &[u8], rhs: &[u8], case_sensitive: bool) -> Option<Ordering> {
    let lhs_folded;
    let rhs_folded;
    let (lhs_bytes, rhs_bytes): (&[u8], &[u8]) = if case_sensitive {
        (lhs, rhs)
    } else {
        lhs_folded = {
            let mut folded = Vec::with_capacity(lhs.len()).ok()?;
            for byte in lhs {
                folded.push(byte.to_ascii_lowercase()).ok()?;
            }
            folded
        };
        rhs_folded = {
            let mut folded = Vec::with_capacity(rhs.len()).ok()?;
            for byte in rhs {
                folded.push(byte.to_ascii_lowercase()).ok()?;
            }
            folded
        };
        (lhs_folded.as_slice(), rhs_folded.as_slice())
    };
    Some(lhs_bytes.cmp(rhs_bytes))
}

fn extract_sid_values(value: &Value) -> Option<Vec<Vec<u8>>> {
    match value {
        Value::Sid(bytes) => {
            let mut extracted = Vec::with_capacity(1).ok()?;
            extracted.push(bytes.try_clone().ok()?).ok()?;
            Some(extracted)
        }
        Value::Composite(values) => {
            let mut extracted = Vec::with_capacity(values.len()).ok()?;
            for value in values {
                match value {
                    Value::Sid(bytes) => extracted.push(bytes.try_clone().ok()?).ok()?,
                    _ => return None,
                }
            }
            Some(extracted)
        }
        _ => None,
    }
}

fn sid_in_membership_set(
    token: &TokenView<'_>,
    context: &ConditionalContext<'_>,
    sid_bytes: &[u8],
    for_allow: bool,
    device: bool,
) -> Option<bool> {
    if !context.membership_allowed {
        return None;
    }

    if !device || context.device_membership_uses_virtual_groups {
        if sid_bytes == OWNER_RIGHTS_SID_BYTES {
            return Some(context.caller_is_owner);
        }
        if sid_bytes == PRINCIPAL_SELF_SID_BYTES {
            if let Some(matches) = context.principal_self_matches {
                return Some(matches);
            }
            let Some(self_sid) = context.self_sid else {
                return Some(false);
            };
            return Some(matches_identity_view(
                effective_identity_view(token, context),
                self_sid,
                for_allow,
            ));
        }
    }

    let identity = effective_identity_view(token, context);
    if !device && context.identity_membership_is_presence_based {
        if identity
            .user
            .is_some_and(|user| user.as_bytes() == sid_bytes)
        {
            return Some(true);
        }

        return Some(
            identity
                .groups
                .iter()
                .any(|group| group.sid.as_bytes() == sid_bytes),
        );
    }

    let groups = if device {
        context.device_groups
    } else {
        identity.groups
    };

    for group in groups {
        if group.sid.as_bytes() != sid_bytes {
            continue;
        }
        let enabled = (group.attributes & SE_GROUP_ENABLED) != 0;
        let deny_only = (group.attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0;
        if for_allow {
            return Some(enabled && !deny_only);
        }
        return Some(enabled || deny_only);
    }

    Some(false)
}

fn effective_identity_view<'a>(
    token: &'a TokenView<'a>,
    context: &'a ConditionalContext<'a>,
) -> IdentityView<'a> {
    context.identity.unwrap_or_else(|| token.identity())
}

fn matches_identity_view(identity: IdentityView<'_>, sid: Sid<'_>, for_allow: bool) -> bool {
    if identity.user.is_some_and(|user| sid == user) {
        return if for_allow {
            !identity.user_deny_only
        } else {
            true
        };
    }

    for group in identity.groups {
        if group.sid != sid {
            continue;
        }
        let enabled = (group.attributes & SE_GROUP_ENABLED) != 0;
        let deny_only = (group.attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0;
        if for_allow {
            return enabled && !deny_only;
        }
        return enabled || deny_only;
    }

    false
}

fn invert_result(result: ConditionalResult) -> ConditionalResult {
    match result {
        ConditionalResult::True => ConditionalResult::False,
        ConditionalResult::False => ConditionalResult::True,
        ConditionalResult::Unknown => ConditionalResult::Unknown,
    }
}

fn normalize_signed_literal(raw_value: i64, sign: u8) -> Option<i64> {
    if raw_value == i64::MIN {
        return match sign {
            0x01 | 0x03 => None,
            0x02 => Some(i64::MIN),
            _ => None,
        };
    }

    let magnitude = if raw_value < 0 {
        raw_value.checked_neg()?
    } else {
        raw_value
    };

    match sign {
        0x01 | 0x03 => Some(magnitude),
        0x02 => Some(magnitude.checked_neg()?),
        _ => None,
    }
}

fn literal_fits_declared_width(value: i64, token_type: u8) -> bool {
    match token_type {
        0x01 => i8::try_from(value).is_ok(),
        0x02 => i16::try_from(value).is_ok(),
        0x03 => i32::try_from(value).is_ok(),
        0x04 => true,
        _ => false,
    }
}

fn invert_result_entry(entry: StackEntry) -> StackEntry {
    match entry {
        StackEntry::Result(result) => StackEntry::Result(invert_result(result)),
        value => value,
    }
}

fn logical_and(lhs: ConditionalResult, rhs: ConditionalResult) -> ConditionalResult {
    match (lhs, rhs) {
        (ConditionalResult::False, _) | (_, ConditionalResult::False) => ConditionalResult::False,
        (ConditionalResult::Unknown, _) | (_, ConditionalResult::Unknown) => {
            ConditionalResult::Unknown
        }
        _ => ConditionalResult::True,
    }
}

fn logical_or(lhs: ConditionalResult, rhs: ConditionalResult) -> ConditionalResult {
    match (lhs, rhs) {
        (ConditionalResult::True, _) | (_, ConditionalResult::True) => ConditionalResult::True,
        (ConditionalResult::Unknown, _) | (_, ConditionalResult::Unknown) => {
            ConditionalResult::Unknown
        }
        _ => ConditionalResult::False,
    }
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Option<u8> {
    let value = *bytes.get(*offset)?;
    *offset += 1;
    Some(value)
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Option<u32> {
    Some(u32::from_le_bytes(read_array::<4>(bytes, offset)?))
}

fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let slice = bytes.get(*offset..end)?;
    let array = <[u8; N]>::try_from(slice).ok()?;
    *offset = end;
    Some(array)
}

fn read_slice<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(len)?;
    let slice = bytes.get(*offset..end)?;
    *offset = end;
    Some(slice)
}

fn decode_utf16_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut code_units = Vec::with_capacity(bytes.len() / 2).ok()?;
    for chunk in bytes.chunks_exact(2) {
        code_units
            .push(u16::from_le_bytes([chunk[0], chunk[1]]))
            .ok()?;
    }

    let mut string = String::new();
    for character in core::char::decode_utf16(code_units.iter().copied()) {
        string.push(character.ok()?).ok()?;
    }
    Some(string)
}
