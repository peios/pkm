//! Ingestion: registry-shaped rule input -> validated `Forest`.
//!
//! The glue lowers each rule key under
//! `Machine\System\Network\Rules\<Layer>\...` into a [`RuleInput`] tree and
//! hands it here. Ingestion parses, validates, resolves priority
//! inheritance, lints for layer-impossible facts, and collects the
//! machinery name sets (tags, counter streams, counter views) — rules are
//! the only source of those names, so the whole set is known here and can
//! be checked. A forest that builds is semantically total; a forest that
//! doesn't is rejected whole (atomic generations: the old policy stays
//! until a new one builds).
//!
//! Two checks span the name sets:
//! - hash collisions among distinct tag (or stream) names are refused, so
//!   the store hash is a deterministic identity within a running policy;
//! - a counter view over a stream no rule writes is statically dead (it
//!   can only ever read absent) and is refused. Streams are machine-scoped,
//!   so the writer may live in another layer's forest: [`check_forests`]
//!   runs that check across every forest being published together.

use crate::action::{parse_action, Action, ParseFailure};
use crate::condition::{
    AddrPattern, CondKey, CondOp, Condition, CounterView, FactFamily, FactId, IntPattern,
};
use crate::error::{BuildError, LintKind, LintWarning};
use crate::hash::name_hash;
use crate::pkm_alloc::{String as PkmString, TryClone, Vec as PkmVec};
use crate::rule::{Forest, Layer, NamedHash, Rule};
use crate::snapshot::tcp_flags;
use crate::strutil::{join_path, str_to_pkm};
use crate::value::RegValue;

/// One rule key as read from the registry: its name, its values, and its
/// subkeys (exceptions).
#[derive(Debug, Default)]
pub struct RuleInput {
    /// The key name.
    pub name: PkmString,
    /// The key's values: (value name, value).
    pub values: PkmVec<(PkmString, RegValue)>,
    /// The key's subkeys.
    pub children: PkmVec<RuleInput>,
}

/// A built forest plus its lint findings.
#[derive(Debug)]
pub struct BuildOutput {
    /// The validated forest.
    pub forest: Forest,
    /// Non-fatal findings for the authoring surface to shout about.
    pub lints: PkmVec<LintWarning>,
}

/// What the walk collects across the whole forest.
struct Collector {
    tag_names: PkmVec<NamedHash>,
    streams: PkmVec<NamedHash>,
    views: PkmVec<CounterView>,
    /// First (rule path, value key) mentioning each view, parallel to
    /// `views` — attribution for the dead-read refusal.
    view_sites: PkmVec<(PkmString, PkmString)>,
}

impl Collector {
    fn note_name(list: &mut PkmVec<NamedHash>, name: &str) -> Result<(), BuildError> {
        if list.iter().any(|n| n.name.as_str() == name) {
            return Ok(());
        }
        list.push(NamedHash {
            name: str_to_pkm(name)?,
            hash: name_hash(name),
        })?;
        Ok(())
    }

    fn note_tag(&mut self, name: &str) -> Result<(), BuildError> {
        Self::note_name(&mut self.tag_names, name)
    }

    fn note_stream(&mut self, name: &str) -> Result<(), BuildError> {
        Self::note_name(&mut self.streams, name)
    }

    fn note_view(
        &mut self,
        view: CounterView,
        rule: &PkmString,
        key: &str,
    ) -> Result<u32, BuildError> {
        if let Some(i) = self.views.iter().position(|v| *v == view) {
            return Ok(i as u32);
        }
        self.views.push(view)?;
        self.view_sites
            .push((rule.try_clone_err()?, str_to_pkm(key)?))?;
        Ok((self.views.len() - 1) as u32)
    }

    /// Records the names an action list mentions (PROMPT fallbacks
    /// included: a fallback TAG is still a TAG).
    fn note_actions(&mut self, actions: &[Action]) -> Result<(), BuildError> {
        for action in actions {
            match action {
                Action::Tag { name, .. } => self.note_tag(name.as_str())?,
                Action::Count { name, .. } => self.note_stream(name.as_str())?,
                Action::Prompt { fallback, .. } => {
                    if let Some(inner) = fallback.action() {
                        self.note_actions(core::slice::from_ref(inner))?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Builds a layer's forest from registry-shaped input.
pub fn build_forest(layer: Layer, roots: &[RuleInput]) -> Result<BuildOutput, BuildError> {
    let mut out_roots = PkmVec::new();
    let mut lints = PkmVec::new();
    let mut collector = Collector {
        tag_names: PkmVec::new(),
        streams: PkmVec::new(),
        views: PkmVec::new(),
        view_sites: PkmVec::new(),
    };
    for input in roots {
        let rule = build_rule(layer, input, "", 0, &mut lints, &mut collector)?;
        out_roots.push(rule)?;
    }
    check_collisions(&collector.tag_names, true)?;
    check_collisions(&collector.streams, false)?;
    Ok(BuildOutput {
        forest: Forest {
            layer,
            roots: out_roots,
            tag_names: collector.tag_names,
            streams: collector.streams,
            views: collector.views,
            view_sites: collector.view_sites,
        },
        lints,
    })
}

/// Cross-forest checks for a set of forests published together: tag and
/// stream hashes must be distinct across all of them (the stores are
/// machine-wide), and every counter view must have a writer somewhere.
pub fn check_forests(forests: &[&Forest]) -> Result<(), BuildError> {
    let mut all_tags: PkmVec<NamedHash> = PkmVec::new();
    let mut all_streams: PkmVec<NamedHash> = PkmVec::new();
    for forest in forests {
        for t in forest.tag_names.iter() {
            if !all_tags.iter().any(|n| n.name.as_str() == t.name.as_str()) {
                all_tags.push(t.try_clone()?)?;
            }
        }
        for s in forest.streams.iter() {
            if !all_streams
                .iter()
                .any(|n| n.name.as_str() == s.name.as_str())
            {
                all_streams.push(s.try_clone()?)?;
            }
        }
    }
    check_collisions(&all_tags, true)?;
    check_collisions(&all_streams, false)?;
    for forest in forests {
        for (i, view) in forest.views.iter().enumerate() {
            if !all_streams.iter().any(|s| s.hash == view.hash) {
                let (rule, key) = &forest.view_sites[i];
                return Err(BuildError::CounterNeverWritten {
                    rule: rule.try_clone_err()?,
                    key: key.try_clone_err()?,
                });
            }
        }
    }
    Ok(())
}

fn check_collisions(names: &[NamedHash], tags: bool) -> Result<(), BuildError> {
    for (i, a) in names.iter().enumerate() {
        for b in names[i + 1..].iter() {
            if a.hash == b.hash && a.name.as_str() != b.name.as_str() {
                let a = a.name.try_clone_err()?;
                let b = b.name.try_clone_err()?;
                return Err(if tags {
                    BuildError::TagHashCollision { a, b }
                } else {
                    BuildError::StreamHashCollision { a, b }
                });
            }
        }
    }
    Ok(())
}

fn build_rule(
    layer: Layer,
    input: &RuleInput,
    parent_path: &str,
    parent_priority: i64,
    lints: &mut PkmVec<LintWarning>,
    collector: &mut Collector,
) -> Result<Rule, BuildError> {
    let name = input.name.as_str();
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return Err(BuildError::BadRuleName {
            rule: join_path(parent_path, name)?,
        });
    }
    let path = join_path(parent_path, name)?;

    let mut conditions = PkmVec::new();
    let mut priority = parent_priority;
    let mut enabled = true;
    let mut actions = PkmVec::new();

    for (key, value) in input.values.iter() {
        match key.as_str() {
            "Priority" => {
                priority = value.as_int().ok_or(BuildError::BadPriority {
                    rule: path.try_clone_err()?,
                })?;
            }
            "Enabled" => match value.as_int() {
                Some(0) => enabled = false,
                Some(1) => enabled = true,
                _ => {
                    return Err(BuildError::BadEnabled {
                        rule: path.try_clone_err()?,
                    })
                }
            },
            "Actions" => {
                let list = match value {
                    RegValue::List(items) => items,
                    _ => {
                        return Err(BuildError::BadActionsValue {
                            rule: path.try_clone_err()?,
                        })
                    }
                };
                for item in list.iter() {
                    let expr = item.as_str().ok_or(BuildError::BadActionsValue {
                        rule: path.try_clone_err()?,
                    })?;
                    actions.push(parse_action_for_rule(expr, &path)?)?;
                }
            }
            _ => {
                let condition = parse_condition(key.as_str(), value, &path, collector)?;
                lint_condition(layer, &condition, &path, key.as_str(), lints)?;
                conditions.push(condition)?;
            }
        }
    }
    collector.note_actions(actions.as_slice())?;

    // A rule key with no Actions value is legal and means NULL (abstain):
    // authors nest pure-grouping rules. An empty Actions list means the same.

    let mut children = PkmVec::new();
    for child in input.children.iter() {
        children.push(build_rule(
            layer,
            child,
            path.as_str(),
            priority,
            lints,
            collector,
        )?)?;
    }

    Ok(Rule {
        name: str_to_pkm(name)?,
        conditions,
        priority,
        enabled,
        actions,
        children,
    })
}

fn parse_action_for_rule(expr: &str, path: &PkmString) -> Result<Action, BuildError> {
    match parse_action(expr) {
        Ok(action) => Ok(action),
        Err(ParseFailure::Alloc) => Err(BuildError::Alloc),
        Err(ParseFailure::Parse(detail)) => Err(BuildError::BadAction {
            rule: path.try_clone_err()?,
            detail,
        }),
    }
}

fn parse_condition(
    key: &str,
    value: &RegValue,
    path: &PkmString,
    collector: &mut Collector,
) -> Result<Condition, BuildError> {
    let (prefix, op_name) = match key.rfind('.') {
        Some(i) => (&key[..i], &key[i + 1..]),
        None => {
            return Err(BuildError::UnknownFact {
                rule: path.try_clone_err()?,
                key: str_to_pkm(key)?,
            })
        }
    };

    let cond_key = if let Some(tag) = prefix.strip_prefix("Tag.") {
        if tag.is_empty() {
            return Err(BuildError::UnknownFact {
                rule: path.try_clone_err()?,
                key: str_to_pkm(key)?,
            });
        }
        collector.note_tag(tag)?;
        CondKey::Tag {
            name: str_to_pkm(tag)?,
            hash: name_hash(tag),
        }
    } else if let Some(spec) = prefix.strip_prefix("Counter.") {
        let view = CounterView::parse(spec).map_err(|_| BuildError::BadCounterView {
            rule: path.try_clone_err().unwrap_or_default(),
            key: str_to_pkm(key).unwrap_or_default(),
        })?;
        CondKey::Counter(collector.note_view(view, path, key)?)
    } else {
        match FactId::from_key(prefix) {
            Some(fact) => CondKey::Fact(fact),
            None => {
                return Err(BuildError::UnknownFact {
                    rule: path.try_clone_err()?,
                    key: str_to_pkm(key)?,
                })
            }
        }
    };

    let family = match &cond_key {
        CondKey::Fact(fact) => fact.family(),
        CondKey::Tag { .. } | CondKey::Counter(_) => FactFamily::Int,
    };
    let fact_for_names = match &cond_key {
        CondKey::Fact(fact) => Some(*fact),
        _ => None,
    };

    let bad_op = || mk_error(path, key, false);
    let bad_pattern = || mk_error(path, key, true);

    let op = match (op_name, family) {
        ("Equal", FactFamily::Int) => {
            let mut patterns = PkmVec::new();
            for_each_element(value, &mut |el| {
                let p = int_pattern(el, fact_for_names).ok_or(())?;
                patterns.push(p).map_err(|_| ())
            })
            .map_err(|()| bad_pattern())?;
            CondOp::EqualInt(patterns)
        }
        ("Equal", FactFamily::Str) => {
            let mut patterns = PkmVec::new();
            for_each_element(value, &mut |el| {
                let s = el.as_str().ok_or(())?;
                patterns.push(str_to_pkm(s).map_err(|_| ())?).map_err(|_| ())
            })
            .map_err(|()| bad_pattern())?;
            CondOp::EqualStr(patterns)
        }
        ("Equal", FactFamily::Addr) => {
            let mut patterns = PkmVec::new();
            for_each_element(value, &mut |el| {
                let s = el.as_str().ok_or(())?;
                let p = addr_pattern(s).ok_or(())?;
                patterns.push(p).map_err(|_| ())
            })
            .map_err(|()| bad_pattern())?;
            CondOp::EqualAddr(patterns)
        }
        ("Equal", FactFamily::Mac) => {
            let mut patterns = PkmVec::new();
            for_each_element(value, &mut |el| {
                let s = el.as_str().ok_or(())?;
                let mac = parse_mac(s).ok_or(())?;
                patterns.push(mac).map_err(|_| ())
            })
            .map_err(|()| bad_pattern())?;
            CondOp::EqualMac(patterns)
        }
        ("GreaterThan", FactFamily::Int) => {
            CondOp::Gt(scalar_int(value).ok_or_else(bad_pattern)?)
        }
        ("LessThan", FactFamily::Int) => {
            CondOp::Lt(scalar_int(value).ok_or_else(bad_pattern)?)
        }
        ("Has", FactFamily::Flags) => CondOp::Has(flag_mask(value).ok_or_else(bad_pattern)?),
        ("Hasnt", FactFamily::Flags) => {
            CondOp::Hasnt(flag_mask(value).ok_or_else(bad_pattern)?)
        }
        _ => return Err(bad_op()),
    };

    Ok(Condition { key: cond_key, op })
}

/// Builds a `BadPattern`/`BadOperator` error; if allocating the message
/// context itself fails, degrades to `Alloc`.
fn mk_error(path: &PkmString, key: &str, pattern: bool) -> BuildError {
    match (
        crate::pkm_alloc::TryClone::try_clone(path),
        str_to_pkm(key),
    ) {
        (Ok(rule), Ok(key)) => {
            if pattern {
                BuildError::BadPattern { rule, key }
            } else {
                BuildError::BadOperator { rule, key }
            }
        }
        _ => BuildError::Alloc,
    }
}

fn for_each_element(
    value: &RegValue,
    f: &mut dyn FnMut(&RegValue) -> Result<(), ()>,
) -> Result<(), ()> {
    match value {
        RegValue::List(items) => {
            if items.is_empty() {
                return Err(());
            }
            for item in items.iter() {
                match item {
                    RegValue::List(_) => return Err(()),
                    other => f(other)?,
                }
            }
            Ok(())
        }
        other => f(other),
    }
}

fn scalar_int(value: &RegValue) -> Option<i64> {
    match value {
        RegValue::Int(v) => Some(*v),
        RegValue::Str(s) => s.as_str().parse().ok(),
        RegValue::List(_) => None,
    }
}

fn int_pattern(el: &RegValue, fact: Option<FactId>) -> Option<IntPattern> {
    match el {
        RegValue::Int(v) => Some(IntPattern::Exact(*v)),
        RegValue::Str(s) => {
            let s = s.as_str();
            if let Ok(v) = s.parse::<i64>() {
                return Some(IntPattern::Exact(v));
            }
            if let Some((a, b)) = s.split_once('-') {
                if let (Ok(a), Ok(b)) = (a.parse::<i64>(), b.parse::<i64>()) {
                    if a <= b {
                        return Some(IntPattern::Range(a, b));
                    }
                }
                return None;
            }
            named_int(s, fact?).map(IntPattern::Exact)
        }
        RegValue::List(_) => None,
    }
}

/// Authoring-friendly names for two facts whose numeric values nobody
/// remembers. Case-insensitive.
fn named_int(name: &str, fact: FactId) -> Option<i64> {
    let eq = |s: &str| -> bool {
        name.len() == s.len()
            && name
                .bytes()
                .zip(s.bytes())
                .all(|(a, b)| a.to_ascii_lowercase() == b)
    };
    match fact {
        FactId::EtherType => {
            if eq("ipv4") {
                Some(0x0800)
            } else if eq("ipv6") {
                Some(0x86DD)
            } else if eq("arp") {
                Some(0x0806)
            } else {
                None
            }
        }
        FactId::Protocol => {
            if eq("tcp") {
                Some(6)
            } else if eq("udp") {
                Some(17)
            } else if eq("icmp") {
                Some(1)
            } else if eq("icmpv6") {
                Some(58)
            } else if eq("sctp") {
                Some(132)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn addr_pattern(s: &str) -> Option<AddrPattern> {
    use core::net::IpAddr;
    if let Some((addr, prefix)) = s.split_once('/') {
        let addr: IpAddr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let width = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > width {
            return None;
        }
        return Some(AddrPattern::Cidr { addr, prefix });
    }
    if let Ok(addr) = s.parse::<IpAddr>() {
        return Some(AddrPattern::Exact(addr));
    }
    // Ranges only make sense for v4 here ('-' never appears in a v6
    // address, and v6 ranges are better written as prefixes anyway).
    if let Some((a, b)) = s.split_once('-') {
        let a: IpAddr = a.parse().ok()?;
        let b: IpAddr = b.parse().ok()?;
        if a.is_ipv4() == b.is_ipv4() {
            return Some(AddrPattern::Range(a, b));
        }
    }
    None
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for slot in out.iter_mut() {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *slot = u8::from_str_radix(part, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

fn flag_mask(value: &RegValue) -> Option<u8> {
    let mut mask = 0u8;
    let mut ok = true;
    let result = for_each_element(value, &mut |el| {
        match el.as_str().and_then(tcp_flags::from_name) {
            Some(bit) => {
                mask |= bit;
                Ok(())
            }
            None => {
                ok = false;
                Err(())
            }
        }
    });
    if result.is_err() || !ok || mask == 0 {
        return None;
    }
    Some(mask)
}

/// Facts that never exist at a layer: conditions over them are legal but
/// can never hold (absent-fact law), so the authoring surface should shout.
fn lint_condition(
    layer: Layer,
    condition: &Condition,
    path: &PkmString,
    key: &str,
    lints: &mut PkmVec<LintWarning>,
) -> Result<(), BuildError> {
    let never = match layer {
        Layer::Packet => false,
        // The RawPacket seat stands before conntrack (inbound) and reads no
        // other layer's state in either direction (ratified visibility law).
        Layer::RawPacket => matches!(
            condition.key,
            CondKey::Fact(FactId::FlowState) | CondKey::Tag { .. }
        ),
    };
    if never {
        lints.push(LintWarning {
            rule: path.try_clone_err()?,
            key: str_to_pkm(key)?,
            kind: LintKind::FactNeverPresentAtLayer,
        })?;
    }
    Ok(())
}

/// Small extension: fallible clone that maps into `BuildError`.
trait TryCloneErr: Sized {
    fn try_clone_err(&self) -> Result<Self, BuildError>;
}

impl TryCloneErr for PkmString {
    fn try_clone_err(&self) -> Result<Self, BuildError> {
        crate::pkm_alloc::TryClone::try_clone(self).map_err(|_| BuildError::Alloc)
    }
}
