//! The rule atom and the forest it forms.

use crate::action::{Action, Verdict};
use crate::condition::Condition;
use crate::pkm_alloc::{String as PkmString, Vec as PkmVec};
use crate::snapshot::Snapshot;

/// Which rules layer a forest belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// The packet layer proper: judged at each traversal's richest seat.
    Packet,
    /// The wire-proximate escape hatch: judged at the device seats.
    RawPacket,
}

impl Layer {
    /// Registry key name under `Machine\System\Network\Rules\`.
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Packet => "Packet",
            Layer::RawPacket => "RawPacket",
        }
    }
}

/// One rule: a named registry key, its match, its standing, its actions,
/// and its exceptions (children, subset-scoped).
#[derive(Debug)]
pub struct Rule {
    /// The registry key name — the attribution handle.
    pub name: PkmString,
    /// Conjunction of match conditions (empty = matches everything).
    pub conditions: PkmVec<Condition>,
    /// Effective priority (inheritance already resolved at ingestion).
    pub priority: i64,
    /// Disabled rules do not match, and their subtree is unreachable.
    pub enabled: bool,
    /// The rule's actions.
    pub actions: PkmVec<Action>,
    /// Exceptions: children carve regions out of this rule's scope.
    pub children: PkmVec<Rule>,
}

impl Rule {
    /// Whether the rule matches a snapshot (disabled rules never match).
    pub fn matches(&self, snap: &Snapshot) -> bool {
        self.enabled && self.conditions.iter().all(|c| c.matches(snap))
    }

    /// Whether the action list contains a direct verdict (PASS/DROP/REJECT
    /// at the top level — verdicts inside PROMPT fallbacks do not count).
    /// This is what makes a rule eligible to speak for an abstaining
    /// descendant in the parentage walk.
    pub fn has_direct_verdict(&self) -> bool {
        self.actions
            .iter()
            .any(|a| matches!(a, Action::Verdict(_)))
    }

    /// The strictest direct verdict, if any.
    pub fn direct_verdict(&self) -> Option<Verdict> {
        let mut out: Option<Verdict> = None;
        for action in self.actions.iter() {
            if let Action::Verdict(v) = action {
                out = Some(match out {
                    Some(cur) => cur.strictest(*v),
                    None => *v,
                });
            }
        }
        out
    }
}

/// A forest of rule trees for one layer. Tree order carries no meaning.
#[derive(Debug)]
pub struct Forest {
    /// The layer this forest governs.
    pub layer: Layer,
    /// The tree roots (each policy source ships complete trees).
    pub roots: PkmVec<Rule>,
}
