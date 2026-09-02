//! The evaluation algorithm (ratified design, PEI-598):
//!
//! 1. Matching reads the immutable snapshot.
//! 2. Trigger set: a node triggers iff it and all ancestors match and no
//!    child matches (shadowing exists only within a lineage).
//! 3. Every triggered rule's side effects execute — priority never
//!    suppresses side effects. Reports dedup per rule and honor the
//!    reporting threshold. Prompts are issued; with no handler answer the
//!    fallback applies (v0 has no handler transport, so every prompt takes
//!    the unanswered path immediately).
//! 4. A triggered rule yielding no verdict walks up its own parentage to
//!    the first ancestor whose actions contain a direct verdict; that
//!    ancestor speaks for the region, executing its full action list once.
//! 5. Collation: highest priority wins; ties resolve strictest
//!    (DROP > REJECT > PASS). Attribution is the yielding rule's path.
//! 6. Nothing yielded anywhere: DROP, attributed to the backstop.
//!
//! Effects are computed here and applied by the glue after collation —
//! so a COUNT lands after this evaluation's own reads (temporal feedback:
//! the next packet sees it), and a REPORT can carry the verdict.

use crate::action::{Action, CountAmount, TagOp, Verdict, MAX_PROMPT_CHAIN};
use crate::pkm_alloc::{AllocError, String as PkmString, TryClone, Vec as PkmVec};
use crate::rule::{Forest, MatchTrace, Rule};
use crate::snapshot::Snapshot;
use crate::strutil::{join_path, str_to_pkm};

/// Evaluation-time configuration.
#[derive(Debug, Clone, Copy)]
pub struct EvalContext {
    /// `CurrentReportingLevel`: a REPORT fires when its level >= this.
    /// Absent from the registry = 1 (everything fires — quietness ships as
    /// a visible value); 6 silences everything.
    pub reporting_level: u8,
}

impl Default for EvalContext {
    fn default() -> Self {
        EvalContext { reporting_level: 1 }
    }
}

/// A side effect the caller must apply (side effects always execute for
/// every triggered rule; the core computes, the glue applies).
#[derive(Debug)]
pub enum Effect {
    /// Write flow-scoped state (no-op on untracked packets — glue's call).
    Tag {
        /// Tag name.
        name: PkmString,
        /// `name_hash(name)`: the store identity.
        hash: u64,
        /// Operation.
        op: TagOp,
    },
    /// Emit into a counter stream; the store increments every table the
    /// forest materialized for it.
    Count {
        /// Stream name.
        name: PkmString,
        /// `name_hash(name)`.
        hash: u64,
        /// Resolved amount (0 when the amount was `Length` and the packet
        /// has no length fact — the glue counts that as a no-op).
        amount: u64,
    },
    /// Emit an event, attributed to the rule.
    Report {
        /// Attribution path of the reporting rule.
        rule: PkmString,
        /// Severity (1..=5), already threshold-checked.
        level: u8,
    },
    /// A PROMPT was issued (observability; v0 has no handler transport, so
    /// the fallback path has already been taken).
    PromptIssued {
        /// Attribution path of the prompting rule.
        rule: PkmString,
        /// Handler name.
        handler: PkmString,
    },
}

/// One yielded verdict, before collation. Exposed so viewers can show every
/// speaker, not just the winner.
#[derive(Debug)]
pub struct VerdictCandidate {
    /// The verdict.
    pub verdict: Verdict,
    /// The yielding rule's effective priority.
    pub priority: i64,
    /// The yielding rule's attribution path.
    pub rule: PkmString,
}

/// The result of judging one traversal against one forest.
#[derive(Debug)]
pub struct Evaluation {
    /// The layer's verdict for this traversal.
    pub verdict: Verdict,
    /// Attribution: the winning rule's path, or `backstop`.
    pub attributed_to: PkmString,
    /// Whether the backstop answered (nothing else yielded).
    pub backstop: bool,
    /// Side effects to apply.
    pub effects: PkmVec<Effect>,
    /// Every yielded verdict (winner included), for observability.
    pub candidates: PkmVec<VerdictCandidate>,
    /// When this evaluation's answer could next change on its own: the
    /// earliest flip of any live-time condition it consulted (epoch
    /// seconds, UTC), or `None` when none was consulted. The Flow layer's
    /// sentence expiry; meaningless for per-packet layers.
    pub expires_at: Option<i64>,
}

/// Judges one snapshot against one forest.
pub fn evaluate(
    forest: &Forest,
    snap: &Snapshot<'_>,
    ctx: &EvalContext,
) -> Result<Evaluation, AllocError> {
    let mut effects = PkmVec::new();
    let mut candidates = PkmVec::new();
    // Speakers already resolved this evaluation (a speaker executes once
    // even when several abstaining descendants reach it).
    let mut spoken: PkmVec<*const Rule> = PkmVec::new();
    let mut trace = MatchTrace::default();

    for root in forest.roots.iter() {
        let mut chain: PkmVec<&Rule> = PkmVec::new();
        walk(
            root, &mut chain, "", snap, ctx, &mut effects, &mut candidates, &mut spoken,
            &mut trace,
        )?;
    }

    let mut winner: Option<usize> = None;
    for (i, c) in candidates.iter().enumerate() {
        let better = match winner {
            None => true,
            Some(w) => {
                let cur = &candidates[w];
                c.priority > cur.priority
                    || (c.priority == cur.priority
                        && c.verdict.strictness() > cur.verdict.strictness())
            }
        };
        if better {
            winner = Some(i);
        }
    }

    match winner {
        Some(w) => Ok(Evaluation {
            verdict: candidates[w].verdict,
            attributed_to: candidates[w].rule.try_clone()?,
            backstop: false,
            effects,
            candidates,
            expires_at: trace.expires_at,
        }),
        None => Ok(Evaluation {
            verdict: Verdict::Drop,
            attributed_to: str_to_pkm("backstop")?,
            backstop: true,
            effects,
            candidates,
            expires_at: trace.expires_at,
        }),
    }
}

/// Recursive descent. Returns whether `rule` matched (so the parent knows
/// it was shadowed). On a triggered node (matched, no matching child), the
/// node's actions resolve; if it abstains, the parentage walk finds its
/// speaker.
#[allow(clippy::too_many_arguments)]
fn walk<'a>(
    rule: &'a Rule,
    chain: &mut PkmVec<&'a Rule>,
    parent_path: &str,
    snap: &Snapshot<'_>,
    ctx: &EvalContext,
    effects: &mut PkmVec<Effect>,
    candidates: &mut PkmVec<VerdictCandidate>,
    spoken: &mut PkmVec<*const Rule>,
    trace: &mut MatchTrace,
) -> Result<bool, AllocError> {
    if !rule.matches_traced(snap, trace) {
        return Ok(false);
    }
    let path = join_path(parent_path, rule.name.as_str())?;

    let mut any_child = false;
    chain.push(rule)?;
    for child in rule.children.iter() {
        any_child |= walk(
            child, chain, path.as_str(), snap, ctx, effects, candidates, spoken, trace,
        )?;
    }
    chain.pop();

    if any_child {
        // Shadowed: a matching descendant speaks for this region.
        return Ok(true);
    }

    // Triggered: side effects always execute.
    let yielded = resolve_rule(rule, path.as_str(), snap, ctx, effects)?;
    match yielded {
        Some(verdict) => candidates.push(VerdictCandidate {
            verdict,
            priority: rule.priority,
            rule: path,
        })?,
        None => {
            // Abstention: walk up this rule's own parentage to the first
            // ancestor with a direct verdict. Intermediate abstaining
            // ancestors execute nothing.
            let mut speaker: Option<(usize, &Rule)> = None;
            for (i, ancestor) in chain.iter().enumerate().rev() {
                if ancestor.has_direct_verdict() {
                    speaker = Some((i, *ancestor));
                    break;
                }
            }
            if let Some((depth, ancestor)) = speaker {
                let already = spoken
                    .iter()
                    .any(|p| core::ptr::eq(*p, ancestor as *const Rule));
                if !already {
                    spoken.push(ancestor as *const Rule)?;
                    let speaker_path = chain_path(&chain[..=depth])?;
                    let verdict =
                        resolve_rule(ancestor, speaker_path.as_str(), snap, ctx, effects)?;
                    // has_direct_verdict guarantees at least one verdict.
                    if let Some(verdict) = verdict {
                        candidates.push(VerdictCandidate {
                            verdict,
                            priority: ancestor.priority,
                            rule: speaker_path,
                        })?;
                    }
                }
            }
            // No speaker in the parentage: this branch contributes nothing;
            // other branches or the backstop answer.
        }
    }
    Ok(true)
}

fn chain_path(chain: &[&Rule]) -> Result<PkmString, AllocError> {
    let mut path = PkmString::new();
    for (i, rule) in chain.iter().enumerate() {
        if i > 0 {
            path.push('/')?;
        }
        for c in rule.name.as_str().chars() {
            path.push(c)?;
        }
    }
    Ok(path)
}

/// Resolves one rule's action list: pushes its side effects (report dedup
/// per rule; threshold applied) and returns its yielded verdict, if any.
/// Prompts take the unanswered path: issue the effect, apply the fallback.
fn resolve_rule(
    rule: &Rule,
    path: &str,
    snap: &Snapshot<'_>,
    ctx: &EvalContext,
    effects: &mut PkmVec<Effect>,
) -> Result<Option<Verdict>, AllocError> {
    let mut verdict: Option<Verdict> = None;
    let mut best_report: Option<u8> = None;
    for action in rule.actions.iter() {
        resolve_action(action, path, snap, effects, &mut verdict, &mut best_report, 0)?;
    }
    if let Some(level) = best_report {
        if level >= ctx.reporting_level {
            effects.push(Effect::Report {
                rule: str_to_pkm(path)?,
                level,
            })?;
        }
    }
    Ok(verdict)
}

fn resolve_action(
    action: &Action,
    path: &str,
    snap: &Snapshot<'_>,
    effects: &mut PkmVec<Effect>,
    verdict: &mut Option<Verdict>,
    best_report: &mut Option<u8>,
    depth: usize,
) -> Result<(), AllocError> {
    match action {
        Action::Null => {}
        Action::Verdict(v) => {
            *verdict = Some(match *verdict {
                Some(cur) => cur.strictest(*v),
                None => *v,
            });
        }
        Action::Tag { name, op } => effects.push(Effect::Tag {
            name: name.try_clone()?,
            hash: crate::hash::name_hash(name.as_str()),
            op: *op,
        })?,
        Action::Count { name, amount } => effects.push(Effect::Count {
            name: name.try_clone()?,
            hash: crate::hash::name_hash(name.as_str()),
            amount: match amount {
                CountAmount::Literal(v) => *v,
                CountAmount::Length => u64::from(snap.length.unwrap_or(0)),
            },
        })?,
        Action::Report { level } => {
            *best_report = Some(match *best_report {
                Some(cur) if cur >= *level => cur,
                _ => *level,
            });
        }
        Action::Prompt { handler, fallback } => {
            effects.push(Effect::PromptIssued {
                rule: str_to_pkm(path)?,
                handler: handler.try_clone()?,
            })?;
            // No handler transport in v0: the unanswered path, immediately.
            if depth < MAX_PROMPT_CHAIN {
                if let Some(inner) = fallback.action() {
                    resolve_action(inner, path, snap, effects, verdict, best_report, depth + 1)?;
                }
            }
        }
    }
    Ok(())
}
