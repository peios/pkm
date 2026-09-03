//! Shared error types for the PNP semantic core.

pub use crate::pkm_alloc::AllocError;
use crate::pkm_alloc::String as PkmString;

/// Why a rule forest was rejected at ingestion.
///
/// Every variant that concerns a specific rule carries the rule's registry
/// path so the authoring surface can point at the offending key.
#[derive(Debug)]
pub enum BuildError {
    /// Allocation failed while building the forest.
    Alloc,
    /// A rule value key names a fact the vocabulary does not contain.
    UnknownFact { rule: PkmString, key: PkmString },
    /// A rule value key uses an operator the fact does not support
    /// (e.g. `GreaterThan` on an address, `Has` on anything but `TcpFlags`).
    BadOperator { rule: PkmString, key: PkmString },
    /// A match value could not be parsed for its fact's type.
    BadPattern { rule: PkmString, key: PkmString },
    /// A `Counter.<n>(...)` key does not parse as a view (bad duration,
    /// unknown key fact, duplicate arguments, window over the horizon).
    BadCounterView { rule: PkmString, key: PkmString },
    /// The `Actions` value is missing, not a list, or contains a non-string.
    BadActionsValue { rule: PkmString },
    /// One action expression could not be parsed.
    BadAction { rule: PkmString, detail: ActionParseError },
    /// PROMPT fallbacks nest deeper than the compiled-in chain cap.
    PromptChainTooDeep { rule: PkmString },
    /// `Priority` is present but not an integer.
    BadPriority { rule: PkmString },
    /// `Enabled` is present but not 0 or 1.
    BadEnabled { rule: PkmString },
    /// A rule name is empty or contains a path separator.
    BadRuleName { rule: PkmString },
    /// Two distinct tag names hash to the same store identity. Names are
    /// the author's; refusing the generation keeps the hash a deterministic
    /// identity within a running policy.
    TagHashCollision { a: PkmString, b: PkmString },
    /// Two distinct counter stream names hash alike (same reasoning).
    StreamHashCollision { a: PkmString, b: PkmString },
    /// A `Counter.<n>` condition views a stream no rule anywhere writes:
    /// statically dead (it can only ever read absent), refused loudly.
    CounterNeverWritten { rule: PkmString, key: PkmString },
    /// A rule reads a tag that a higher layer writes: a downward read,
    /// forbidden by the visibility law (tags flow strictly upward).
    TagDownwardRead { rule: PkmString, name: PkmString },
    /// A `Present` condition on a fact that never exists at the rule's
    /// layer. Every other operator over such a fact is merely dead (the
    /// absent-fact law makes it false, and the lint says so); `Present`
    /// looks through that law, so `X.Present = 0` on a fact absent by law
    /// would be an always-true condition wearing a meaningful name. Refused.
    PresentNeverAtLayer { rule: PkmString, key: PkmString },
    /// A condition key that cannot exist at the rule's layer at all: a
    /// `Tag.*` or `Counter.*` read in the interface layer, where no store
    /// stands behind it.
    KeyNotAtLayer { rule: PkmString, key: PkmString },
    /// An action the rule's layer does not speak: `JOIN`, `IGNORE` or
    /// `DOWN` outside the interface layer, or anything but those, `NULL`
    /// and `REPORT` inside it.
    ActionNotAtLayer { rule: PkmString },
}

impl From<AllocError> for BuildError {
    fn from(_: AllocError) -> Self {
        BuildError::Alloc
    }
}

/// Why a single action expression failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionParseError {
    /// The action name is not in the language.
    UnknownAction,
    /// Wrong number of arguments for the action.
    BadArity,
    /// An argument has the wrong shape (e.g. non-integer REPORT level).
    BadArgument,
    /// `REJECT(Kind)` names a kind that is not minted.
    UnknownRejectKind,
    /// Unbalanced parentheses or trailing garbage.
    Malformed,
}

/// A non-fatal ingestion finding: the rule is legal but almost certainly
/// wrong, e.g. a condition on a fact that never exists at the rule's layer
/// (the absent-fact law makes it silently never match). Surfaced loudly by
/// authoring surfaces; never blocks ingestion.
#[derive(Debug)]
pub struct LintWarning {
    /// Registry path of the rule.
    pub rule: PkmString,
    /// The value key that triggered the warning.
    pub key: PkmString,
    /// What is wrong with it.
    pub kind: LintKind,
}

/// The kinds of lint findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintKind {
    /// The fact never exists at this layer, so the condition can never hold.
    FactNeverPresentAtLayer,
}
