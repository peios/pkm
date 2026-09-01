//! The PNP action language: parsing and representation.
//!
//! Six actions, three species (ratified design, PEI-598):
//! - verdicts (PASS / DROP / REJECT) — dispositions, at most one yielded per
//!   rule after resolution;
//! - facts & noise (TAG / COUNT / REPORT) — side effects, never terminal;
//! - deferral (PROMPT) plus NULL, the explicit abstention.
//!
//! Grammar per action expression: `NAME` or `NAME(arg, arg, ...)`, ASCII
//! whitespace ignored everywhere, action names case-insensitive. A PROMPT
//! fallback is itself an action expression (nesting capped).

use crate::error::ActionParseError;
use crate::pkm_alloc::{AllocError, String as PkmString};
use crate::strutil::str_to_pkm;

/// How deep PROMPT fallbacks may nest, e.g. `PROMPT(a, PROMPT(b, DROP))`
/// has depth 2. Compiled-in chain cap from the ratified design.
pub const MAX_PROMPT_CHAIN: usize = 4;

/// A disposition. Strictness order: DROP > REJECT > PASS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// This layer approves; higher layers still judge.
    Pass,
    /// Refuse, and tell the sender (protocol-phrased; kinds unminted).
    Reject,
    /// Refuse silently.
    Drop,
}

impl Verdict {
    /// Strictness rank; higher wins a tie at equal priority.
    pub fn strictness(self) -> u8 {
        match self {
            Verdict::Pass => 0,
            Verdict::Reject => 1,
            Verdict::Drop => 2,
        }
    }

    /// Canonical action-language name.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Reject => "REJECT",
            Verdict::Drop => "DROP",
        }
    }

    /// The stricter of two verdicts.
    pub fn strictest(self, other: Verdict) -> Verdict {
        if other.strictness() > self.strictness() {
            other
        } else {
            self
        }
    }
}

/// A TAG operation on flow-scoped state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagOp {
    /// Set the tag to a value.
    Set(i64),
    /// Increment by an amount (default 1).
    Increment(i64),
    /// Decrement by an amount (default 1).
    Decrement(i64),
}

/// One parsed action.
#[derive(Debug)]
pub enum Action {
    /// Do nothing; defer to parentage.
    Null,
    /// Yield a verdict.
    Verdict(Verdict),
    /// Defer to a userspace handler; on no answer, the fallback applies.
    Prompt {
        /// Handler name.
        handler: PkmString,
        /// Applied when the handler returns NULL or never answers.
        fallback: Fallback,
    },
    /// Write flow-scoped state (no-op on untracked packets).
    Tag {
        /// Tag name.
        name: PkmString,
        /// Operation to apply.
        op: TagOp,
    },
    /// Increment a machine-scoped named counter cell.
    Count {
        /// Counter name.
        name: PkmString,
        /// Amount to add (default 1).
        amount: u64,
    },
    /// Emit an event (fires when level >= CurrentReportingLevel; at most one
    /// emission per rule per evaluation).
    Report {
        /// Severity, 1..=5; higher is more important.
        level: u8,
    },
}

/// A PROMPT fallback: a boxed action, allocated fallibly.
#[derive(Debug)]
pub struct Fallback(pub crate::pkm_alloc::Vec<Action>);

impl Fallback {
    /// The fallback action, or `None` for an implicit/explicit NULL.
    pub fn action(&self) -> Option<&Action> {
        self.0.iter().next()
    }
}

/// Parses one action expression. Whitespace is ignored; names are
/// case-insensitive.
pub fn parse_action(expr: &str) -> Result<Action, ParseFailure> {
    let mut compact = PkmString::new();
    for c in expr.chars() {
        if !c.is_ascii_whitespace() {
            compact.push(c).map_err(|_| ParseFailure::Alloc)?;
        }
    }
    let (action, rest) = parse_one(compact.as_str(), 0)?;
    if !rest.is_empty() {
        return Err(ParseFailure::Parse(ActionParseError::Malformed));
    }
    Ok(action)
}

/// Parse failure: either the expression is bad, or allocation failed.
#[derive(Debug)]
pub enum ParseFailure {
    /// The expression is malformed; see the inner error.
    Parse(ActionParseError),
    /// Allocation failed.
    Alloc,
}

impl From<AllocError> for ParseFailure {
    fn from(_: AllocError) -> Self {
        ParseFailure::Alloc
    }
}

fn parse_one(input: &str, prompt_depth: usize) -> Result<(Action, &str), ParseFailure> {
    let name_end = input
        .find(['(', ',', ')'])
        .unwrap_or(input.len());
    let name = &input[..name_end];
    let rest = &input[name_end..];

    let mut upper = [0u8; 8];
    if name.is_empty() || name.len() > upper.len() {
        return Err(ParseFailure::Parse(ActionParseError::UnknownAction));
    }
    for (i, b) in name.bytes().enumerate() {
        upper[i] = b.to_ascii_uppercase();
    }
    let name = core::str::from_utf8(&upper[..name.len()])
        .map_err(|_| ParseFailure::Parse(ActionParseError::UnknownAction))?;

    let (args, rest) = split_args(rest)?;
    let action = match name {
        "NULL" => {
            expect_arity(&args, 0)?;
            Action::Null
        }
        "PASS" => {
            expect_arity(&args, 0)?;
            Action::Verdict(Verdict::Pass)
        }
        "DROP" => {
            expect_arity(&args, 0)?;
            Action::Verdict(Verdict::Drop)
        }
        "REJECT" => {
            // Kinds are unminted: `REJECT(x)` is rejected at ingestion with a
            // dedicated error so authors learn the slot exists but is closed.
            if !args.is_empty() {
                return Err(ParseFailure::Parse(ActionParseError::BadArity));
            }
            Action::Verdict(Verdict::Reject)
        }
        "PROMPT" => {
            if prompt_depth >= MAX_PROMPT_CHAIN {
                return Err(ParseFailure::Parse(ActionParseError::Malformed));
            }
            if args.is_empty() || args.len() > 2 {
                return Err(ParseFailure::Parse(ActionParseError::BadArity));
            }
            let handler = str_to_pkm(args[0])?;
            if handler.is_empty() {
                return Err(ParseFailure::Parse(ActionParseError::BadArgument));
            }
            let mut fallback = crate::pkm_alloc::Vec::new();
            if let Some(text) = args.get(1) {
                let (inner, left) = parse_one(text, prompt_depth + 1)?;
                if !left.is_empty() {
                    return Err(ParseFailure::Parse(ActionParseError::Malformed));
                }
                match inner {
                    Action::Null => {}
                    other => fallback.push(other)?,
                }
            }
            Action::Prompt {
                handler,
                fallback: Fallback(fallback),
            }
        }
        "TAG" => {
            if args.len() < 2 || args.len() > 3 {
                return Err(ParseFailure::Parse(ActionParseError::BadArity));
            }
            let tag_name = str_to_pkm(args[0])?;
            if tag_name.is_empty() {
                return Err(ParseFailure::Parse(ActionParseError::BadArgument));
            }
            let op_name = args[1];
            let amount = match args.get(2) {
                Some(a) => Some(
                    parse_int(a).ok_or(ParseFailure::Parse(ActionParseError::BadArgument))?,
                ),
                None => None,
            };
            let op = match (upper_eq(op_name, "SET"), upper_eq(op_name, "INCREMENT"), upper_eq(op_name, "DECREMENT")) {
                (true, _, _) => TagOp::Set(amount.ok_or(ParseFailure::Parse(ActionParseError::BadArity))?),
                (_, true, _) => TagOp::Increment(amount.unwrap_or(1)),
                (_, _, true) => TagOp::Decrement(amount.unwrap_or(1)),
                _ => return Err(ParseFailure::Parse(ActionParseError::BadArgument)),
            };
            Action::Tag { name: tag_name, op }
        }
        "COUNT" => {
            if args.is_empty() || args.len() > 2 {
                return Err(ParseFailure::Parse(ActionParseError::BadArity));
            }
            let counter = str_to_pkm(args[0])?;
            if counter.is_empty() {
                return Err(ParseFailure::Parse(ActionParseError::BadArgument));
            }
            let amount = match args.get(1) {
                Some(a) => {
                    let v = parse_int(a)
                        .ok_or(ParseFailure::Parse(ActionParseError::BadArgument))?;
                    if v < 0 {
                        return Err(ParseFailure::Parse(ActionParseError::BadArgument));
                    }
                    v as u64
                }
                None => 1,
            };
            Action::Count {
                name: counter,
                amount,
            }
        }
        "REPORT" => {
            expect_arity(&args, 1)?;
            let level = parse_int(args[0])
                .ok_or(ParseFailure::Parse(ActionParseError::BadArgument))?;
            if !(1..=5).contains(&level) {
                return Err(ParseFailure::Parse(ActionParseError::BadArgument));
            }
            Action::Report { level: level as u8 }
        }
        _ => return Err(ParseFailure::Parse(ActionParseError::UnknownAction)),
    };
    Ok((action, rest))
}

/// Splits a leading `(...)` argument list off `input`. Returns the argument
/// substrings (split on top-level commas only) and the remainder after the
/// closing parenthesis. No leading `(` means an empty argument list.
type Args<'a> = crate::pkm_alloc::Vec<&'a str>;

fn split_args(input: &str) -> Result<(Args<'_>, &str), ParseFailure> {
    let mut args = Args::new();
    if !input.starts_with('(') {
        return Ok((args, input));
    }
    let bytes = input.as_bytes();
    let mut depth = 0usize;
    let mut start = 1usize;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    if i > start {
                        args.push(&input[start..i])?;
                    } else if !args.is_empty() {
                        // Trailing comma: `TAG(x,)`.
                        return Err(ParseFailure::Parse(ActionParseError::Malformed));
                    }
                    return Ok((args, &input[i + 1..]));
                }
            }
            b',' if depth == 1 => {
                if i == start {
                    return Err(ParseFailure::Parse(ActionParseError::Malformed));
                }
                args.push(&input[start..i])?;
                start = i + 1;
            }
            _ => {}
        }
    }
    Err(ParseFailure::Parse(ActionParseError::Malformed))
}

fn expect_arity(args: &Args<'_>, want: usize) -> Result<(), ParseFailure> {
    if args.len() != want {
        return Err(ParseFailure::Parse(ActionParseError::BadArity));
    }
    Ok(())
}

fn parse_int(s: &str) -> Option<i64> {
    s.parse::<i64>().ok()
}

fn upper_eq(s: &str, upper: &str) -> bool {
    s.len() == upper.len()
        && s.bytes()
            .zip(upper.bytes())
            .all(|(a, b)| a.to_ascii_uppercase() == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_verdicts_case_insensitively() {
        assert!(matches!(
            parse_action("pass").unwrap(),
            Action::Verdict(Verdict::Pass)
        ));
        assert!(matches!(
            parse_action(" DROP ").unwrap(),
            Action::Verdict(Verdict::Drop)
        ));
        assert!(matches!(
            parse_action("Reject").unwrap(),
            Action::Verdict(Verdict::Reject)
        ));
        assert!(matches!(parse_action("NULL").unwrap(), Action::Null));
    }

    #[test]
    fn parses_nested_prompt_with_spaces() {
        let a = parse_action("PROMPT( user , PROMPT(dpi, DROP) )").unwrap();
        match a {
            Action::Prompt { handler, fallback } => {
                assert_eq!(handler.as_str(), "user");
                match fallback.action().unwrap() {
                    Action::Prompt { handler, fallback } => {
                        assert_eq!(handler.as_str(), "dpi");
                        assert!(matches!(
                            fallback.action().unwrap(),
                            Action::Verdict(Verdict::Drop)
                        ));
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn prompt_chain_cap_is_enforced() {
        let deep = "PROMPT(a,PROMPT(b,PROMPT(c,PROMPT(d,PROMPT(e,DROP)))))";
        assert!(matches!(
            parse_action(deep),
            Err(ParseFailure::Parse(ActionParseError::Malformed))
        ));
    }

    #[test]
    fn parses_tag_count_report() {
        match parse_action("TAG(seen, INCREMENT)").unwrap() {
            Action::Tag { name, op } => {
                assert_eq!(name.as_str(), "seen");
                assert_eq!(op, TagOp::Increment(1));
            }
            other => panic!("unexpected {other:?}"),
        }
        match parse_action("TAG(mark, SET, 7)").unwrap() {
            Action::Tag { op, .. } => assert_eq!(op, TagOp::Set(7)),
            other => panic!("unexpected {other:?}"),
        }
        match parse_action("COUNT(synburst)").unwrap() {
            Action::Count { name, amount } => {
                assert_eq!(name.as_str(), "synburst");
                assert_eq!(amount, 1);
            }
            other => panic!("unexpected {other:?}"),
        }
        match parse_action("REPORT(3)").unwrap() {
            Action::Report { level } => assert_eq!(level, 3),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_expressions() {
        assert!(parse_action("").is_err());
        assert!(parse_action("ALLOW").is_err());
        assert!(parse_action("PASS(1)").is_err());
        assert!(parse_action("TAG(x, SET)").is_err()); // SET needs a value
        assert!(parse_action("REPORT(0)").is_err());
        assert!(parse_action("REPORT(6)").is_err());
        assert!(parse_action("COUNT(x, -1)").is_err());
        assert!(parse_action("PROMPT()").is_err());
        assert!(parse_action("DROP)").is_err());
        assert!(parse_action("TAG(x,").is_err());
        assert!(parse_action("DROP PASS").is_err());
    }

    #[test]
    fn verdict_strictness_order_is_drop_reject_pass() {
        assert_eq!(Verdict::Pass.strictest(Verdict::Reject), Verdict::Reject);
        assert_eq!(Verdict::Reject.strictest(Verdict::Drop), Verdict::Drop);
        assert_eq!(Verdict::Drop.strictest(Verdict::Pass), Verdict::Drop);
    }
}
