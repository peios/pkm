use crate::error::{LcsError, LcsResult};

/// LCS global monotonic sequence counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceCounter {
    next_sequence: u64,
}

impl SequenceCounter {
    /// Creates a counter with an explicit next sequence number.
    pub const fn new(next_sequence: u64) -> Self {
        Self { next_sequence }
    }

    /// Initialises from the maximum sequence reported by one or more sources.
    pub fn from_highest_persisted(max_sequence: u64) -> LcsResult<Self> {
        let next_sequence = max_sequence
            .checked_add(1)
            .ok_or(LcsError::SequenceOverflow)?;
        Ok(Self { next_sequence })
    }

    /// Returns the next sequence number LCS will allocate.
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Allocates the next sequence number and advances the counter.
    pub fn allocate(&mut self) -> LcsResult<u64> {
        let allocated = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(LcsError::SequenceOverflow)?;
        Ok(allocated)
    }

    /// Advances this counter after a source reports a newly observed persisted
    /// maximum sequence number.
    pub fn advance_past_source_max(&mut self, source_max_sequence: u64) -> LcsResult<()> {
        let candidate = source_max_sequence
            .checked_add(1)
            .ok_or(LcsError::SequenceOverflow)?;
        if candidate > self.next_sequence {
            self.next_sequence = candidate;
        }
        Ok(())
    }

    /// Rejects source-returned layer-qualified entries from the future.
    pub fn validate_source_entry_sequence(&self, sequence: u64) -> LcsResult<()> {
        if sequence >= self.next_sequence {
            return Err(LcsError::FutureSequence {
                sequence,
                next_sequence: self.next_sequence,
            });
        }
        Ok(())
    }
}
