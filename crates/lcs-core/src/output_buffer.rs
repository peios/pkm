use crate::error::{LcsError, LcsResult};

/// Caller-supplied shape of one variable-size output buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputBufferRequest {
    pub buffer_len: usize,
    pub pointer_present: bool,
}

/// Shape classification before required-size comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputBufferShape {
    /// Zero-length probe; the pointer is ignored by PSD-005.
    Probe,
    /// Non-zero buffer with a non-null pointer.
    WritableCandidate { len: usize },
}

/// Required-size decision for one output buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputBufferDecision {
    Fits {
        provided_len: usize,
        required_len: usize,
    },
    TooSmall {
        provided_len: usize,
        required_len: usize,
    },
}

/// Aggregate result for an ioctl with one or more output buffers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputBufferAggregate {
    AllFit,
    TooSmall,
}

/// Classifies one `(buffer_length, buffer_ptr)` pair under the uniform ABI.
pub fn classify_output_buffer_request(
    request: OutputBufferRequest,
) -> LcsResult<OutputBufferShape> {
    if request.buffer_len == 0 {
        return Ok(OutputBufferShape::Probe);
    }

    if !request.pointer_present {
        return Err(LcsError::MissingOutputBufferPointer {
            len: request.buffer_len,
        });
    }

    Ok(OutputBufferShape::WritableCandidate {
        len: request.buffer_len,
    })
}

/// Compares a caller buffer against the operation's known required byte size.
pub fn validate_output_buffer_required_size(
    request: OutputBufferRequest,
    required_len: usize,
) -> LcsResult<OutputBufferDecision> {
    classify_output_buffer_request(request)?;

    if request.buffer_len < required_len {
        Ok(OutputBufferDecision::TooSmall {
            provided_len: request.buffer_len,
            required_len,
        })
    } else {
        Ok(OutputBufferDecision::Fits {
            provided_len: request.buffer_len,
            required_len,
        })
    }
}

/// Aggregates per-buffer decisions before any output buffer is filled.
pub fn aggregate_output_buffer_decisions(
    decisions: &[OutputBufferDecision],
) -> OutputBufferAggregate {
    if decisions
        .iter()
        .any(|decision| matches!(decision, OutputBufferDecision::TooSmall { .. }))
    {
        OutputBufferAggregate::TooSmall
    } else {
        OutputBufferAggregate::AllFit
    }
}
