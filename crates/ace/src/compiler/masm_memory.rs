//! Fixed-anchor memory layout for recursive-verifier MASM generation.

use std::{format, string::String};

use crate::{AceError, EXT_DEGREE, InputKey, InputLayout};

/// Relation-sized allocations, measured in base-field elements.
#[derive(Clone, Copy, Debug)]
pub struct MasmMemoryExtents {
    /// State beginning at `RELATION_STATE_START`, including scratch and padding.
    pub state_felts: usize,
    /// Encoded circuit stream following the ACE READ inputs.
    pub stream_felts: usize,
    /// Scratch row for authenticated query openings.
    pub query_row_felts: usize,
    /// OOD dispatch storage required by the relation's scatter plan.
    pub scatter_felts: usize,
}

/// Places a relation's ACE inputs between the generic verifier's fixed anchors.
///
/// Public inputs precede the lookup-challenge anchor; the remaining ACE inputs and circuit stream
/// follow it. Relation state and the query-row buffer occupy separate regions. All sizes and
/// addresses count base-field elements. This computes generation-time addresses only.
#[derive(Clone, Debug)]
pub struct MasmMemoryLayout {
    relation_state_start: usize,
    ace_inputs_start: usize,
    stream_start: usize,
    num_inputs: usize,
}

impl MasmMemoryLayout {
    /// Places the compiled ACE input vector and checks each supplied extent against its anchor.
    ///
    /// The address declarations and `NUM_QUERIES_MAX` must be decimal u32 literals. Missing,
    /// duplicate, or nonliteral declarations fail. The query buffer must end before the maximum
    /// FRI query allocation, which grows backward from `FRI_COM_PTR`.
    pub fn new(
        constants: &str,
        inputs: &InputLayout,
        extents: MasmMemoryExtents,
    ) -> Result<Self, AceError> {
        let relation_state_start = literal(constants, "RELATION_STATE_START")?;
        let challenges_start = literal(constants, "AUX_RAND_ELEM_PTR")?;
        let ood_start = literal(constants, "OOD_EVALUATIONS_PTR")?;
        let query_row_start = literal(constants, "CURRENT_TRACE_ROW_PTR")?;
        let scatter = literal(constants, "OOD_SCATTER_TABLE_PTR")?;
        let fri_start = literal(constants, "FRI_COM_PTR")?;
        let num_queries_max = literal(constants, "NUM_QUERIES_MAX")?;
        let query_row_limit = num_queries_max
            .checked_mul(4)
            .and_then(|size| fri_start.checked_sub(size))
            .ok_or_else(|| invalid("FRI queries exceed the memory before FRI_COM_PTR"))?;
        if !scatter.is_multiple_of(4)
            || !relation_state_start.is_multiple_of(4)
            || !challenges_start.is_multiple_of(8)
            || !query_row_start.is_multiple_of(8)
            || !fri_start.is_multiple_of(4)
        {
            return Err(invalid(
                "dispatch, state and FRI anchors must be word-aligned; ACE and query-row \
                 anchors must be eight-felt aligned",
            ));
        }
        if !(scatter < relation_state_start
            && relation_state_start < challenges_start
            && challenges_start < query_row_start
            && query_row_start < query_row_limit)
        {
            return Err(invalid(
                "memory anchors must order dispatch storage, relation state, ACE data, query row, \
                 and FRI data without overlap",
            ));
        }
        let beta = inputs
            .index(InputKey::AuxRandBeta)
            .ok_or_else(|| invalid("ACE inputs are missing the lookup challenges"))?;
        if beta != inputs.counts.num_public
            || (beta > 0
                && (inputs.index(InputKey::Public(0)) != Some(0)
                    || inputs.index(InputKey::Public(beta - 1)) != Some(beta - 1)))
        {
            return Err(invalid(
                "ACE public values must form a dense prefix before the lookup challenges",
            ));
        }
        let ace_inputs_start = beta
            .checked_mul(EXT_DEGREE)
            .and_then(|prefix| challenges_start.checked_sub(prefix))
            .filter(|&start| start >= relation_state_start && start.is_multiple_of(8))
            .ok_or_else(|| invalid("ACE public-input prefix exceeds its region or is unaligned"))?;
        // The generic transcript stores both extension challenges with one word store.
        if inputs.index(InputKey::AuxRandAlpha) != Some(beta + 1) || beta + 2 > inputs.total_inputs
        {
            return Err(invalid("lookup challenges must occupy adjacent beta, alpha READ slots"));
        }
        let mut layout = Self {
            relation_state_start,
            ace_inputs_start,
            stream_start: 0,
            num_inputs: inputs.total_inputs,
        };
        let first_ood = inputs
            .index(InputKey::Preprocessed { offset: 0, index: 0 })
            .ok_or_else(|| invalid("ACE inputs are missing the first OOD row"))?;
        if layout.input_ptr(first_ood)? != ood_start {
            return Err(invalid("ACE OOD inputs must begin at OOD_EVALUATIONS_PTR"));
        }
        layout.stream_start = layout.input_ptr(inputs.total_inputs)?;
        if layout.stream_start > query_row_start || !layout.stream_start.is_multiple_of(8) {
            return Err(invalid("ACE READ inputs cross the query-row anchor or are unaligned"));
        }
        if !extents.stream_felts.is_multiple_of(8) || !extents.query_row_felts.is_multiple_of(8) {
            return Err(invalid("ACE streams and query rows must be eight-felt aligned"));
        }
        for (name, start, len, limit) in [
            ("OOD dispatch table", scatter, extents.scatter_felts, relation_state_start),
            ("relation state", relation_state_start, extents.state_felts, ace_inputs_start),
            ("ACE stream", layout.stream_start, extents.stream_felts, query_row_start),
            ("query row", query_row_start, extents.query_row_felts, query_row_limit),
        ] {
            if limit.checked_sub(start).is_none_or(|capacity| len > capacity) {
                return Err(invalid(format!(
                    "{name} requires {len} felts at {start}, exceeding its limit {limit}"
                )));
            }
        }
        Ok(layout)
    }

    /// First address available for relation-specific state, after the generic control frame.
    pub fn relation_state_start(&self) -> usize {
        self.relation_state_start
    }

    /// First ACE READ input, including the public-input prefix.
    pub fn ace_inputs_start(&self) -> usize {
        self.ace_inputs_start
    }

    /// First circuit-stream element, immediately after the ACE READ inputs.
    pub fn stream_start(&self) -> usize {
        self.stream_start
    }

    /// Resolves an ACE input index to its first felt; `total_inputs` denotes the stream start.
    pub fn input_ptr(&self, index: usize) -> Result<usize, AceError> {
        index
            .checked_mul(EXT_DEGREE)
            .and_then(|offset| self.ace_inputs_start.checked_add(offset))
            .filter(|&ptr| index <= self.num_inputs && u32::try_from(ptr).is_ok())
            .ok_or_else(|| invalid("ACE input index is outside the READ section or u32 memory"))
    }
}

fn invalid(message: impl Into<String>) -> AceError {
    AceError::InvalidInputLayout { message: message.into() }
}

fn literal(source: &str, name: &str) -> Result<usize, AceError> {
    let prefix = format!("pub const {name} = ");
    let mut values = source.lines().filter_map(|line| line.trim().strip_prefix(&prefix));
    let value = values.next().ok_or_else(|| invalid(format!("missing {name}")))?;
    if values.next().is_some() {
        return Err(invalid(format!("duplicate {name}")));
    }
    value
        .split('#')
        .next()
        .unwrap_or(value)
        .trim()
        .parse::<u32>()
        .map(|value| value as usize)
        .map_err(|_| invalid(format!("{name} must be a decimal u32 literal")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InputCounts;

    const ANCHORS: &str = "pub const RELATION_STATE_START = 1024
        pub const AUX_RAND_ELEM_PTR = 4096
        pub const OOD_EVALUATIONS_PTR = 4104
        pub const CURRENT_TRACE_ROW_PTR = 8192
        pub const OOD_SCATTER_TABLE_PTR = 768
        pub const FRI_COM_PTR = 10240
        pub const NUM_QUERIES_MAX = 8";
    const EXTENTS: MasmMemoryExtents = MasmMemoryExtents {
        state_felts: 8,
        stream_felts: 128,
        query_row_felts: 64,
        scatter_felts: 128,
    };

    fn inputs(num_public: usize) -> InputLayout {
        InputLayout::new_masm(InputCounts {
            preprocessed_width: 8,
            width: 8,
            aux_width: 4,
            num_aux_boundary: 1,
            num_public,
            num_randomness: 2,
            num_quotient_chunks: 4,
        })
    }

    #[test]
    fn places_public_inputs_before_the_shared_challenge_anchor() {
        for count in [4, 32] {
            let inputs = inputs(count);
            let layout = MasmMemoryLayout::new(ANCHORS, &inputs, EXTENTS).unwrap();
            assert_eq!(
                layout.input_ptr(inputs.index(InputKey::AuxRandBeta).unwrap()).unwrap(),
                4096
            );
            assert_eq!(layout.input_ptr(0).unwrap(), 4096 - EXT_DEGREE * count);
            assert_eq!(layout.input_ptr(inputs.total_inputs).unwrap(), layout.stream_start());
            assert!(layout.input_ptr(inputs.total_inputs + 1).is_err());
            assert!(layout.input_ptr(usize::MAX).is_err());
        }
    }

    #[test]
    fn construction_checks_exact_fits_alignment_and_overflow() {
        let inputs = inputs(4);
        let public_start = 4096 - 8;
        let state = public_start - 1024;
        let stream = 8192 - (public_start + EXT_DEGREE * inputs.total_inputs);
        // FRI's eight query records occupy 32 felts before its commitment anchor.
        let row = 10240 - 32 - 8192;
        let scatter = 1024 - 768;
        let exact = MasmMemoryExtents {
            state_felts: state,
            stream_felts: stream,
            query_row_felts: row,
            scatter_felts: scatter,
        };
        // State can end with a scalar field and need not fill a word.
        for state_felts in state - 3..=state {
            MasmMemoryLayout::new(ANCHORS, &inputs, MasmMemoryExtents { state_felts, ..exact })
                .unwrap();
        }
        for (state_felts, stream_felts, query_row_felts, scatter_felts, expected) in [
            (state + 1, stream, row, scatter, "relation state"),
            (state, stream + 8, row, scatter, "ACE stream"),
            (state, stream, row + 8, scatter, "query row"),
            (state, stream, row, scatter + 1, "OOD dispatch table"),
            (usize::MAX, stream, row, scatter, "relation state"),
            (state, usize::MAX - 7, row, scatter, "ACE stream"),
            (state, stream, usize::MAX - 7, scatter, "query row"),
            (state, stream, row, usize::MAX, "OOD dispatch table"),
            (state, stream - 1, row, scatter, "aligned"),
            (state, stream, row - 1, scatter, "aligned"),
        ] {
            let extents = MasmMemoryExtents {
                state_felts,
                stream_felts,
                query_row_felts,
                scatter_felts,
            };
            let error = MasmMemoryLayout::new(ANCHORS, &inputs, extents).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn rejects_invalid_anchors_and_input_extents() {
        for (from, to, expected) in [
            ("pub const CURRENT_TRACE_ROW_PTR = 8192", "", "missing"),
            ("OOD_EVALUATIONS_PTR = 4104", "OOD_EVALUATIONS_PTR = 4112", "OOD inputs"),
            ("8192", "4096 + 4096", "literal"),
            ("8192", "4294967296", "literal"),
            ("8192", "8193", "aligned"),
            ("OOD_SCATTER_TABLE_PTR = 768", "OOD_SCATTER_TABLE_PTR = 769", "aligned"),
            ("OOD_SCATTER_TABLE_PTR = 768", "OOD_SCATTER_TABLE_PTR = 1024", "order"),
            ("8192", "2048", "order"),
            ("NUM_QUERIES_MAX = 8", "NUM_QUERIES_MAX = 4096", "FRI queries"),
        ] {
            let source = ANCHORS.replace(from, to);
            let error =
                MasmMemoryLayout::new(&source, &inputs(4), EXTENTS).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
        }
        let duplicate = format!("{ANCHORS}\npub const CURRENT_TRACE_ROW_PTR = 8192");
        assert!(
            MasmMemoryLayout::new(&duplicate, &inputs(4), EXTENTS)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        assert!(MasmMemoryLayout::new(ANCHORS, &inputs(2048), EXTENTS).is_err());
        let mut stale_prefix = inputs(4);
        stale_prefix.counts.num_public += 4;
        assert!(
            MasmMemoryLayout::new(ANCHORS, &stale_prefix, EXTENTS)
                .unwrap_err()
                .to_string()
                .contains("dense prefix")
        );
        for total in [0, 4096, usize::MAX] {
            let mut inputs = inputs(4);
            inputs.total_inputs = total;
            assert!(MasmMemoryLayout::new(ANCHORS, &inputs, EXTENTS).is_err());
        }
    }
}
