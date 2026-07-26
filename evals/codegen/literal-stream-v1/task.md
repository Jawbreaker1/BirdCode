# Literal-stream Rust calibration v1

Implement exactly one dependency-free Rust library file at `src/lib.rs`.

The public API is fixed:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralMatch {
    pub offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiteralSearchResult {
    pub matches: Vec<LiteralMatch>,
    pub truncated: bool,
    pub bytes_scanned: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiteralSearchError {
    EmptyNeedle,
    ZeroMatchLimit,
    OffsetOverflow,
}

pub fn search_literal_chunks<'a, I>(
    chunks: I,
    needle: &[u8],
    max_matches: usize,
) -> Result<LiteralSearchResult, LiteralSearchError>
where
    I: IntoIterator<Item = &'a [u8]>;
```

Requirements:

- Search the logical concatenation of all chunks without assuming UTF-8.
- Detect matches spanning chunk boundaries and include overlapping matches.
- Return absolute byte offsets in ascending order.
- Retain at most `max_matches` offsets, but continue far enough to set
  `truncated=true` if and only if another match exists.
- `bytes_scanned` is the total number of input bytes consumed, including empty
  chunks.
- Return `EmptyNeedle` for an empty needle and `ZeroMatchLimit` for a zero
  match limit before consuming the iterator.
- Return `OffsetOverflow` if the absolute byte count cannot be represented by
  `u64`.
- Use memory bounded by `O(needle.len() + max_matches)` rather than joining all
  chunks.
- Use only the Rust standard library. Do not use regex, unsafe code, filesystem,
  process, environment, or network access.
- Target Rust 1.92 with edition 2024. The source must already satisfy `rustfmt`
  and strict Cargo Clippy with the `all` and `pedantic` lint groups promoted to
  errors; the evaluator will not format or repair the candidate before scoring.

This is a development calibration fixture, not a hidden superiority benchmark.
All candidates receive this exact task and are scored only by the same compiler,
tests, formatting, and lint commands. Provider/source identity is disclosed
only after the mechanical report is finalized.
