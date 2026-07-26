use candidate::{LiteralMatch, LiteralSearchError, LiteralSearchResult, search_literal_chunks};

fn offsets(result: &LiteralSearchResult) -> Vec<u64> {
    result.matches.iter().map(|entry| entry.offset).collect()
}

#[test]
fn overlapping_matches_are_reported_in_absolute_order() {
    let result =
        search_literal_chunks([b"bananana".as_slice()], b"ana", 8).expect("valid literal search");
    assert_eq!(offsets(&result), vec![1, 3, 5]);
    assert!(!result.truncated);
    assert_eq!(result.bytes_scanned, 8);
}

#[test]
fn matches_cross_arbitrary_chunk_and_empty_boundaries() {
    let chunks = [
        b"a".as_slice(),
        b"".as_slice(),
        b"bcab".as_slice(),
        b"".as_slice(),
        b"c".as_slice(),
    ];
    let result = search_literal_chunks(chunks, b"abc", 8).expect("valid chunked search");
    assert_eq!(offsets(&result), vec![0, 3]);
    assert!(!result.truncated);
    assert_eq!(result.bytes_scanned, 6);
}

#[test]
fn binary_input_never_requires_utf8() {
    let chunks = [
        [0xff, 0x00].as_slice(),
        [0xfe, 0xff].as_slice(),
        [0x00, 0xfe].as_slice(),
    ];
    let result =
        search_literal_chunks(chunks, &[0xff, 0x00, 0xfe], 4).expect("binary literal search");
    assert_eq!(
        result.matches,
        vec![LiteralMatch { offset: 0 }, LiteralMatch { offset: 3 }]
    );
    assert!(!result.truncated);
    assert_eq!(result.bytes_scanned, 6);
}

#[test]
fn truncation_requires_a_real_additional_match() {
    let chunks = [b"aaaa".as_slice()];
    let limited = search_literal_chunks(chunks, b"aa", 2).expect("limited search");
    assert_eq!(offsets(&limited), vec![0, 1]);
    assert!(limited.truncated);
    assert_eq!(limited.bytes_scanned, 4);

    let exact =
        search_literal_chunks([b"aaa".as_slice()], b"aa", 2).expect("exact-capacity search");
    assert_eq!(offsets(&exact), vec![0, 1]);
    assert!(!exact.truncated);
}

#[test]
fn empty_needle_and_zero_limit_fail_before_iteration() {
    struct PanicIterator;

    impl<'a> IntoIterator for &'a PanicIterator {
        type Item = &'a [u8];
        type IntoIter = std::iter::Empty<&'a [u8]>;

        fn into_iter(self) -> Self::IntoIter {
            panic!("invalid input must fail before consuming chunks")
        }
    }

    let chunks = PanicIterator;
    assert_eq!(
        search_literal_chunks(&chunks, b"", 1),
        Err(LiteralSearchError::EmptyNeedle)
    );
    assert_eq!(
        search_literal_chunks(&chunks, b"x", 0),
        Err(LiteralSearchError::ZeroMatchLimit)
    );
}

#[test]
fn no_match_and_short_input_are_complete() {
    let result = search_literal_chunks(
        [b"".as_slice(), b"ab".as_slice(), b"".as_slice()],
        b"abcd",
        3,
    )
    .expect("short search");
    assert!(result.matches.is_empty());
    assert!(!result.truncated);
    assert_eq!(result.bytes_scanned, 2);
}

#[test]
fn large_stream_does_not_change_match_semantics() {
    let block = vec![b'x'; 1024 * 1024];
    let chunks =
        std::iter::repeat_n(block.as_slice(), 8).chain(std::iter::once(b"needle".as_slice()));
    let result = search_literal_chunks(chunks, b"needle", 1).expect("large bounded search");
    assert_eq!(
        result.matches,
        vec![LiteralMatch {
            offset: 8 * 1024 * 1024,
        }]
    );
    assert!(!result.truncated);
    assert_eq!(result.bytes_scanned, 8 * 1024 * 1024 + 6);
}
