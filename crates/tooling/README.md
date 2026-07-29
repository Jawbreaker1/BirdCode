# BirdCode repository tooling

`birdcode-tooling` is BirdCode's descriptor-confined, read-only execution
adapter for the canonical Protocol-v7 repository broker. Semantic agents decide
which typed action to request. This crate performs deterministic authority
evaluation, bounded filesystem execution and exact evidence production; it does
not classify prose, filenames, languages, model names or error strings.

There is one public authority and wire model:

- `birdcode_protocol::RepositoryToolReceiptAuthorityV2`
- `RepositoryToolCanonicalParametersV1`
- `evaluate_repository_tool_authorization_v1`
- `RepositoryToolPreparedReceiptV2`
- `RepositoryToolObservedReceiptV2` / `RepositoryToolUnknownReceiptV2`
- `RepositoryToolResultV2` and Protocol's result/evidence codecs

Tooling retains no parallel policy, operation, result, denial or receipt enum.
Its own public structs only transport exact artifact bytes between the broker
and a caller-owned artifact store.

## Supported operations

- `RepositoryTree`: byte-sorted, depth- and entry-bounded enumeration.
- `RepositoryFileRead`: offset- and byte-bounded regular-file reads.
- `LiteralSearch`: exact, case-sensitive UTF-8 byte matching. Metacharacters
  have no special meaning; this is deliberately not a regex or semantic router.

Repository paths remain Protocol `Unix { components: Vec<Vec<u8>> }` values.
No slash splitting, string normalization, extension inference or current
working directory resolution occurs in Tooling.

## Runtime integration API

The Store-backed child repository-explorer path now owns Prepared publication:

1. Construct a `RepositoryToolReceiptAuthorityV2` from the durable child work
   order and a `RepositoryBrokerEpochStateV1` from Store replay. Open one
   `RepositoryToolBroker`, then consume it into
   `birdcode_store::ChildRepositoryToolLane`.
2. Call `Store::prepare_child_repository_explorer_tool_dispatch` with only the
   retry-stable event/action/tool-call IDs and runtime clock authority. Store
   derives the binding, selected action, grant, operation, ordinal, actor,
   parent and provenance from replay.
3. The shared lane serializes broker Prepare, exact artifact retention and the
   immediate Store transaction. A fresh commit returns durable evidence plus a
   non-cloneable in-process handoff; an exact retry or restart recovery returns
   evidence only and cannot recreate effect authority.

The handoff deliberately exposes no execution method yet. Active-epoch
interruption and Store's Observed/Unknown terminal contracts must be harmonized
and generation-fenced before product execution is enabled.

The lower-level broker lifecycle used by that boundary is:

1. Pass exact canonical parameters as `RepositoryToolPrepareInputV2`.
2. Persist both returned artifacts—`canonical_parameters` and
   `prepared_receipt`—then use `project_prepared_event_v2` to append the matching
   `ChildToolPreparedV2` event. Only after Store acknowledges that event may a
   trusted integration call `execute`.
3. Call `execute(RepositoryToolExecuteInputV2)` with that exact Prepared bundle,
   its durable event ID and the runtime finish clock. Persist every
   `supporting_artifact`, then `terminal_receipt`, then use
   `project_observed_event_v2` to append the matching `ChildToolObservedV2`
   event.
4. If execution has not started, close an active-epoch Prepared with
   `record_interruption`. After a restart, activate a fresh epoch, place the old
   broker UUID in the closed set and use `reconcile_abandoned_prepared`. Persist
   the returned artifacts before using `project_unknown_event_v2` to append
   `ChildToolOutcomeUnknownV2`. The runtime supplies typed Protocol
   reason/boundary values; the adapter rejects any pair that does not map
   exactly to the broker receipt.

`verify_terminal_output_v2` independently rechecks byte/hash/media bindings,
Protocol canonical codecs and successful-result coherence. It is useful at the
daemon boundary and in tests, but it does not replace Store's causal replay.

## Store boundary obligations

Tooling cannot prove that external persistence preceded an effect. Store/runtime
integration must still enforce:

- the Prepared event and both source artifacts were durably acknowledged before
  `execute`;
- the authority is exactly the immutable work-order authority;
- caller IDs, bindings, action, grant, ordinal and Prepared event ID match the
  child lifecycle projection;
- broker epochs are activated once, closed UUIDs never become active again, and
  restart reconciliation cites a genuinely pending Prepared from a closed epoch;
- supporting and terminal artifacts are stored by their exact `ArtifactRef`
  before the terminal event is appended;
- retries/idempotent appends do not create a second terminal event.

`RepositoryToolBroker` serializes successful in-memory Prepare publication and
does not advance its sequence for duplicate IDs, encoding/size failures, lock
failure, or arithmetic exhaustion. That does not by itself order durable
commits from parallel children. `ChildRepositoryToolLane` is now that
coordinator for the Store-backed child repository-explorer Prepared path and
spans `prepare`, artifact persistence and Store acknowledgement. Other broker
callers still need an equivalent broker-epoch coordinator. Tool execution may
resume in parallel only after each exact Prepared event is acknowledged; an
in-memory Prepared bundle alone is never proof of durability.

The in-process broker consumes each active Prepared once. Restart reconciliation
also consumes each `(abandoned epoch, call ID, Prepared digest)` once in the new
broker instance. Store remains the durable cross-process authority.

## Authority, containment and races

- Protocol's evaluator sees the complete ordered grant list. Duplicate grant
  IDs anywhere in the global sibling namespace deny the call; Tooling never
  selects around malformed authority.
- The root is opened read-only with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` and
  must exactly match the Protocol root descriptor identity.
- Traversal uses `openat` relative to retained descriptors. Intermediate and
  final symlinks are never followed. Direct reads accept regular files only.
- Directory streams originate from descriptors, and names are byte-sorted.
- Every opened/reported node must remain on the root device. Nested mounts are
  rejected instead of silently broadening authority.
- Root, directory and file identities are compared around observations to
  detect ordinary mutation and replacement races.
- The broker exposes no write, process, environment, credential or network API.

These checks do not manufacture snapshot immutability. The workspace manager
must provision the read-only snapshot and writer-revocation lease represented by
Protocol authority. A privileged writer can otherwise race or restore metadata
outside what portable Unix descriptor checks can prove.

## Exact artifact limits

| Artifact | Canonical authority | Maximum |
|---|---|---:|
| Parameters | Protocol compact JSON + evaluator | hard 16 MiB; policy may deny lower |
| Prepared receipt | Protocol compact JSON | 256 KiB |
| Failure/denial/unknown evidence | Protocol typed codecs | 256 KiB |
| Observed/Unknown terminal receipt | Protocol compact JSON | 256 KiB |
| Separate successful result | Protocol result-v2 codec | 64 MiB; policy may be lower |

Successful result bytes never appear inside a terminal receipt. Read bytes use
Protocol's canonical RFC 4648 base64 result encoding. Before filesystem access,
authorization reserves an operation-specific, worst-width empty result
envelope inside the exact policy ceiling. File reads derive their content limit
from the complete canonical JSON plus base64 expansion. Tree and literal-search
collectors account for each canonical array item once and deterministically stop
with `truncated: true` before another item could cross the ceiling. The final
encoder check remains a fail-closed defense, not the first place an oversized
result is discovered.

## Platform status

`repository_tool_platform_support_v2()` reports the compiled capability.
Protocol-v7 paths and the current secure adapter are Unix-only. The adapter is
actively validated on macOS/Apple Silicon. Linux shares the Unix implementation
but still requires independent platform/release validation before a support
claim. Windows has no handle-relative adapter yet and fails closed as
`UnsupportedPlatform`; it never falls back to joined path strings. Some native
filesystems may reject byte sequences even though Protocol preserves Unix path
components losslessly.

## Verification

```sh
cargo test -p birdcode-tooling
cargo clippy -p birdcode-tooling --all-targets -- -D warnings
rustfmt --edition 2024 --check crates/tooling/src/*.rs crates/tooling/tests/*.rs
```

The adversarial suite covers all three operations, literal metacharacters,
multilingual/native paths, duplicate sibling grants, cross-root and traversal
attempts, root/intermediate symlinks, root identity races, Prepared substitution,
execute-at-most-once, same-length result mutation, results larger than the
terminal cap, tiny result ceilings, base64 expansion, long-path/count budget
truncation, Prepared/terminal caps, active interruptions, abandoned-epoch
reconciliation and duplicate reconciliation.
