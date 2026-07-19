# Foundation release-gate review — 2026-07-19

## Verdict

**GO for the BirdCode foundation milestone at source commit
`3a05d2972b2efcc2b3067594b928f90418e1e93c`.**

A separate read-only coding-agent instance reviewed the immutable commit after
the deterministic gate completed. It reported no open P0, P1, or P2 finding in
the scope below. This is a scoped engineering review, not a security
certification and not a claim that BirdCode is already a usable coding agent.

## Scope and acceptance gate

The reviewer was asked to:

- verify response provenance and fail-closed behavior in both initial and
  repair inference paths;
- verify causal execution/attempt identities and exact bundled-prompt scope;
- search for new P0-P2 correctness, security, provenance, or API-contract
  defects introduced by those fixes;
- independently validate the retained Gemma router report and its privacy
  boundaries; and
- check that README status claims match the implementation.

Acceptance required no open P0-P2 finding in that scope and a green
deterministic foundation gate. Both conditions passed.

## Defects closed before the reviewed snapshot

Earlier adversarial reviews found three material defects. Commit `3a05d297`
closed them before the final review:

1. A nominally successful backend response was not independently bound to the
   requested model, backend, raw assistant JSON, decoded value, and reported
   output-token ceiling.
2. Parallel attempts with identical candidate text could not be causally
   distinguished in the retained journal.
3. A caller-supplied manifest with the semantic-router ID could bypass current
   invariants if it used an unbundled version or mutated same-key content.

The final implementation journals before validation, rejects typed response
contract violations in both inference phases, performs at most one repair,
uses UUID v7 execution/attempt identities with an exact repair parent, retains
the parent raw-text SHA-256, and accepts only exact typed manifests and
canonical digests from the internal bundled registry. Historical bundled
router versions remain available for replay.

## Deterministic gate

The following checks passed on the reviewed source commit:

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets` — 194 Rust test executions
- `npm test` — 9 GUI tests
- `npm run typecheck`
- `npm run build`
- CLI `doctor` — `BirdCode daemon 0.1.0 is ready (protocol 2, macos/aarch64)`
- CLI `session-smoke` — a multilingual session persisted and reloaded
  successfully through the real daemon

The independent reviewer additionally reran the focused orchestrator (20/20),
LM Studio mock-HTTP (28/28), and eval-runner (13/13) suites plus focused Clippy.
It also ran the 13/13 eval-runner contract tests from an archived checkout of
the report's source commit.

Verified toolchain and host:

- macOS 26.5.2 (25F84), Apple Silicon ARM64
- Rust/Cargo 1.92.0, LLVM 21.1.3
- Node.js 22.16.0, npm 10.9.2
- Apple clang 21.0.0
- Codex CLI 0.144.5

## Retained live-model evidence

The retained report
[`2026-07-19-gemma-4-26b-q8-router-v1.1.3.json`](../../evals/reports/2026-07-19-gemma-4-26b-q8-router-v1.1.3.json)
records a live run against the already-loaded LM Studio model
`google/gemma-4-26b-a4b`, Q8_0, with reasoning off.

- Source revision: `9e12f133d60cd9dad5dd4bbc0ca6e6cedc8bde72`
- Report SHA-256:
  `0275440b73ac4ef9fe3df441b44fdced8e0bc3c4e3492662e1b744eb04565ece`
- Catalog SHA-256:
  `7a75af6b744c53b7874eabce4e891b87fdb6a9e8ce20d96e9ad8e9143c49e26b`
- Result: 9/9 passed, with nine distinct completion IDs and
  `finish_reason=stop` for every case
- Coverage: all route axes, required/forbidden evidence sections, subtask and
  clarification bounds, multilingual intent, and repository prompt injection

The reviewer decoded every raw assistant response, compared it with the
retained validated value and expectations, and confirmed all reported output
token counts remained within their fixture limits. A privacy scan found no
credentials, tokens, user filesystem paths, local model paths, or credentialed
endpoints in the report. Four earlier failing reports remain in the repository.

## Native macOS artifact verification

The source commit produced:

- `BirdCode.app`
- `BirdCode_0.1.0_aarch64.dmg`

Both the desktop executable and bundled daemon are thin ARM64 Mach-O binaries
with minimum macOS 11.0. `codesign --verify --deep --strict` passed for the
ad-hoc runtime-signed app, and `hdiutil verify` reported the DMG checksum and
partition map as valid.

SHA-256 values:

- desktop executable:
  `24ec1aba764c1abf69b5333e9779600d623f781f9179809b1ea07ffab4ac3fcd`
- bundled daemon:
  `32fb194781ea4e803a9ddf2bf1ffb78d52dc534f40c44aee636a3c950c6796a0`
- DMG:
  `f941bc2488b8dc1d7a4e7eebd0d7cc2dbaf8182bd9d4c502b2a3f2e9d4b4fcd2`

The app is not Developer ID signed or notarized; those remain separate public
distribution gates.

## Review limitations

- The agent execution loop, tools, dynamic subagents, durable orchestration
  journal, and context compaction runtime are not implemented or reviewed as
  product capabilities.
- The router executor is not wired into the daemon, GUI, CLI, or live-model
  evaluation path. Its repair flow is fake-backend tested only.
- If a future backend omits `usage.output_tokens`, the provider-neutral
  executor cannot independently count provider-specific tokens and relies on
  the backend contract. The retained LM Studio run reported usage in all nine
  cases.
- A report's CLI-supplied source revision is not a cryptographic attestation of
  the executed binary. The review instead verified the hash chain and reran
  report contracts from that commit.
- Explicit resume/replay may intentionally reuse a caller-supplied execution
  ID; attempt IDs remain separately generated.
- Windows and Linux builds are not yet verified.

## Codex Sol/Ultra status

Codex Sol/Ultra was used as a development comparison signal earlier in the
foundation work. An additional external final-snapshot pass was not performed:
the environment stopped the request before repository data was sent because
explicit approval to export the private repository and retained eval evidence
was not available. That stopped attempt is not counted as review evidence in
this document.
