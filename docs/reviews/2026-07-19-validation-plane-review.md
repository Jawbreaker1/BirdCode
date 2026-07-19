# Execution & Validation Plane release-gate review — 2026-07-19

## Verdict

**GO for the typed Execution & Validation Plane foundation at source commit
`405ff2d5e51e4adeb7ec4159cc5d33f41590e2ec`.**

The reviewed milestone defines bounded, provider-neutral contracts for targets,
commands, evidence, provenance, policy validation, sealing, and blind review.
It does not execute processes or applications, implement a platform adapter,
prove reviewer independence, or establish that BirdCode outperforms Codex.

## Reviewed scope

The release gate covered:

- the new `birdcode-validation` crate and its 18 adversarial integration tests;
- the normative product, orchestration, validation, and clean-room benchmark
  specifications;
- consistency between current implementation status and README claims;
- a same-model-lineage Codex code audit plus a separate local Gemma design
  review; and
- the existing workspace, CLI, GUI, and native macOS packaging gates after the
  validation crate joined the workspace.

The implementation introduces one canonical 12-phase lifecycle, composite
surface/platform targets, lossless native command encodings, frozen validation
plans and policies, explicit evidence priority, bounded collect-all validation,
hash-linked append-only provenance, a consuming run seal, and evaluator-local
opaque identifiers. The default adapter catalog is empty by design.

## Deterministic gate

The following checks passed on the reviewed source content:

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets` — 212 Rust test executions
- `cargo test -p birdcode-validation` — 18/18 adversarial integration tests
- `npm test` — 9/9 GUI tests
- `npm run typecheck`
- `npm run build`
- `cargo build --workspace`
- CLI `doctor` — `BirdCode daemon 0.1.0 is ready (protocol 2, macos/aarch64)`
- CLI `session-smoke` — session
  `019f7890-b8cd-7ec3-8275-53685a3a7183` persisted and reloaded through the
  real daemon
- `npm run tauri:build --workspace @birdcode/desktop`

The focused validation gate was rerun immediately before the source commit:
18/18 tests, formatting, and Clippy with `-D warnings` all passed.

Verified host and toolchain:

- macOS 26.5.2 (25F84), Apple Silicon ARM64
- Rust/Cargo 1.92.0, LLVM 21.1.3
- Node.js 22.16.0, npm 10.9.2
- Apple clang 21.0.0
- Codex CLI 0.144.5

## Native macOS artifact verification

The reviewed source content produced a native `BirdCode.app` and
`BirdCode_0.1.0_aarch64.dmg`. The desktop executable and bundled daemon are
thin ARM64 Mach-O binaries with minimum macOS 11.0 and SDK 26.5.
`codesign --verify --deep --strict` passed for the ad-hoc signed app, and
`hdiutil verify` passed for the DMG.

SHA-256 values:

- desktop executable:
  `24ec1aba764c1abf69b5333e9779600d623f781f9179809b1ea07ffab4ac3fcd`
- bundled daemon:
  `32fb194781ea4e803a9ddf2bf1ffb78d52dc534f40c44aee636a3c950c6796a0`
- DMG:
  `a871046f1b53fd00d8111dc60f0ef10761fe7843b6da30ad16aaba4027080824`

The app is not Developer ID signed or notarized. Those remain separate public
distribution gates.

## Review evidence

### Codex code and contract audit

A read-only Codex subagent audited the frozen validation source and reported GO
with no open P0 or P1 finding. It reran the focused crate check, tests, and
format gate; a separate test subagent ran focused Clippy. This is useful
adversarial review but **not independent model review**: the producing and
reviewing agents share the same model lineage.

A separate publication audit verified all nine source hashes in the retained
Gemma report, parsed the JSON, checked local Markdown links, and found no
private absolute paths, credentials, conflict markers, placeholders, or
unsupported current-capability claims.

### Local Gemma cross-lineage secondary review

The retained structured report
[`2026-07-19-validation-plane-gemma-review.json`](2026-07-19-validation-plane-gemma-review.json)
binds the exact reviewed file corpus and inference instruction by SHA-256. The
review used the already-running local LM Studio endpoint and the backend-reported
model `google/gemma-4-26b-a4b` with temperature 0.

- Completion ID: `chatcmpl-r5w7rv265zrfw26pue5t9f`
- Created: `2026-07-19T04:13:01Z`
- Prompt tokens: 44,980
- Completion tokens: 1,007
- Finish reason: `stop`
- Instruction SHA-256:
  `67782b68f843c73d488e0ea4795441454f28fab2ad14ce2a2eac1b8ea6553e8b`
- Corpus SHA-256:
  `b2d8a567e2ce4db826c913691aa2d32abe46c6c8d5e77ad3a4283b7579f27d94`

Gemma returned `fail` with one alleged P0, three alleged P1s, and one P2. The
P0/P1 claims were rejected after direct code inspection and passing targeted
tests: phase advancement is blocked while any prior attempt is open;
saturating resource accounting and native-size conversion fail closed; and
guessing secrets from arbitrary URL text would add a prohibited brittle
semantic heuristic rather than a typed broker boundary. The P2 request for
more granular digest diagnostics is non-blocking. Gemma is a secondary review
signal, not the acceptance authority and not proof of cryptographically exact
model lineage.

### Requirements and overclaim audit

The documentation review ended GO with no open P0–P2 issue. Before the frozen
commit it required one canonical lifecycle, LLM-authored semantic obligation
coverage, reviewer independence based on model/backend/deployment lineage, and
sealed rotating holdouts for superiority claims. It also removed two potential
overclaims: artifact/resolved-byte data is caller- or adapter-declared rather
than attested, and the current blind seal/disclosure exists only in memory.

## Deliberate limitations and next gates

- No process, browser, API, CLI/TUI, desktop, simulator, Android, Windows, or
  Linux adapter executes yet; target variants are requirements, not support.
- Durable seal reload, atomic persistence, signatures/external anchoring,
  verdict lock, and controlled unblinding require a trusted controller.
- Artifact bytes are neither fetched nor attested, and evidence contents are
  not anonymized by this crate.
- Callers must bound transport frames before deserialization.
- Full Windows Unicode environment-name comparison is an adapter requirement;
  the contract layer checks exact and ASCII case aliases.
- Comparison-grade backend deployment, model revision, weights/quantization,
  identity verification, and reviewer-role eligibility remain integration
  gates.
- Repair/rewind currently creates a new immutable run rather than mutating an
  earlier phase.

## Codex Sol/Ultra benchmark status

No fair BirdCode-versus-Codex outcome benchmark has been run. The common
adapter/controller layer and blind benchmark runner do not exist yet, so this
milestone cannot measure complete-application superiority. No external
final-snapshot Codex execution was performed because explicit approval to send
the private repository snapshot outside the local environment was unavailable.
That stopped path is not counted as evidence.

The normative protocol in [`benchmarking.md`](../benchmarking.md) requires the
strongest normally selectable Codex Sol/Ultra configuration at the dated gate,
equivalent immutable inputs and budgets, repeated clean-room runs, one blind
validation harness, commit/reveal identity disclosure, retained failures, and
sealed rotating holdouts before any superiority claim is permitted.
