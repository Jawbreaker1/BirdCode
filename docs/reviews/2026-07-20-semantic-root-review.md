# Protocol-v5 semantic root-review release gate

Review date: `2026-07-20`

Source commit: `78a77b40483b3a6949bab8301a62483168e13d5a`

Host: macOS `26.5.2` build `25F84`, ARM64

Toolchain: Rust/Cargo `1.92.0`, Node.js `22.16.0`, npm `10.9.2`, Apple clang
`21.0.0`

## Verdict

**GO for the Protocol-v5 policy-separated semantic root-review milestone at the
pinned source commit. NO-GO for coding-agent, parallel-agent-runtime,
executing-validation-adapter, or Codex-parity claims.**

The product-wired path now compiles an initial root plan, submits the exact
candidate to a policy-separated critic, and either accepts it or authorizes one
complete replacement plan followed by one final review. Direct acceptance is
exactly two model calls; successful repair is exactly four. There is no second
repair. Typed non-acceptance or an invalid contract fails closed.

This gate proves the lifecycle through deterministic, adversarial, fake-backend
and product-surface tests. It is not a retained live Protocol-v5 run: the local
LM Studio inventory exposed only `google/gemma-4-26b-a4b`, while current policy
requires distinct exact producer and critic model IDs.

## Provenance boundary

Protocol v5 and Store schema v8 persist the prepared request before inference
and distinguish `Prepared`, `Observed`, and typed `Unknown` inference
boundaries. Store re-derives stage, backend, model, reasoning, normalized
evidence, outcome, token use, candidate, critique, validation, and receipt
bindings from durable typed state. It rejects a payload that contradicts the
retained response or attempts to forge acceptance.

Retained provider evidence consists of the canonical provider-neutral request,
exact assistant response text, parsed provider response JSON, and SHA-256 of
the exact HTTP response bytes. BirdCode does not claim to retain the exact
provider-specific HTTP request bytes or raw HTTP response bytes.

These are application-enforced Store/SQLite and artifact-root integrity checks,
not signatures, a hash chain, or external anchoring. A privileged storage owner
who can replace both database and artifact state remains outside the current
threat boundary.

## Deterministic and product gates

| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo check --workspace --all-targets` | Passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed, no warnings |
| `cargo test --workspace --all-targets` | 455 test executions, zero failures |
| Focused protocol/store/daemon provenance suites | 175 test executions, zero failures |
| `cargo build --workspace` | Passed |
| `npm test` | 23/23 tests passed |
| `npm run typecheck` | Passed |
| `npm run build` | Passed; production fixture scan had zero hits |
| `cargo test -p birdcode-cli --all-targets` | 18/18 tests passed |
| Built CLI `doctor` | Protocol 5, macOS/aarch64, ready |
| Built CLI `session-smoke` | Session `019f7cff-bb25-7413-af48-13d5a2271ed5` persisted and reloaded |
| Built CLI `models` | Discovered exact LM Studio model `google/gemma-4-26b-a4b` |
| `sh -n apps/desktop/scripts/tauri-build.sh` | Passed |
| `git diff --check` | Passed |

The first sandboxed LM Studio discovery attempt was denied at the local-network
boundary. The identical read-only command passed when run with the required
loopback-network permission; this was an environment permission result, not a
BirdCode transport failure.

## Native macOS gate

`npm run tauri:build --workspace @birdcode/desktop` built the ARM64 desktop and
daemon, produced the application bundle and DMG, cleared non-content Finder
xattrs from the generated standalone app, verified it with
`codesign --verify --deep --strict`, and verified the disk image with
`hdiutil verify` (`CRC32 C7F6ADDC`, valid).

| Artifact | Format | SHA-256 |
| --- | --- | --- |
| `birdcode-desktop` | Mach-O 64-bit executable arm64 | `8777a99761acbd329dc043560984db5f7e317df9f6327a9db8a524a452c54600` |
| `birdcode-daemon` | Mach-O 64-bit executable arm64 | `3ab0a68789467fcccaa92077611557476ca18e5a6fa58afa6f8d5e1431e397c9` |
| `BirdCode_0.1.0_aarch64.dmg` | Apple disk image | `fcb05c717b78abb5d6409634cf230617ff2277d902168301d6f63a29cc9589de` |

The bundle is ad-hoc signed. It is not Developer ID signed or notarized. This
gate does not claim strict verification of the app copy mounted from the DMG.

## Desktop capture evidence

The current README images use the exact production `App` renderer with a
development-only, non-executing documentation bridge. Their dimensions,
hashes, fixture limits, and production-bundle exclusion are retained in the
[desktop capture evidence](../evidence/2026-07-20-desktop-captures/README.md).
They are not native-window screenshots and do not prove policy preflight or a
model run.

## Clean-room audit roles and tooling

The root coordinated bounded specialists and retained responsibility for the
combined release decision. The observed roles included:

- provenance implementer and nested read-only test mapper: protocol, Store and
  supervisor inspection, patching, Rust tests and strict Clippy;
- semantic-heuristic auditor: repository search and targeted control-flow
  inspection for keyword, regexp, filename, language and error-string routing;
- Codex-parity architect: clean-room source/document/tool-surface comparison;
- release-truth auditor: read-only claim-to-code, artifact and screenshot audit;
- frontend capture verifier: renderer/fixture inspection, GUI tests,
  TypeScript/build checks and production-bundle scanning; and
- CLI validator: built-product lifecycle, persistence and local-model discovery.

The demanding comparison audits were explicitly requested with
`gpt-5.6-sol`/`ultra`. Agent result/list metadata did not attest their effective
runtime model or reasoning identity, so this gate records the requested profile
only.

No P0–P2 runtime use of keyword, regexp, filename, extension, language, or free
error-string classification was found in the audited semantic paths. One P3
provenance hardening item remains: the typed `Cancelled` boundary permits two
coarse typed reasons and could later be split for one-to-one precision.

## Codex parity boundary

The milestone closes one planning-quality precursor; it does not close the
coding-agent gap. BirdCode still lacks product-wired repository inspection,
tool execution, evidence-driven replanning, model-backed child agents, durable
child mailboxes, isolated writing worktrees, integration ownership, executing
validation adapters, context compaction/retrieval, and blind comparative runs.
None of `GAP-MA-001` through `GAP-MA-016` is passed as a complete product-path
multi-agent capability.

The next parity-bearing slice is durable parallel repository reconnaissance:
connect an accepted plan to at least two real read-only model explorers with
separate contexts and brokered tree/list, bounded file-read, and literal-search
tools; retain Prepared/Observed/Unknown effects, identities, handoffs, overlap,
cancellation, and replay; then compile a second evidence-citing planner turn.
That slice must end honestly in `Waiting`, not claim implementation completion.
