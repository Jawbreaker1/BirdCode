# Durable root-planner release review

Date: 2026-07-19

Host: macOS / Apple Silicon (`aarch64`)

Reviewed implementation commit: `006786caec7f484a07a3d8fb1851e0246e56e154`

## Outcome

This milestone adds BirdCode's first product-wired model turn. Both the native
desktop and the CLI can discover an exact already-loaded LM Studio model,
submit a durable `PlanOnly` run, and consume typed replay plus hash-verified
artifacts from the local daemon. The daemon owns claims, bounded dispatch,
deadlines, cancellation, restart recovery, budget accounting, inference,
proposal validation, and terminal state.

The slice is deliberately read-only. It does not inspect repository contents,
call tools, execute proposed work orders, launch subagents, replan from tool
evidence, or perform an independent model-based semantic review. Acceptance
proves schema, binding, authority, budget, and graph invariants; it does not
prove that the model's plan is good. The final live run demonstrates that
limitation directly.

## Deterministic gate

The final source bytes were frozen, checked from a clean fully hydrated
snapshot, and committed without modification. The native bundle and live run
were then repeated from those same bytes. The exact gate was:

```text
npm ci
  110 packages installed; 0 vulnerabilities

cargo fmt --all -- --check
  PASS
git diff --check
  PASS
cargo test --workspace --all-targets
  PASS: 365 tests, 0 failed
cargo clippy --workspace --all-targets -- -D warnings
  PASS

npm test
  PASS: 2 files, 19 tests
npm run typecheck
  PASS
npm run build
  PASS: Vite production build, 20 modules

npm run tauri:build --workspace @birdcode/desktop
  PASS: BirdCode.app and BirdCode_0.1.0_aarch64.dmg
codesign --verify --deep --strict --verbose=2 BirdCode.app
  PASS: valid on disk; satisfies designated requirement
file BirdCode.app/Contents/MacOS/birdcode-desktop
file BirdCode.app/Contents/MacOS/birdcode-daemon
  PASS: both Mach-O 64-bit arm64
```

The app is ad-hoc signed for local verification and is not notarized. Final
bundle hashes from the clean snapshot were:

| Bundle artifact | SHA-256 |
| --- | --- |
| `BirdCode_0.1.0_aarch64.dmg` | `8ae13bef6b43a7291a99f902317af4fcc9e93e4a08ded3fbc49c8070c07ca1ac` |
| `birdcode-desktop` | `11cd8c99abee9db973bcd5ef2997924cf4f8e447416bfa3891e54ecee524cc1c` |
| bundled `birdcode-daemon` | `768c3733cddcc9ca0317391b891fff19fe13ae504542b28314fbdb3e3f3b4302` |

Loopback HTTP tests and the live LM Studio call ran outside the filesystem
sandbox because the sandbox denies local socket binds. No network dependency
was needed after the clean snapshot's `npm ci` and cached Rust dependencies.

## Final live LM Studio evidence

The final run used the implementation commit above and the same CLI → client →
daemon → supervisor → LM Studio → store path exposed by the product. The exact
invocation and commit-pinned, hash-addressed artifact payloads are retained in
[`docs/evidence/2026-07-19-root-planner-live`](../evidence/2026-07-19-root-planner-live/).

| Field | Retained value |
| --- | --- |
| Command exit | `0` |
| Backend | `lmstudio` |
| Exact loaded model | `google/gemma-4-26b-a4b` |
| Reported context | 262,144 tokens |
| Reasoning | off |
| Run purpose | `PlanOnly` |
| Run ID | `019f7bdc-f4a1-7d40-84d3-347ab32013e8` |
| Session ID | `019f7bdc-f49f-76c2-a85a-27e6317aaebd` |
| Input | Swedish goal with Japanese semantic-continuity constraint |
| Mechanical result | accepted plan with two ordered work orders |
| Semantic review | rejected: no two parallel audits or structured handoffs |
| Provider usage | 1,866 input + 1,046 output = 2,912 total tokens |
| Exact response-body SHA-256 | `5db21fca4de108fbeb01a988e02cff68f8f3f29983ebf0df409d66ebefa057db` |

The ordered run replay contained eight run-specific events:

| Sequence | Type | Event ID | Causal parent |
| ---: | --- | --- | --- |
| 2 | `RunCreated` | `019f7bdc-f4a1-7b62-a06d-09e4224dff14` | none |
| 3 | `RunClaimed` | `019f7bdc-f4a5-78e1-8438-36a64258ec54` | `019f7bdc-f4a1-7b62-a06d-09e4224dff14` |
| 4 | `RunStateChanged → Running` | `019f7bdc-f4a6-7a33-91d6-3350079a3e25` | `019f7bdc-f4a5-78e1-8438-36a64258ec54` |
| 5 | claim heartbeat | `019f7bdc-f507-7643-8610-775664631c40` | `019f7bdc-f4a6-7a33-91d6-3350079a3e25` |
| 6 | `PlannerInferencePrepared` | `019f7bdc-f529-71e0-84f1-1eb88b3a5cc1` | `019f7bdc-f507-7643-8610-775664631c40` |
| 7 | `PlannerInferenceObserved` | `019f7bdd-4340-71e0-a0c9-350a446dc5b4` | `019f7bdc-f529-71e0-84f1-1eb88b3a5cc1` |
| 8 | `PlanProposalAccepted` | `019f7bdd-4399-7ab1-baa4-673c2cef587a` | `019f7bdd-4340-71e0-a0c9-350a446dc5b4` |
| 9 | `RunStateChanged → Completed` | `019f7bdd-439d-74f2-9e23-5e1260d5ef8c` | `019f7bdd-4399-7ab1-baa4-673c2cef587a` |

The complete session contains one additional `SessionCreated` event,
`019f7bdc-f4a0-7510-82e3-2be2cf9a1e90`, at sequence 1. Every run event after
creation is bound through its recorded causal parent.

| Artifact | SHA-256 | Bytes |
| --- | --- | ---: |
| compiled prompt | `cb00f02c270e7440351e64c8123676ac4ec17ceeb0cce0a388b5e99499f302f6` | 17,639 |
| inference request | `c978b0edd3e1a99533233b9cd9953e40e1bc68b8ba4a1c488784379ecdcd8321` | 13,454 |
| provider evidence | `711cb17e7baa1caeefd0f7a359b20c2085e193045add148b790ebc74fa6a1bbd` | 9,596 |
| model proposal | `86e469458bfc56953364f2e0c1a3c86add82f432e86dc981cd7ad837c95e1030` | 2,959 |
| accepted plan | `f9a4ad5959912bdeede1683666904a6aa79273c66caeabd72125b73165e77077` | 2,388 |
| validation report | `30f5de6c69d11b8c3753b8f68222a8dda1147c3586183f1083c28ee925141b99` | 37 |

The supervisor producer was `birdcode-daemon-root-supervisor/1`. Exact
backend/model identity, reasoning, prompt and policy digests, request digest,
claim, token reservation, usage, causal parents, and terminal state are present
in replay or referenced artifacts.

### Why exit zero is not a quality pass

The model accurately restated the multilingual goal, including the Japanese
constraint, but returned two sequential discovery steps. It did not express
two dependency-independent audit orders or a structured handoff collection
step. The current validator correctly established structural safety, but it
had only one coarse root obligation and no independent semantic critic.

The next integration slice therefore needs a model-driven critic and bounded
repair/replanning loop with richer obligation decomposition. Adding English,
Swedish, or Japanese keyword rules would mask the failure and violate the
product design.

## Retained failure history

The successful transport run was preceded by two fail-closed schema failures
against the same class of multilingual goal:

| Attempt | Failure | Usage | Exact response-body SHA-256 |
| --- | --- | ---: | --- |
| 1 | model emitted three empty target selectors | 3,207 | `84bc83aed98766e4ba8f2e28b2d08b8544233e0537ba9168d415c94c859c3db0` |
| 2 | model emitted one empty search selector | 2,966 | `7879d70d4f4b7560fa797ac1f8a869a6fedf086c944415a546c887c4de2edd7f` |

Both were persisted as typed `schema_violation` failures and never normalized
with string parsing. The prompt was clarified and the conservative provider
generation schema gained the same non-empty selector bound already enforced by
the authoritative local schema. A later run then passed structural validation.
The final source-commit run above still failed the independent semantic quality
judgment, and that failure is retained rather than relabeled as success.

## Independent adversarial review

Two read-only agents audited durability/security and product truth
independently. The documentation audit was performed before final evidence was
written and identified stale claims, missing screenshots, placeholders, and
the difference between mechanical and semantic success. The kernel audit then
re-reviewed the frozen source after repairs and reported no remaining P0 or P1.

The milestone closes these concrete audit findings:

- post-commit supervisor shutdown or queue state can no longer turn a durable
  `CreateRun` mutation into a client-visible rejection;
- a lost or ambiguous `CreateRun` response retains one client-generated run ID
  and exact specification, permits only bounded exact replay, and now treats
  internal server outcomes as ambiguous rather than proof of rollback;
- desktop start and reconciliation share one atomic lifecycle reservation, so
  concurrent starts cannot replace a retained identity;
- cancellation recorded before restart, after a proposal decision, or during
  terminal-state races dominates recovery and final result projection;
- the durable dispatcher crosses its scan quantum and cannot orphan queued
  runs merely because an in-memory wake-up was lost;
- provider token usage is checked against the total context reservation before
  success, including over-reporting across restart;
- oversized native requests fail before session creation or submission;
- protocol v4 persists typed pre-inference failure phase and evidence, while
  exact provider-body hashes distinguish byte-different responses; and
- GUI controls, cancellation messages, token ceilings, reasoning choices, and
  reconciliation status now describe only executable behavior.

## Remaining limitations and follow-up risks

These items are not represented as completed by this milestone:

- full execute/delegate/replan/finish orchestration and isolated subagents;
- repository, filesystem, shell, Git, browser, API, desktop, simulator, mobile,
  Windows, and Linux tool adapters;
- context retrieval, semantic compaction, session reattachment, and a durable
  long-session UX;
- an independent model-based semantic critic and repair loop;
- desktop restart reattachment for a retained or running plan; current typed
  reconciliation state is process-local;
- retention of the exact successful HTTP body bytes themselves; current
  evidence retains the parsed response plus exact-body SHA-256;
- efficient verified range reads for large artifacts; current chunk reads
  re-verify the full bounded artifact; and
- a blind clean-room BirdCode-versus-Codex outcome run. The development audits
  above are same-lineage code reviews, not that benchmark.

Screenshots are supporting UX evidence only. The release judgment rests on
compiled code, deterministic tests, strict linting, typed replay, exit status,
artifact hashes, the real local-model run, and the explicit semantic failure
classification.
