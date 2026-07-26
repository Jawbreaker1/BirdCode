# Literal-stream code-generation calibration

This fixture is BirdCode's first retained **development calibration**, not a
claim that one model or harness is generally superior. It exercises the loop we
need in the product: generate a complete bounded artifact, evaluate real
behavior, return typed mechanical evidence, and allow one evidence-bound repair.

The current formal cohort below was frozen on 2026-07-20 with evaluator v3.
Every candidate received the exact same [`task.md`](./task.md). The evaluator
saw candidate bytes, not the provider label, and applied the same formatter,
seven acceptance tests, and strict Clippy gate in a fresh temporary Cargo
workspace. Provider identity was disclosed only after each report existed.

## Formal result

| Blind label | Disclosed source after scoring | Attempt 1 | One allowed repair | Honest interpretation |
| --- | --- | --- | --- | --- |
| A | Current root assistant, direct authoring | Failed strict Clippy (`similar_names`) after tests passed | **Passed** formatting, 7/7 tests, and Clippy | Non-blind development control: the root authored the fixture and had seen its tests. It validates evaluator and repair mechanics, not provider superiority. The v3 diagnostic was byte-for-byte equivalent in substance to v2, so the already-retained full replacement was reused without mutation. |
| B | BirdCode LM Studio backend, `google/gemma-4-26b-a4b`, discovered Q8_0, reasoning off | Failed formatting because the returned Rust source ended mid-implementation | Failed formatting again because the new full replacement also ended mid-implementation | A real retained failure. BirdCode sent the complete prior candidate and v3 report, retained the exact response, and did not silently complete or patch it. |
| C | Clean-room Codex subagent, requested `gpt-5.6-sol` with `ultra` reasoning | Failed only `rustfmt --check` | **Passed** formatting, 7/7 tests, and Clippy | The repair received the complete task, prior candidate, and v3 report in an isolated context. Requested profile is recorded, but this environment does not attest the effective Codex model or reasoning profile. |

Formal report hashes:

| Report | SHA-256 |
| --- | --- |
| `blind-a-v3-formal-attempt-1.json` | `5c3ebb3dc4bd6187c097bbd8556b03f1a174566ee0fa86a6eea674c6abba2251` |
| `blind-a-v3-formal-repair-1.json` | `838b880158034098608a7c09bf5eed83ec54c7ceb3366ca5c277012a0e70af0a` |
| `blind-b-v3-formal-attempt-1.json` | `419331a507f2c9b448fa4c25431ca92a3b6d21807040f55e0253d10ee67722c8` |
| `blind-b-v3-formal-repair-1.json` | `2e0982b051e5f88d21f1a3d1d2f82feb234bd5ec069262fff0ca347dac76dabd` |
| `blind-c-v3-formal-attempt-1.json` | `14f83e7c78b221152b26436cf0c6398d578611c8d8c0b04ffcfe13795e84fd8e` |
| `blind-c-v3-formal-repair-1.json` | `82d94cfbf11406fe62f6643a163fc8c70546095568b35259eb541adf66c02820` |

[`cohort-v3.json`](./cohort-v3.json) binds each blind label to both immutable
candidate generations and reports, then records the post-scoring disclosure.

The current formal reports all bind the same task (`b6f7bbe8…`), acceptance
suite (`0600fd07…`), prompt manifest (`a3f89b52…`), and evaluator v3
(`0eacb431…`). Each report additionally binds the exact candidate, extracted
source, canonical evaluator input, explicit limits, environment allowlist,
command argv, timestamps, elapsed time, exit status, bounded stdout/stderr, and
cleanup policy.

## Evaluator lineage and fail-closed hardening

The first formal cohort was produced by evaluator v2. Its exact source is
retained as `scripts/codegen_calibration_v2.mjs` with SHA-256
`63beaa356d286674194fd02086197a61a6ac3b8b0ba5f378270acb41a9934a28`.
That byte-for-byte archive and its six `blind-?-formal-*.json` reports are kept
as historical provenance; the table above and normal evaluation use
`scripts/codegen_calibration.mjs`, evaluator v3.

The v3 audit found and fixed two concrete fail-closed defects:

- v2 opened the create-new report only after executing Cargo, so an occupied
  report path prevented overwrite but did not prevent candidate effects. v3
  reserves the report with `open(..., "wx")` before reading the candidate or
  starting any subprocess, and finalizes that one reservation.
- v2 cleared the command timeout only after a normal `close` event. A spawn
  error could therefore leave the timer alive for as long as five minutes. v3
  clears it on every terminal path and still removes the temporary workspace.

V3 also reads at most 128 KiB plus one sentinel byte from a regular candidate
file and rejects malformed UTF-8 before JSON parsing. Its evaluator-input digest
is a sorted-key canonical JSON object containing the evaluator, fixture,
candidate, extracted source, task, acceptance, and prompt hashes plus every
size/output limit and the configured timeout. Changing only the timeout changes
the input digest. These changes alter both `evaluator_sha256` and
`evaluator_input_sha256`; a v2 report remains valid historical evidence, but
must never be relabeled as a v3 result. The frozen v3 source hash for the current
cohort is `0eacb431b4e5dd042f3f83b2948658f945f26d4207824571712f8275618c8afd`.

The built-in Node test suite covers exact v2 preservation, pre-execution shape
and size rejection, create-new refusal/non-overwrite, a screened passing
candidate, formatting and compilation failures, input/report hashes, command
order and stop-on-first-failure, spawn failure, environment filtering, bounded
stdout/stderr, process-group timeout termination, and observable temporary
workspace cleanup:

```sh
node --test scripts/codegen_calibration.test.mjs
```

The LM Studio generation example was hardened after this cohort was frozen.
Future calls through
`crates/backends/examples/lmstudio_codegen_calibration.rs` reserve both the
candidate path and the generation-evidence path with create-new semantics
before model inference starts. An occupied output therefore prevents the model
effect, and a failed evidence reservation releases the unused candidate
reservation. Its focused tests also prove that a second reservation cannot
replace either exact output. This later generator hardening must not be
retroactively attributed to the immutable v3 cohort above; its retained
generation records describe the code path that actually produced them.

## Evaluation and repair protocol

1. Create exactly one JSON candidate containing only `src/lib.rs`.
2. Freeze its bytes and generation provenance before evaluating it.
3. Manually screen generated source before local execution. This is a temporary
   development safety gate, not a product sandbox.
4. Run `cargo fmt --check`, then offline acceptance tests, then strict Clippy.
   Stop at the first failed gate and retain the exact evidence.
5. If repair is used, provide the complete original task, complete previous
   candidate, and complete mechanical report as untrusted data. Permit exactly
   one full replacement. Never repair the file outside the candidate model.
6. Evaluate the replacement from scratch with the same evaluator.

Reproduce any retained candidate with:

```sh
node scripts/codegen_calibration.mjs \
  --fixture evals/codegen/literal-stream-v1 \
  --candidate evals/codegen/literal-stream-v1/candidates/CANDIDATE.json \
  --report /tmp/literal-stream-report.json
```

The evaluator uses an ephemeral workspace, `cargo --offline`, a small inherited
environment allowlist, independently bounded one-MiB stdout and stderr capture,
a per-command timeout, and process-group termination on macOS/Linux.
It is **not yet a hostile-code isolation boundary**. Running an unscreened model
candidate therefore remains out of scope until BirdCode's sandboxed Execution &
Validation Plane exists.

## Provenance layout

- `candidates/` contains the immutable candidate envelopes.
- `generation/` records how each candidate was requested and produced. LM
  Studio records include exact backend catalog evidence, model ID, quantization,
  request/response bodies and hashes, token usage, reasoning setting, and timeout.
- `reports/` contains only mechanical evaluator evidence. Files containing
  `v3-formal` belong to the current cohort reported above. The unversioned
  `blind-?-formal-*` files are the historical evaluator-v2 cohort.
- Other reports and `gemma-reasoning-off-*` candidates are retained preflight
  runs from evaluator/prompt development. They must not be mixed into either
  formal cohort or used for cherry-picked claims.

One small fixture cannot establish Codex parity, code-agent completeness, or
general model quality. Its useful finding is narrower: BirdCode can already
retain a local-model failure honestly, drive an evidence-bounded repair, and
score local, Codex-requested, and manual-control artifacts through one identical
outcome-based evaluator.

## Exploratory reasoning-budget profile

An additional non-cohort run on 2026-07-20 used the same frozen repair task and
the same loaded `google/gemma-4-26b-a4b` Q8_0 model to probe reasoning/output
budget behavior. With reasoning `off`, the provider returned `finish_reason:
stop` after 1,351 output tokens, but the code artifact still ended with
unclosed delimiters. With reasoning `low`, the provider reached the 8,192-token
completion ceiling, reported 8,186 reasoning tokens, and left no complete
structured candidate; the backend correctly returned `IncompleteResponse` and
discarded the create-new candidate reservation.

The compact, hash-bound observation is retained in
[`exploratory-profile-2026-07-20.json`](./exploratory-profile-2026-07-20.json).
Its full raw generation records remain local temporary artifacts, so it is a
development signal—not a formal retained comparison. The design consequence is
still actionable: BirdCode must learn per-profile decomposition and separate
reasoning/output reservations from measured evidence. It must not branch on a
model-name heuristic or assume that a higher generic reasoning setting is
always better.
