# Target validation and Codex comparison

This is the acceptance policy for backend and evaluation work. The foundation
currently runs deterministic build, protocol, persistence, CLI, desktop,
prompt-contract, and mock-HTTP backend checks. A standalone LM Studio semantic
router evaluation exists; comparable multi-backend run orchestration is not yet
wired into the daemon. `crates/validation` provides typed contracts and
collect-all policy validation for the future Execution & Validation Plane; it
does not yet execute applications or implement any platform adapter.

The provider-neutral router executor has deterministic fake-backend coverage
for first-pass acceptance, multi-section duplicate repair in one extra call,
semantic-field locking, unique-evidence preservation, non-repairable concurrent
violations, malformed/missing/extra/blank patches, backend failures, journal
failures, prompt-key scoping, causal repair provenance, sensitive-input
projection, and the hard two-call maximum. These tests do not claim that the
standalone live LM Studio eval currently uses the repair executor.

Producing better complete applications than the strongest available Codex
Sol/Ultra configuration is BirdCode's primary measured target, not a current
claim. Codex remains an independent development reference and a planned
comparison backend. Retained competitive claims must follow the complete
clean-room protocol in [benchmarking.md](benchmarking.md).

## Comparable run

A comparable run begins from a versioned `RunSpec` containing:

- user task and compiled context manifest;
- Git commit or content snapshot;
- workspace and platform manifest;
- allowed tools, permissions, and network policy;
- time, token, concurrency, and retry budgets;
- acceptance tests and semantic review rubric.

Candidates run in isolated worktrees or overlays. The system stores raw backend
events, normalized events, patches, artifacts, tests, timings, and reported
usage. Both BirdCode and comparison candidates are exercised by the same
versioned validation plan. Provider/model/agent identity is withheld from blind
semantic and visual evaluators until their findings are durably locked.

## Canonical plane lifecycle and outcomes

Every adapter and orchestration document uses one ordered lifecycle:

```text
prepare -> build -> install -> launch -> readiness -> exercise
        -> inspect_state -> collect -> validate -> terminate -> cleanup
        -> package
```

Phases that do not apply are retained explicitly; they are not silently
omitted. The wire taxonomies are separate and must not be conflated:

- `PhaseOutcome`: `succeeded`, `candidate_failure`, `infrastructure_error`,
  `timed_out`, `cancelled`, `policy_denied`, or `not_applicable`;
- `CheckOutcome`: `passed`, `failed`, or `inconclusive`; and
- `RunVerdict`: `complete_pass`, `partial`, `failed`,
  `infrastructure_invalid`, or `cancelled`.

An adapter may report an `infrastructure_error` with evidence. Only the
benchmark controller may adjudicate the final `infrastructure_invalid` run
verdict under a preregistered symmetric policy. Candidate output or a semantic
reviewer cannot assign that verdict. A later phase never erases an earlier
mandatory failure; every phase and check remains in provenance.

The current typed crate deliberately never derives `infrastructure_invalid`.
Malformed provenance, a corrupt hash chain, and adapter-reported
`infrastructure_error` all remain rejected non-invalid results unless a future
trusted benchmark-controller layer performs a separate evidence-backed
adjudication. That controller API is not implemented yet.

## Evaluation

Deterministic checks decide everything they can: compilation, tests, linting,
schema validity, file scope, exit status, and artifact comparison. Semantic
qualities are judged blind from a structured rubric with evidence references.

The evidence priority is:

1. builds, tests, package/install verification, exit and process state, API
   responses, persistence, and reproducible artifact state;
2. logs, structured traces, DOM/accessibility/platform UI state, network and
   resource observations;
3. screenshots and video captured by the validation plane; and
4. blind semantic or visual review.

Lower-priority evidence cannot override a contradictory mandatory result above
it. Vision is expected for visual and UX evaluation but is never sufficient by
itself for functional acceptance. A visual pass must cite retained media and
the corresponding real interaction/state evidence.

The bundled semantic-router catalog covers clarify, answer, inspect, and change
actions; direct and delegated strategies; read-only and write access; genuine
English, Japanese, and Arabic intent; multilingual data; repository prompt
injection; irrelevant repository context that must not be cited; and a
zero-delegation limit. Acceptance includes required and forbidden evidence
sections and bounded clarification/subtask counts in addition to the three
route axes. Its pure catalog and comparison tests live in a normal Cargo test
target and therefore run under `cargo test --workspace`.

Catalog v4 assigns evidence by causal effect on the complete routing result.
Repository context is required when it supplies otherwise unnamed delegated
targets or when rejecting a repository control attempt is a material safety
decision. It is forbidden when it merely repeats a complete request, including
the zero-delegation and direct English-change fixtures. The Arabic delegation
fixture is user-only.

Expected subtask maxima are evaluator-only scoring metadata. They are separate
from the model-visible runtime delegation cap, which defaults to four and is
zero only in the explicitly versioned zero-delegation fixture.

Live inference requires a create-new report path that is reserved with valid,
synced JSON before the first HTTP request. The reservation is finalized as a
complete `passed` or `failed` report before the process returns success or a
nonzero status. Each versioned report records the source revision, timestamp,
runner/platform identity, LM Studio version and version source, the exact
selected OpenAI identity plus bounded matching native identity/quantization
evidence, SHA-256 digests of the complete discovery response bodies, raw
inference evidence, manifest and schema hashes, raw case-file digests,
canonical prompt-input digests, and validated or rejected output. Full model
inventories, unrelated model configuration, and local model paths are omitted.
The report retains each case identifier, expectation, and runtime limit, but
case identifiers and expectations are never compiled into model input.
Model-visible data provenance uses only reproducible opaque identifiers of the
form `eval-fixture:<case SHA-256>:<ordinal>`. Configured URL user information is
rejected; every retained endpoint is also credential-, query-, and fragment-free.
Existing evidence cannot be overwritten accidentally, and discovery, inference,
validation, and expectation failures are retained before a nonzero exit.

Sol/Ultra can generate, critique, or compare work, but never serves as the only
authority for its own output. Independent agents, alternative providers, and
deterministic tests counter correlated failure modes.

## Clean-room boundary

BirdCode may use public Codex documentation, documented protocols, and
externally observable behavior. It must not inspect or copy Codex implementation
source. The Codex bridge is an optional backend adapter and is not the
implementation of BirdCode's own runtime.

The same boundary applies to benchmark fixtures and evaluators: no private
implementation code, hidden prompt extraction, credential copying, or
candidate-specific validator exceptions. Clean-room isolation, budget
normalization, repetitions, commit-reveal blinding, anti-gaming rules,
statistics, and report acceptance are normative in
[benchmarking.md](benchmarking.md).
