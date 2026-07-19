# Clean-room outcome benchmark protocol

This document defines the target protocol for comparing BirdCode with the
strongest available Codex Sol/Ultra configuration and with other coding-agent
harnesses. It is a normative design, not a claim that the complete benchmark
runner or the product capabilities being measured already exist.

The protocol extends the general policy in [validation.md](validation.md).
BirdCode's current implemented scope remains documented in the repository
[README](../README.md).

## 1. Objective

The benchmark measures whether a candidate produces a complete, working result
under a declared resource envelope. It does not reward a convincing transcript,
the number of agents launched, or similarity to another harness's internal
behavior.

Every retained comparison MUST be:

- **clean-room:** based only on public interfaces, public documentation, and
  externally observable behavior; no Codex or competitor implementation source
  may be inspected or copied;
- **symmetric:** candidates receive the same task materials and are judged by
  the same version of the Execution & Validation Plane;
- **blind:** candidate identity is unavailable to semantic and visual judges
  until scores and findings are locked;
- **outcome-based:** builds, tests, launched applications, real state, and
  captured evidence take precedence over self-reported success;
- **versioned and immutable:** manifests, fixtures, validators, budgets, and
  scoring rules are frozen before scored inference begins; and
- **auditable:** all scored successes, failures, retries, exclusions, and
  provenance are retained.

No benchmark result is a security certification. A result applies only to the
declared tasks, candidate versions, models, settings, platforms, and budget
stratum.

## 2. Experiment families and attribution

Benchmark reports MUST identify exactly one of the following experiment
families. Results from different families MUST NOT be merged into a single
leaderboard number.

### 2.1 Harness-isolation experiment

This experiment is the only one that may attribute a difference primarily to
harness quality. Every candidate uses the same exact base-model deployment,
model revision, quantization where relevant, reasoning setting, sampling
configuration, context ceiling, and provider endpoint. Task inputs, tools,
permissions, concurrency, retry policy, and resource ceilings are also matched.

If a candidate cannot use that deployment without changing its normal agent
contract, the incompatibility is reported; a different model MUST NOT be
silently substituted.

### 2.2 End-to-end system experiment

This experiment compares complete systems: for example, BirdCode with a
declared model stack against the strongest externally verifiable Codex
Sol/Ultra configuration available when the run is frozen. It answers which
system produced better outcomes inside the declared envelope. Because base
models, inference infrastructure, and orchestration may differ, it MUST NOT be
described as proof that either harness alone is better.

Remote systems with undisclosed compute or token accounting cannot be called
compute-normalized. They may be compared at matched observable wall-clock,
monetary, request, concurrency, and retry ceilings, with all unknown resource
dimensions called out explicitly.

### 2.3 BirdCode model-robustness experiment

This experiment runs one frozen BirdCode harness against a preregistered matrix
of open-source model profiles, including smaller or weaker models. It measures
degradation, recovery, and resource tradeoffs from adaptive decomposition,
parallel candidates, specialist agents, verification, and repair. It does not
compare BirdCode's harness quality with Codex unless a separate harness-isolation
or end-to-end system experiment is run.

The report MUST present family-specific conclusions. Phrases such as
"BirdCode beats Codex Sol/Ultra" are prohibited unless the corresponding
end-to-end protocol passes and the statement includes its task suite, platform
matrix, budget stratum, number of runs, uncertainty, and date.

## 3. Roles and separation of duties

The implementation SHOULD enforce the following roles with separate process
capabilities or credentials. One person may fill multiple roles during local
development, but a retained competitive comparison MUST disclose that fact.

| Role | May access | Must not access before score lock |
| --- | --- | --- |
| Fixture custodian | Full task bundle, hidden checks, contamination notes | Candidate outputs while changing fixtures |
| Benchmark controller | Frozen manifests, candidate launch contracts, sealed identity map | Hidden expected implementation details not needed for scheduling |
| Candidate runner | Public task input, starter snapshot, allowed tools and network | Hidden tests, rubric answers, other candidate outputs, identity map |
| Mechanical evaluator | Candidate artifact and frozen Validation Plan | Candidate display name; mutable scoring policy |
| Semantic/visual evaluator | Normalized evidence packet and rubric | Candidate identity, private chain-of-thought, other candidates' scores |
| Unblinder | Sealed identity map and locked scores | Authority to alter scores or rerun selected failures |
| Auditor | Immutable bundle and, when authorized, sealed fixture material | Authority to rewrite retained evidence |

Candidate generation and evaluation MUST run in separate sessions. An LLM that
generated a candidate MUST NOT be the sole semantic reviewer of that candidate.
Producer/integrator and evaluator manifests retain exact model, backend,
deployment, and configuration lineage. When semantic review is the sole
acceptance authority, at least one evaluator must be outside every producing
lineage, or the preregistration must require an independent multi-model quorum
or human adjudication. A different actor ID using the same deployment is not by
itself independent. Review prompts and models are versioned benchmark inputs
just like build scripts.

## 4. Immutable benchmark bundle

A scored run begins from a create-new benchmark bundle. At minimum it contains:

```text
benchmark-manifest.json
preregistration.json
tasks/<task-id>/task-manifest.json
tasks/<task-id>/public-input/...
tasks/<task-id>/validation-plan.json
platforms/<platform-id>.json
candidates/<opaque-candidate-id>/run-spec.json
evidence/<opaque-candidate-id>/<task-id>/<run-id>/...
scores/locked-scores.json
identity/sealed-map.json
report.json
```

The benchmark manifest MUST record:

- benchmark protocol version, suite ID and semantic version;
- canonical SHA-256 of every task manifest, starter snapshot, validation plan,
  rubric, prompt, adapter, script, image/container/VM, and preregistration file;
- source revisions for the benchmark runner and each source-available candidate
  harness; opaque services instead retain the supported client release,
  executable hash, service selector, and an explicit unavailable-source marker;
- experiment family, platform matrix, candidate count, repetitions, run-order
  seed, and statistical plan;
- complete budget vectors and invalid-run rules;
- identity-randomization commitment; and
- timestamps in UTC plus the benchmark controller identity.

Canonical JSON MUST use one declared serialization. Artifact bytes are
content-addressed with SHA-256. Run provenance follows the canonical plane
contract: a `run_context_sha256` first binds the schema, run/candidate/case
identities, target, bounds, environment, and immutable run manifest. That
manifest binds source/workspace, fixture, Validation Plan, harness
configuration, selected adapter implementation, permission policy, and network
policy by digest. Every record then binds that context, its contiguous
sequence, observation time, previous-record hash, and typed event:

```text
record_sha256 = SHA-256(canonical_json({
  schema_version, run_id, run_context_sha256, sequence,
  observed_at_unix_ms, previous_record_sha256, event
}))
```

Mutating immutable run context therefore breaks verification even if an event
chain is otherwise internally consistent. The initial reservation is durably
written before the first candidate is started and the report is finalized as
`complete`, `failed`, or `incomplete` before the controller exits.

After the first scored model call, no manifest, fixture, validator, budget, or
scoring rule may change in place. A correction creates a new suite version and
retains the superseded bundle and reason.

## 5. Task construction and clean-room isolation

### 5.1 Fixture requirements

Each task manifest MUST declare:

- an opaque task ID and version;
- task category and required platforms;
- the exact public prompt and starter-repository snapshot;
- allowed documentation, tools, permissions, credentials, and network hosts;
- mandatory and optional outcome gates;
- expected build, launch, exercise, teardown, and evidence adapters;
- maximum runtime, inactivity timeout, and resource budget;
- contamination risk and fixture provenance; and
- whether persistence, packaging, accessibility, visual quality, security, or
  cross-process behavior is in scope.

The public task describes desired behavior, not a preferred architecture or a
copy of hidden assertions. Hidden validators MUST test requirements present in
the public task. They may add adversarial inputs and boundary cases but MUST NOT
introduce undisclosed product requirements.

### 5.2 Candidate isolation

Every run starts from the same byte-identical starter snapshot in a fresh VM,
container, simulator state, or isolated worktree/overlay as declared by the
platform manifest. There is no shared writable cache, conversation history,
agent mailbox, generated artifact, or model state between scored runs unless
the benchmark explicitly tests warm-state behavior for every candidate.

Candidate runners receive only:

- the public task and starter snapshot;
- the same public documentation snapshot;
- capability-equivalent tools and credentials;
- the frozen visible budget and policy; and
- a per-run opaque nonce that carries no candidate or expected-answer meaning.

They do not receive hidden tests, rubric exemplars, fixture identifiers with
semantic hints, prior run outputs, baseline outputs, or another candidate's
name. Candidate-controlled system prompts are allowed as part of the harness
and MUST be versioned or hashed, but they may not contain scored-task answers.
Prompts inside an opaque provider service are recorded as unavailable rather
than inferred or obtained by bypassing the public interface.

### 5.3 Clean-room boundary

BirdCode development and comparison may use public Codex documentation,
documented protocols, CLI help, and black-box observations made through normal
user interfaces. It MUST NOT inspect, decompile, retrieve, or copy Codex or
another competitor's private implementation code, prompts, server payloads, or
credentials. The same restriction applies in reverse when preparing a neutral
baseline.

The benchmark suite is created independently of candidate implementation code.
Fixture authors may inspect public candidate behavior only to define general
product requirements; they MUST NOT add candidate-specific traps or exemptions.

## 6. Contamination controls

Development tasks and scored tasks are separate, versioned pools. Scored tasks
MUST NOT be used for prompt tuning, model profiling, retry-policy selection, or
manual rehearsal. A failed scored run remains scored; moving it to the
development pool requires a new benchmark suite version and invalidates
cross-version aggregation.

Before freezing a suite, the fixture custodian MUST:

1. record the origin and creation date of every task and asset;
2. scan public corpora and repository history for exact or near-exact task
   leakage using a declared method and threshold;
3. include generated per-suite values, filenames, and behaviorally relevant
   canaries that cannot be solved by copying a known template;
4. record whether any candidate provider or evaluator may have seen the task;
5. freeze hidden tests and their hashes before candidate execution; and
6. choose and disclose a fixture-release policy.

A canary is an observation aid, not automatic proof of contamination. Suspected
leakage triggers a documented investigation. If a fixture is invalidated, it is
removed symmetrically for every candidate before unblinding, or the entire
comparison is rerun under a new suite version. Selective removal based on which
candidate benefited is prohibited.

Provider retention and training settings MUST be recorded. If a provider
cannot guarantee zero retention, that limitation is disclosed and confidential
fixtures MUST NOT be sent without explicit authorization.

### 6.1 Continuous comparison cadence and holdouts

Continuous measurement uses two pools with different authority:

- **development suites** may run on every material harness, prompt,
  model-profile, or validation-plane change. They guide engineering but can
  never support a superiority claim after their outcomes influence development;
  and
- **sealed holdouts** have limited preregistered exposure and run at release
  candidates and other declared material harness gates. They alone may support
  a new comparative claim.

Any holdout whose tasks, hidden checks, aggregate result, or failure evidence
is used for tuning is immediately retired from future claims and may become a
development suite. The fixture custodian replenishes and rotates sealed
holdouts under a versioned policy; old suites and results remain retained.

At every holdout gate the controller re-freezes dated evidence for the
strongest normally selectable Codex model/reasoning configuration and records
baseline/client drift. Scheduled runs that are skipped, blocked by missing
data-sharing approval, fail setup, or fail infrastructure are retained rather
than silently deferred. Cadence never permits repeated probing of a sealed
task until a preferred candidate passes.

## 7. Candidate identity and model configuration

Every candidate specification records both harness and model identity.

Harness provenance includes source commit or signed release digest, executable
hash, dependency lockfiles, resolved configuration, application prompts or
their hashes, tool adapters, and feature flags. Dirty source trees are rejected
unless a complete content snapshot is captured and hashed.

Model provenance includes every model in a multi-model candidate stack, its
declared role or routing policy, and:

- provider and endpoint class;
- exact requested model ID and, where available, returned/native model ID;
- model revision, weights digest, quantization, context length, and tokenizer;
- reasoning mode or effort, sampling values, seed support, and output limit;
- discovery evidence and provider/client version; and
- whether identity is independently verified, provider-attested, or merely
  caller-asserted.

A caller-supplied label alone is not proof of model identity. Local models use
bounded native discovery evidence and weight/config digests where accessible.
Remote models retain response metadata and signed/provider-native discovery
where available. If a remote agent exposes only a selector, the report records
the selector, client version and executable hash, resolved configuration, and
an `asserted_not_independently_verified` limitation.

"Strongest available Codex Sol/Ultra" means the highest-capability configuration
that can be selected through the normal supported interface at suite-freeze
time. The controller MUST capture the available selectors, exact selected model,
reasoning effort (including `ultra` when offered), Codex client version, and the
evidence source. The selection also records its public capability-ordering
basis or a preregistered selection rule. If the strongest choice is ambiguous,
the experiment runs every plausibly tied configuration as separate strata or
does not use the phrase "strongest available." It may not silently fall back. A
fallback either fails the run or creates a separately labelled candidate
stratum.

## 8. Resource and budget normalization

Budgets are vectors, not a single synthetic score. Each `RunSpec` freezes:

- wall-clock and active execution time;
- model input, cached-input, output, and reasoning-token ceilings when exposed;
- monetary ceiling and price snapshot when applicable;
- maximum model calls, parallel calls, subagents, retries, and repair attempts;
- CPU, RAM, disk, GPU/device allocation, and process limits for local work;
- network allowlist and transferred-byte ceiling;
- context and artifact storage ceilings; and
- manual intervention policy, normally zero after launch.

All candidates receive the same visible budget vector in a harness-isolation
experiment. In an end-to-end system experiment, the controller preregisters
one or more observable budget strata. Unobservable remote compute is reported
as unknown, never estimated as equal.

The default comparison uses hard ceilings rather than forcing every candidate
to consume equal resources. Outcomes are reported together with actual usage
and Pareto curves for quality versus wall time and cost. A candidate that
finishes early keeps the efficiency benefit. A timeout is a scored failure, not
an excuse for an unreported continuation.

Provider token counts are retained but are not assumed comparable across
different tokenizers. When usage is unavailable, bytes and call counts may be
reported as observable proxies, explicitly not as token equivalence. Local
hardware and remote-service comparisons must disclose the asymmetry.

Adaptive decomposition, model routing, parallel candidates, specialist agents,
verification, and repair are legitimate harness behavior inside the frozen
ceiling. The benchmark does not mandate an orchestration strategy. It measures
whether that strategy produces the required result without exceeding policy.

## 9. Repetitions, seeds, and run order

Each stochastic candidate-task cell MUST have at least five scored runs for a
retained comparative claim. Ten or more are preferred for heterogeneous tasks.
Fewer runs may be published as a pilot, but only with descriptive statistics
and the explicit label `insufficient_for_comparative_claim`.

The preregistration fixes the repetition count; execution never stops early
because a preferred candidate is winning. Supported seeds are explicitly set
and recorded. When a provider does not expose a seed, the controller still runs
independent repetitions with opaque run nonces and records `seed_unavailable`.
It MUST NOT pretend those repetitions are deterministically seeded.

Candidate order is balanced within each task and repetition using the frozen
run-order seed. Where shared infrastructure could create temporal effects,
blocked randomization interleaves candidates and records queue delay, service
health, and rate-limit state. Failed infrastructure is handled by the
preregistered symmetric retry rule, never by candidate-specific discretion.

## 10. Blind candidate randomization

Before execution, the controller generates a 256-bit random salt and an opaque
ID for each candidate. It commits to the identity map with:

```text
SHA-256(canonical_json({
  "domain": "birdcode-benchmark-identity-v1",
  "benchmark_id": benchmark_id,
  "candidate_map": candidate_map,
  "salt_hex": salt_hex
}))
```

The canonical map and salt are sealed from evaluators. Candidate names,
provider logos, model names, distinctive output paths, and self-identifying
metadata are removed from the normalized review packet. Raw evidence remains
unaltered in the audit bundle but is inaccessible to blind reviewers until
their scores are locked.

All mechanical and semantic results are signed or hash-committed before the
unblinder reveals the map. The revealed canonical map and salt MUST reproduce
the original commitment. If operational details make a reviewer aware of an
identity, that reviewer records the exposure and is replaced or the affected
judgment is marked unblinded.

## 11. Execution & Validation Plane

The same versioned Execution & Validation Plane executes acceptance checks for
every candidate. Candidate harnesses produce workspace and application
artifacts; they do not choose which validator judges them or modify the plane.

Every platform adapter exposes the canonical lifecycle and outcome taxonomy in
[validation.md](validation.md):

```text
prepare -> build -> install -> launch -> readiness -> exercise
        -> inspect_state -> collect -> validate -> terminate -> cleanup
        -> package
```

Each phase returns a typed status, start/end timestamps, commands or structured
actions, exit codes, bounded stdout/stderr, environment digest, and artifact
references. A later phase cannot turn an earlier mandatory failure into a pass.
Timeout, candidate failure, infrastructure error, permission denial,
cancellation, and non-applicable phases are distinct typed outcomes. An adapter
cannot assign the benchmark-level `infrastructure_invalid` verdict.

The plane compiles each task's immutable `ValidationPlan` into adapter actions.
It runs outside the candidate's writable boundary, verifies its own scripts and
binaries before and after the run, and treats candidate-controlled logs or test
claims as untrusted evidence. Candidates cannot write score files, validator
configuration, hidden fixtures, or the evidence ledger.

### 11.1 Evidence priority

Evidence is evaluated in this order:

1. compiler/typechecker results, independent tests, package verification, exit
   status, process state, API responses, database or filesystem state, and
   reproducible artifact comparison;
2. runtime logs, structured traces, accessibility trees, DOM snapshots,
   platform UI trees, network traces, and independently captured telemetry;
3. screenshots and video captured by the plane; and
4. blind semantic or visual review against a versioned rubric.

Higher-numbered evidence cannot override contradictory lower-numbered evidence.
A screenshot of a success message does not prove that the underlying operation
occurred. Candidate narration and self-reported completion are diagnostic data,
not scoring evidence. Vision is useful for layout, affordances, rendering
defects, and UX, but it MUST NOT be the sole judge of functional correctness.
Every visual score references the exact screenshot/video hashes and, where
applicable, the corresponding DOM/accessibility state and interaction trace.

### 11.2 Required adapters

Suites select only adapters implemented and frozen for that suite, but the
target plane includes:

| Surface | Primary mechanical evidence | Secondary evidence |
| --- | --- | --- |
| Web | Playwright actions/assertions, DOM, accessibility tree, console/network traces, server state | Screenshots and video |
| API/server | Real client requests, schemas, status/body assertions, logs, persistence and concurrency probes | Operator-facing diagnostics |
| CLI/TUI | PTY transcript, exit codes, terminal dimensions, filesystem/process state | Terminal snapshots/video |
| macOS desktop | Signed build metadata, process/IPC state, accessibility API, application logs | Screenshots/video |
| Apple simulators | `simctl`/XCTest state, device logs, accessibility hierarchy, application data | Screenshots/video |
| Android | Emulator/ADB state, instrumentation/UI Automator, logcat, package data | Screenshots/video |
| Windows | VM snapshot, process tree, UI Automation, Event Log, installer state | Screenshots/video |
| Linux | VM/container state, process tree, accessibility/DOM where applicable, system logs and package state | Screenshots/video |

The platform manifest pins OS image, architecture, SDK, browser/runtime, locale,
timezone, display scale, fonts, input method, device profile, and relevant
driver/tool versions. "Cross-platform" requires passing the declared matrix;
successful cross-compilation alone is not platform support.

## 12. Complete-application success gates

Each task declares mandatory gates. A run earns `complete_pass` only if every
applicable mandatory gate passes:

1. **Scope integrity:** the submitted workspace derives from the frozen starter
   snapshot and contains no forbidden files, validator changes, or undeclared
   external dependency on the candidate session.
2. **Clean build/install:** documented commands work from a clean checkout with
   only allowed caches and network access.
3. **Launch/readiness:** the real target starts, stays alive for the specified
   soak period, and exposes genuine readiness rather than a fabricated status.
4. **Core behavior:** every mandatory end-to-end user journey succeeds through
   the real interface and produces the required underlying state.
5. **Persistence and restart:** required data survives process or device restart
   and is recovered through the intended product path.
6. **Failure behavior:** declared invalid inputs, unavailable dependencies, and
   permission boundaries fail safely and observably.
7. **Accessibility and interaction:** mandatory controls are reachable and their
   programmatic state agrees with visible state.
8. **Observability:** logs and diagnostics are sufficient to bind interactions
   to resulting process, network, and persistent state without secrets.
9. **Packaging/platform:** when in scope, the produced installable artifact has
   the required architecture, metadata, signature policy, and launch behavior.
10. **Repeatability:** a fresh validation pass against the retained artifact
    reproduces all mandatory outcomes without agent assistance.

An attractive mockup that does not build or execute is not a complete pass. A
working subset is retained as `partial`, with its passed and failed gates, not
rounded up. A mandatory security or permission-policy violation is a failure
even if functional tests pass.

`infrastructure_invalid` is reserved for failures demonstrably caused by the
plane or shared infrastructure before candidate-controlled behavior could
matter. The reason and evidence must be recorded and the preregistered rerun
rule applied equally. It is a controller-adjudicated final `RunVerdict`, based
on retained adapter `infrastructure_error` evidence; candidate output, an
adapter, or a semantic reviewer cannot self-assign it. Unknown-cause failures
remain candidate failures.

## 13. Scoring and statistical reporting

The primary metric is the macro-average complete-pass rate:

1. calculate `complete_pass` as 0 or 1 for every retained run;
2. average repetitions within each task; and
3. average task rates with equal task weight unless different weights were
   justified and frozen in the preregistration.

Secondary metrics include mandatory-gate pass rate, blind rubric score, time to
first independently verified success, wall time, monetary cost, model calls,
retries, peak concurrency, token/byte usage, flaky-pass rate, and categorized
failure modes. These MUST be shown separately; no undocumented weighted score
may replace the primary result.

Candidate differences use paired analysis by task and repetition where pairing
is valid. A retained comparison reports:

- numerator, denominator, and all excluded or invalid runs;
- absolute difference and relative ratio where defined;
- a 95% interval from the preregistered method, defaulting to a deterministic
  cluster bootstrap that resamples tasks and then runs with a published PRNG
  seed;
- task-level results rather than only an aggregate;
- win/tie/loss counts for blind rubric comparisons;
- resource-outcome Pareto plots or tables; and
- sensitivity analyses for invalid infrastructure and task weighting.

The superiority margin, non-inferiority margin, bootstrap method, sample count,
and any multiple-comparison correction are frozen before runs. The default
superiority claim requires the lower 95% bound for the complete-pass-rate
difference to exceed the preregistered margin. If it does not, the result is
`inconclusive`, not a win inferred from the point estimate. Holm correction is
the default when testing multiple candidates against one reference.

Missing, timed-out, policy-violating, and crashed candidate runs stay in the
denominator as failures. Only preregistered `infrastructure_invalid` runs are
excluded, and their count remains visible.

## 14. Anti-gaming rules

The following invalidate a run or, when systematic, the comparison:

- reading, modifying, probing for, or inferring hidden validators outside
  normal application interactions;
- detecting candidate identity and changing validation, budgets, or task input;
- candidate-specific prompts, tool restrictions, retries, grace periods,
  exemptions, or manual assistance not frozen as part of that candidate's
  declared system configuration;
- stopping repetitions early, discarding failures, selecting favorable seeds,
  or reporting only the best candidate artifact;
- changing a rubric, dependency, network policy, platform image, or validator
  after seeing candidate output;
- hard-coding benchmark fixture IDs, canaries, screenshots, expected outputs,
  or test-specific responses instead of implementing the requested behavior;
- calling another candidate, importing its artifacts, or using undeclared
  external human/model assistance;
- forging readiness, test, usage, model-identity, provenance, or state evidence;
- disabling logs, traces, accessibility data, or teardown collection required
  by the plane;
- modifying the plane, its clock, resource accounting, identity map, or
  evidence store; and
- publishing a harness-only causal claim from an end-to-end system experiment.

General reusable knowledge in a frozen harness is allowed. Task-specific tuning
on the scored suite is not. Adaptive behavior based on the current task,
observed tool results, and declared model profile is allowed when performed
inside the candidate boundary and retained in provenance.

Suspected gaming is recorded as a finding with evidence and adjudicated blind
to candidate name when possible. Rules are applied symmetrically; there are no
retroactive candidate-specific penalties.

## 15. Provenance and failure retention

For every attempt, including setup failures and timeouts, the plane retains:

- benchmark, task, candidate, execution, agent, subagent, and parent-attempt
  identifiers;
- exact candidate and validator source/executable hashes;
- model request identity, resolved model evidence, reasoning/sampling settings,
  token ceilings, usage, and bounded raw backend events;
- compiled prompts or their access-controlled content-addressed artifacts;
- permissions, budgets, environment variables after secret-name/value
  redaction, network policy, and platform image digest;
- every command or structured UI/API action, working directory, timestamps,
  exit code, bounded stdout/stderr, process state, and retry/handoff relation;
- patches, repository status, build/install artifacts, test results, logs,
  traces, accessibility/DOM/UI trees, screenshots, and videos;
- validator decisions with exact evidence references; and
- final workspace and application-artifact hashes.

Secrets, personal filesystem paths, unrelated model inventories, and private
chain-of-thought are not public report material. Redaction occurs through typed
fields before publication, never by rewriting source evidence in place. The
original may be encrypted in an access-controlled audit bundle; its ciphertext,
redaction manifest, and public replacement are all hashed.

Failed evidence is never overwritten by a retry. Retries create new attempt IDs
linked to exact parents. Reports include the complete attempt tree, not only the
accepted branch. Raw nondeterministic inference need not reproduce byte for
byte; the environment, inputs, controls, and deterministic validation must be
replayable.

## 16. Acceptance criteria for a retained comparison report

A comparison report is `complete` only when all of the following are true:

- the experiment family and permitted conclusion are explicit;
- the suite, preregistration, task, platform, adapter, candidate, model, budget,
  rubric, and statistical versions/hashes are present and validate;
- the strongest-available claim for Codex Sol/Ultra, if used, is supported by
  dated selector/version/reasoning evidence and no silent fallback occurred;
- every candidate received byte-identical public inputs and the same applicable
  Validation Plan and plane version;
- the minimum repetition rule is met, or the report is labelled a pilot and
  makes no comparative claim;
- all runs, failures, retries, timeouts, policy violations, and
  infrastructure-invalid decisions are present with evidence;
- candidate order and opaque identity commitment are retained, scores were
  locked before unblinding, and the revealed map verifies the commitment;
- mandatory complete-application gates were evaluated mechanically wherever
  possible, with vision used only as secondary evidence;
- reported aggregates can be recomputed from per-run records with the frozen
  statistical code and seed;
- content hashes and provenance chains verify, and mechanical validators replay
  from the retained candidate artifacts on the declared platform images;
- contamination checks, disclosures, exclusions, reviewer identity exposure,
  and conflicts of interest are recorded;
- public and restricted evidence boundaries are explicit and no credential or
  unauthorized private fixture was published; and
- limitations distinguish observed system outcomes from claims about harness
  quality or base-model quality.

If any required item is missing, the report is finalized as `incomplete` or
`failed`; it may still be useful diagnostic evidence but MUST NOT support a
winner claim.

## 17. Audit and publication

An independent auditor MUST be able to verify the hash graph, identity
commitment, run counts, score lock, exclusions, and aggregate calculations
without trusting the benchmark controller's prose. With appropriate access to
sealed fixtures, the auditor SHOULD be able to recreate platform images,
replay all mechanical validation against retained candidate artifacts, and
trace every score to exact evidence.

Public reports include the immutable manifest, non-sensitive per-run outcomes,
statistical notebook or executable analysis, hashes for restricted artifacts,
and a precise reproduction guide. If hidden fixtures remain sealed to preserve
future usefulness, the report says so and distinguishes `publicly_reproducible`
from `auditor_reproducible`. Fixture disclosure later creates an append-only
release event; it does not alter the original report.

Corrections are new signed or hash-linked report revisions that retain the
original. Negative and inconclusive results are published under the same policy
as positive results.

## 18. Interpretation

The benchmark is designed to make future claims testable, not to predeclare a
winner. A strong result demonstrates performance on a frozen suite under a
specific envelope. It does not prove universal superiority, future model
performance, security, or support for an untested platform.

BirdCode's intended advantage is an inspectable harness that can adapt its
orchestration and validation to different model capabilities. Whether that
design yields better complete applications than Codex Sol/Ultra or another
harness must be established by retained comparisons that satisfy this protocol.
