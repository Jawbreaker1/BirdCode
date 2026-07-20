# Target architecture

This document describes the intended system, not a claim that every component
already exists. The current executable slice is listed in the repository
README. Negotiated runtime capabilities advertise the coarse durable planning,
replay, streaming, and cancellation surface; semantic-review policy readiness
is reported separately through runtime health and is not a capability bit.

## Product shape

BirdCode is being built as a local-first coding-agent system. The desktop client
is the main experience. A CLI will expose a subset of the same capabilities.
Both communicate with a durable local runtime through a versioned protocol.

```text
React/Tauri desktop ─┐
                    ├── versioned local protocol ── Rust daemon
Rust CLI ───────────┘                               ├── agent runtime
                                                    ├── context compiler
                                                    ├── execution/validation plane
                                                    ├── event and artifact store
                                                    ├── tool and permission broker
                                                    └── backend adapters
```

The initial build and distribution target is `aarch64-apple-darwin`. Core
crates must compile independently from the desktop shell. Operating-system
behavior belongs behind platform adapters in the runtime.

### Current product-wired slice

Protocol v5 currently connects both desktop and CLI to a durable daemon-owned
`PlanOnly` supervisor. An explicit trusted policy pins exact producer and
critic lineages plus the bundled planner, critic, and repair contracts before
inference. The backend reports the exact discovered model IDs; deployment and
independence-domain separation are currently trusted operator declarations,
not backend attestations, and both roles use one configured backend instance.
The supervisor executes `InitialPlan → InitialReview → optional
Repair → FinalReview`, with exactly two calls for direct acceptance and at most
four calls when one complete replacement plan is authorized. It persists each
prompt and canonical provider-neutral request before inference, records the
exact assistant text, parsed provider response JSON, SHA-256 of the exact HTTP
response bytes, and token use, and exposes typed replay plus individually
content-addressed, hash-verified artifacts to the caller. It does not retain or
claim exact provider-specific HTTP request bytes or raw HTTP response bytes.
Initial `Prepared` state also retains the policy-validated producer and critic lineage
snapshot. Recovery can therefore attribute and terminalize a later-stage
missing or corrupt policy artifact without redispatching inference or trusting
that damaged file. Claims, deadlines, cancellation, bounded durable dispatch,
semantic-stage legality, and restart recovery are mechanical runtime concerns
rather than model decisions.

This is intentionally narrower than the durable root-actor capability gate in
the product requirements. The context contains repository identity and user
input but no repository observations; there are no live tools, work-order
execution, child actors, or replanning from tool evidence. The policy-separated
critic can reject or authorize one repair of the root plan, but it is a fixed
supervisor role rather than a general child-agent runtime.

## Backend taxonomy

A model backend gives BirdCode control over the agent loop. Initial examples
are Ollama, LM Studio, and the OpenAI API. An agent backend already owns an
inner loop. The local Codex bridge is an agent backend and uses Codex-managed
authentication.

The distinction is represented in capabilities rather than hidden behind a
false least-common-denominator interface.

## Outcome loop and Execution & Validation Plane

BirdCode's target loop is outcome-driven:

```text
goal -> semantic plan -> isolated implementation -> execute real product
     -> collect mechanical + visual evidence -> verify -> repair/replan
     -> staged integration -> independent review -> complete or fail
```

The Execution & Validation Plane is provider-neutral so the same versioned
plan can exercise BirdCode, Codex, or another candidate without provider-aware
exceptions. An explicit target combines an application surface with an
execution platform and resolves mechanically to a registered adapter. The
target adapter families are Playwright web, API/server, CLI, TUI, macOS desktop,
Apple simulator, Android, Windows, and Linux.

`crates/validation` currently implements only the typed foundation: explicit
targets and a surface-plus-platform adapter inventory, lossless
command/provenance contracts, bounded evidence, validation policy, and
provider-blind review packages. Its immutable run manifest binds the source
snapshot, fixture, Validation Plan, harness configuration, concrete adapter,
permissions, and network policy into the provenance hash root. Its default
adapter catalog is empty. It does not execute a process, launch an application,
drive a browser/device, or claim platform support.

Evidence has an enforced hierarchy. Builds, tests, exit/process state, API and
persisted state, DOM/accessibility observations, logs, and traces are primary.
The current crate represents screenshots, video, logs, and traces as bounded
artifact metadata; visual metadata cannot satisfy a passing policy without
primary non-visual evidence. It hash-binds typed actor, declared model,
environment, command, exit, and caller-/adapter-declared artifact metadata.
It does not capture, fetch, anonymize, or attest the referenced bytes, and
secret-resolved byte counts remain declarations until a broker receipt exists.
The typed foundation does not yet carry comparison-grade backend deployment,
model revision, weights/quantization, or identity-verification evidence; that
lineage expansion is required before the blind-comparison gate.

The current blind projection creates an in-memory opaque evaluator package,
removes provider, model, agent, command, storage-path, and raw target
identities, and returns a separate in-memory disclosure plus a digest of the
exact evaluator input. The caller must isolate and persist that disclosure.
Durable validated seal reload, signatures/external anchoring, verdict lock, and
controlled unblinding are controller work that is not implemented yet. See
[validation.md](validation.md) and [benchmarking.md](benchmarking.md).

## Durable state

The application-enforced append-only event log is authoritative. Large prompts,
outputs, terminal logs, patches, and other artifacts are content-addressed and
referenced from events. Materialized session state and memories are rebuildable
projections.
Sequential event reads are bounded pages; callers resume from the last sequence
instead of materializing an arbitrarily long session in memory.

Current run state is maintained atomically as an indexed projection whenever an
authoritative event is appended. Historical schema upgrades are persisted as
small checkpointed phases, so a crash or startup deadline resumes from durable
progress rather than replaying the full database. The online health probe is a
bounded closed-world schema/database/artifact canary, not an O(N) forensic data
audit; affected reads still fail closed if stored state is inconsistent.

The runtime can replay recorded state exactly. Re-running a nondeterministic
model is not expected to reproduce identical tokens. Append-only enforcement
is a trusted runtime/SQLite-schema property, not a signed or externally
anchored hash chain. Individual content-addressed artifacts are hash-verified,
but a privileged storage owner able to rewrite the database and artifact state
is outside the current threat boundary.

## Context and compaction

The active context is compiled for a specific next action from:

- user constraints and active goals;
- decisions and their rationale;
- open commitments and unresolved questions;
- current repository observations;
- recent causal events;
- semantically retrieved older events and artifacts.

Every compiled context has a manifest describing included and deliberately
omitted sources. Compaction creates a versioned checkpoint and projections; it
does not delete raw events or artifacts.

Application prompt manifests separately declare a conservative generation
schema for provider grammar engines and the full authoritative output schema.
Provider-constrained JSON is accepted only after the full local schema and
cross-field invariants validate it against the original runtime invocation.

The standalone `crates/orchestrator` router executor permits at most two
structured model calls: one normal route and, only when the collect-all
invariant report contains nothing except duplicate evidence sections, one
evidence-consolidation repair.
The repair input is an untrusted projection of duplicate section names and
bases; it contains no original request/repository payloads or semantic route
fields. The repair output is a patch rather than another route, so action,
strategy, access, confidence, questions, subtasks, and unique evidence remain
mechanically locked. The complete original route contract is validated again
after patch application, with no further retry.

Every backend response or error is retained with globally unique UUID v7
execution/attempt IDs, its compiled prompt, requested model, reasoning setting,
token ceiling, and phase before orchestration can continue. A repair carries
the exact parent attempt ID and remains SHA-256-bound to the initial assistant
text. Before inference, the executor requires the selected router to match an
exact key, typed manifest, and content digest in its internal bundled registry;
caller-added versions and same-key policy mutations fail setup without a model
call or journal entry. Historical bundled versions remain available for replay.
Responses and errors are submitted to an acknowledged injectable journal
boundary that fails closed; the bundled implementation is intentionally
in-memory. Wiring that boundary to the durable event/artifact store remains
daemon integration work.

## Subagents

Subagents are isolated actors with their own causal event branches, mailboxes,
budgets, permissions, and delivery contracts. The LLM decides semantically
when and how to delegate through structured actions. The scheduler enforces
mechanical limits and permissions.

Writing agents use isolated worktrees or overlays. Parents receive structured
handoffs containing evidence, artifacts, tests, risks, and unresolved work,
not an unbounded copy of the child transcript.

Model assignment and decomposition use versioned evaluation-derived profiles,
not model-name branches. A semantic planner may compensate for a weaker model
with smaller work orders, specialist agents, parallel candidates, more frequent
validation, or bounded repair. The scheduler only enforces the resulting typed
graph, permissions, isolation, and ledgers; it never parses raw task language.
The complete target lifecycle and measurable vertical slices are specified in
[orchestration.md](orchestration.md).

## Local transport

The transport must support ordered streaming, cancellation, reconnection, and
protocol-version negotiation. Its public types live in `crates/protocol`.
Transport-specific code must not leak into runtime domain types.

Protocol v5 retains the separately versioned lossless workspace-path wire
value introduced in v4:
Unix paths carry their exact bytes and Windows paths carry exact UTF-16 code
units. This avoids forcing either representation through Unicode text, so
non-UTF-8 POSIX names and unpaired Windows surrogates survive canonical JSON
round trips. A foreign-family path remains valid protocol data but must not be
converted to a native `PathBuf` on an incompatible host.

Mutating requests require a client-stable identity whose result is recorded
atomically with its state change. `CreateRun` uses a
client-allocated run ID and accepts replay of the same decoded typed `RunSpec`
while rejecting reuse with a different spec. Cancellation records one stable
server-generated cancellation identity for the run. The client classifies
definitely-unsent, authoritative rejection, and ambiguous outcomes separately.
It reconnects at most once and replays only the exact retained `CreateRun`;
generic mutations and `CreateSession` are never replayed.
The native desktop keeps that pending identity and exposes an explicit typed
reconciliation action while the process remains alive. Reattaching that run
after a complete desktop restart is still incomplete.

## Platform strategy

- Phase 1 host: macOS on Apple Silicon, distributed outside the Mac App Store.
- First validation surfaces: bounded local processes, API/server, CLI/TUI, and
  Playwright web on that host.
- Native expansion: macOS desktop and Apple simulators, then Android.
- Host expansion: Windows process/UI Automation/PTY and Linux process,
  packaging, accessibility, and distribution-matrix adapters.

Platform support means verified builds and behavior, not merely successful
cross-compilation.
