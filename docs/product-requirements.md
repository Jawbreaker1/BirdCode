# Product requirements

This document is the normative product direction for BirdCode. It distinguishes
required behavior from the narrower pre-alpha slice that happens to exist
today. The repository README remains authoritative for current implementation
status.

## Primary outcome

BirdCode's primary goal is to produce better final outcomes than the strongest
available Codex Sol/Ultra baseline: code that builds, starts, behaves correctly,
survives its declared validation flow, and forms a complete application for the
task—not merely a plausible patch or transcript.

This is a measurable target, not a current superiority claim. BirdCode may only
claim an advantage for a versioned benchmark suite when retained, auditable
evidence supports it. Comparisons follow the clean-room protocol in
[benchmarking.md](benchmarking.md).

## Definition of a complete result

A task fixture defines what “complete” means for that product. Unless the
fixture explicitly narrows the scope, a successful candidate must:

1. build or package from a clean declared environment;
2. start every required process or application;
3. complete representative user journeys through real interfaces;
4. satisfy deterministic tests, schemas, accessibility/DOM checks, API
   contracts, exit-state checks, and platform-specific requirements;
5. retain sufficient logs, traces, screenshots/video, and artifact hashes to
   reproduce and audit the verdict; and
6. leave no known fixture-blocking defect hidden behind a partial-success
   label.

Semantic quality—clarity, usefulness, visual coherence, interaction design—can
be part of the rubric, but it cannot override a failed mechanical requirement.

User constraints are first compiled by an LLM into a source-cited typed
obligation ledger and checked semantically against the original input by an
independent eligible reviewer/quorum or human adjudicator. Deterministic code
then preserves accepted obligation IDs and approvals; it never claims to infer
semantic weakening from prose or patches.

## Model diversity and adaptive compensation

BirdCode must support many model backends, including small and comparatively
weak open-source models. The harness may not assume that one prompt or agent
topology fits every model.

Required mechanisms are:

- versioned model profiles derived from retained capability and reliability
  evaluations rather than model-name conditionals;
- LLM-classified task structure, uncertainty, delegation needs, and specialist
  requirements with typed output contracts;
- adaptive decomposition depth and context size within explicit budgets;
- parallel independent candidates when empirical profiles justify the cost;
- specialist agents for implementation, testing, platform operation, security,
  accessibility, visual review, and integration;
- execution-feedback, critique, and bounded repair/replanning loops; and
- escalation to a stronger configured model or human decision when the current
  plan cannot meet its acceptance gate.

Deterministic code enforces budgets, permissions, schemas, scheduling, causal
state, isolation, and retry ceilings. It must not replace semantic planning
with keyword lists, regular expressions, language-specific branches, or hidden
filename conventions.

## Full subagent orchestration

Subagents are a core runtime primitive, not an optional prompt pattern. The
eventual runtime must support:

- parallel execution with isolated contexts and worktrees/overlays;
- explicit parent/child causality, budgets, permissions, deadlines, and model
  selection;
- mailboxes and structured handoffs containing evidence and unresolved risks;
- bounded retries, repair, cancellation, resume, and replanning;
- deterministic integration ownership and conflict handling;
- independent review agents that did not author the candidate under review;
  and
- continuous feedback from the Execution & Validation Plane.

The implementable lifecycle and acceptance gates are specified in
[orchestration.md](orchestration.md).

## General Tooling Plane

Subagents are useful only when they can act through a broad, permissioned
capability layer. The Tooling Plane is therefore a core requirement in its own
right, separate from the Execution & Validation Plane that judges evidence.
It must cover:

- repository intelligence: tree and content search, symbols/references,
  dependencies, ownership, and change-impact analysis;
- bounded change construction: reads, writes, patches, renames, deletes,
  diffs, and generated assets;
- Git and workspace isolation: snapshots, branches, worktrees/overlays, patch
  export, integration, and conflict inspection;
- shell and process control: typed argv, PTY, streaming logs, process trees,
  ports, cancellation, and cleanup;
- build and language intelligence: compilers, package managers, formatters,
  linters, tests, and language-server evidence;
- web, API, server, desktop, simulator, device, Windows, and Linux operation;
- knowledge and integrations such as official documentation, search, issue/PR
  systems, and CI;
- logs, traces, screenshots, video, reports, manifests, and content-addressed
  artifacts;
- agent coordination through task graphs, mailboxes, questions, handoffs,
  review findings, and integration; and
- security-sensitive effects through a credential broker, network grants,
  publication gates, and explicit user approval.

Every advertised tool must have machine-readable input and output schemas,
side-effect and idempotency classes, permission and path/network scope,
cancellation behavior, bounded output, and reproducible provenance. Tool
availability must never be inferred from filenames, language-specific strings,
or unverified platform labels.

## Execution & Validation Plane

A general provider-neutral Execution & Validation Plane is a core requirement.
Agents must be able to build, start, operate, observe, and validate real
applications throughout development—not only after code generation stops.

The plane must expose explicit typed adapters for:

- web applications through Playwright;
- API and long-running server processes;
- CLI and TUI applications;
- native macOS desktop applications;
- Apple simulators;
- Android devices/emulators;
- Windows; and
- Linux.

An adapter is considered supported only after its relevant platform matrix and
real behavior have been verified. An enum variant, cross-compilation, or a
mock-only test is not platform support.

## Evidence hierarchy

Primary evidence is derived from actual state:

- compiler, linker, package, and installer outcomes;
- test and lint results;
- process lifecycle, exit codes, and health checks;
- API responses and persisted state;
- accessibility trees, DOM state, and interaction traces;
- logs, crash reports, and resource observations; and
- content-addressed build and runtime artifacts.

Screenshots and video are required where they materially demonstrate UI/UX and
are expected to be reviewed with vision-capable models. Vision is never the
sole judge: every passing visual journey also needs non-visual evidence that
the intended application and state were actually exercised.

## Reproducible provenance

Every execution and validation attempt must retain a causally linked,
append-only record containing, as applicable:

- run, candidate, agent, execution, attempt, and parent identifiers;
- exact backend-reported model and harness identities and settings;
- immutable source/workspace and task-fixture digests;
- argv, working directory identity, bounded environment, toolchain, permissions,
  budgets, timeouts, and network policy;
- start/end timestamps, exit status, stdout/stderr/log artifact references;
- interaction steps, accessibility/DOM snapshots, traces, screenshots, and
  video references; and
- SHA-256 hashes, sizes, media types, and retention status for every artifact.

Sensitive values remain redacted or referenced through a credential broker;
reproducibility is not permission to persist secrets.

## Blind outcome comparison

BirdCode and Codex candidates must be evaluated by the same validation harness
from equivalent fixtures, snapshots, permissions, budgets, and platform
environments. Candidate and provider identities remain opaque to semantic
evaluators until results are sealed. Deterministic checks consume candidate
artifacts without provider-specific exceptions.

The benchmark must separate:

- base-model quality;
- harness/orchestration quality;
- execution and validation reliability; and
- cost, latency, and resource usage.

Raw successes and failures are retained. Reports include all configured runs,
not a selected best transcript.

Development comparison suites run continuously after material harness, prompt,
model-profile, or validation changes, but become tuning evidence rather than
claim evidence. Superiority claims require limited-exposure sealed holdouts at
preregistered release/material-change gates. A holdout used for tuning is
retired, replacements are rotated in, and the strongest normally selectable
Codex configuration is re-frozen with dated evidence at each claim-bearing
gate.

## Capability gates

BirdCode advances by evidence-backed vertical slices:

1. **Typed plane foundation:** provider-blind plans, evidence, provenance, and
   collect-all policy validation.
2. **Durable root-actor slice:** a real model executes through the daemon with
   action-specific context, read-only repository tools, budgets, streaming,
   cancellation, resume, and retained actor/tool events.
3. **Isolated child slice:** a parent delegates one typed work order to a
   writing child in a permission-bounded worktree/overlay; its hash-bound
   handoff is integrated by an explicit owner and build failure blocks success.
4. **Parallel actor-graph slice:** at least two children overlap in time with
   atomic budget accounting, isolated contexts/workspaces, durable mailboxes,
   subtree cancellation, candidate integration, and independent review.
5. **Tool and validation slices:** execute bounded local processes and then a
   Playwright build/start/journey/DOM/accessibility/trace/screenshot flow
   against real fixtures before expanding through API/server and CLI/TUI.
6. **Feedback and replanning slice:** retained failures drive bounded repair,
   graph amendment, and a complete rerun of the same acceptance gate.
7. **Blind comparison slice:** BirdCode and Codex complete the same
   preregistered fixtures and are scored from opaque candidate bundles.
8. **Platform expansion:** verified macOS and Apple simulator operation, then
   Android, Windows, and Linux adapters.

No later gate is advertised as implemented until its real end-to-end evidence
is retained.
