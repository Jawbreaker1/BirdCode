# Agent roles and Tooling Plane registry

This document is the living capability registry for BirdCode agents. It names
the roles and tools a complete coding harness needs, but it does **not** turn
natural-language routing into hard-coded personas. The semantic planner chooses
an appropriate role composition and tool requests through versioned structured
output. Deterministic code only validates identity, capability compatibility,
authority, budget, lifecycle, and evidence.

The registry deliberately separates three things:

- an **agent role** is a model-facing purpose, context contract, and acceptance
  behavior;
- a **tool capability** is a broker-enforced typed effect or observation; and
- a **runtime component** such as the scheduler, permission broker, journal, or
  workspace manager is deterministic infrastructure, not an LLM persona.

Role selection must never depend on keyword lists, regular expressions,
filename extensions, guessed programming languages, or model-name branches.
When several eligible profiles exist, the planner makes the semantic choice and
cites the evidence that caused it. When policy leaves exactly one eligible
profile, the runtime may assign it mechanically without pretending that this is
semantic classification.

This registry is a BirdCode product contract, not a claim that every listed
role, isolation rule, durable control, or evidence property is implemented by
Codex. Some requirements deliberately exceed the directly observed Codex
surface. The evidence class and parity standing of those behaviors are tracked
separately in [the clean-room capability ledger](clean-room-codex-capability-ledger.md).
The distinction between documented Codex built-ins, BirdCode functional roles,
and the semantic conditions for starting a child is specified in
[the subagent taxonomy and spawn policy](subagent-taxonomy-and-spawn-policy.md).

## Clean-room Codex lifecycle observation (`2026-07-21`)

This observation is bound to the Codex desktop collaboration surface exposed
while working on branch `codex/parallel-reconnaissance-runtime` at repository
`HEAD d53d7b56f507f23aabfdf477de205be2c0a68490`. The worktree was dirty and
changed concurrently, so this is a session-surface observation, not a pin of
BirdCode source behavior or Codex internals. Publicly documented behaviors stay
`DOC`; callable or exercised session contracts are `OBS`; statements about
unexposed implementation remain explicitly unknown.

| Surface | Purpose and activation | Identity and timing semantics | Evidence boundary |
| --- | --- | --- | --- |
| `spawn_agent` | Creates and immediately dispatches one bounded child task that can run independently. The caller selects `none`, `all`, or a positive number of recent turns as the context fork. | Allocates a new canonical hierarchical task identity. A full-history fork inherits the parent profile; requested model/reasoning overrides are accepted only under the exposed non-full-history constraints. | Exercised by the parent to create this child. The requested profile is not an attestation of the effective backend model or reasoning setting. No child-specific sandbox selector was exposed by this session's spawn call. |
| `list_agents` | Reads a snapshot of live agents, optionally below one task-path prefix; it does not activate work. | Reports canonical identities and current running or terminal status. A snapshot is not a durable event stream and does not prove actual backend overlap. | Exercised. Status and terminal payload visibility were observed; race consistency, replay, raw child transcript visibility, and private scheduler state were not. |
| `send_message` | Delivers a message promptly to an existing agent without triggering a new turn. The exact admission boundary was not exposed. | Reuses the target identity and current turn; it does not allocate a child or itself turn an idle identity into a new activation. | Exercised in this documentation task. Delivery durability, ordering across senders, deduplication, and exactly-once processing were not attested. |
| `followup_task` | Triggers a new turn when an existing target is idle/completed, or steers a running target at a message boundary or after its pending tool call. | Reuses the canonical agent identity. This documentation assignment followed a completed audit turn on `/root/codex_role_tool_parity_audit`, directly demonstrating identity reuse without proving internal storage or replay. | Exercised. A follow-up is not evidence of an automatic retry policy, and no attempt-generation contract was exposed. |
| `interrupt_agent` | Requests interruption of the current turn and returns the previous status. It is distinct from sending a message or starting a follow-up. | Leaves the agent identity available for later work. The exposed contract does not say that owned model calls, processes, leases, or effects were durably reconciled. | Exercised on a reported-running follow-up turn; the call returned `previous_status: running`. Cancellation durability, owned tool/process cleanup, and race behavior remain unobserved. |
| `wait_agent` | Waits for a mailbox update from any live child or for user steering; it does not activate a target. | The exposed timeout defaults to 30 seconds, is bounded from 10 seconds to 3,600 seconds, and returns an update/timeout summary rather than the child payload itself. A timeout is an observation, not child failure. | Exposed and previously exercised in this session; fairness, restart durability, cursor semantics, lost wakeups, and terminal-delivery ordering were not measured. |
| Terminal child result | Delivers a child's final payload to its parent when that child turn finishes. | Ends the turn represented by that result but, as the exercised follow-up shows, need not retire the reusable agent identity. | Delivery was observed. The payload was free-form prose rather than a typed, hash-verified, exactly-once BirdCode handoff. |

Agents in this session had isolated selected model/history contexts but shared
the same current directory and checkout. Context isolation therefore does not
attest filesystem, peer-visibility, workspace, or permission isolation. The
earlier audit instruction was read-only while the effective session sandbox
remained workspace-write capable; making no writes proved compliant behavior,
not a mechanically read-only grant. Likewise, a requested model, reasoning
effort, sandbox label, role name, or agent task name is not the corresponding
effective attestation. BirdCode must retain requested, inherited,
policy-resolved, broker-granted, and backend-attested values independently.

Nothing above supports an inference about Codex's private prompts, context
representation, scheduler, mailbox storage, retry policy, durability, or
execution topology. Absence from this exposed collaboration surface also does
not prove absence from other Codex clients or private implementation.

## Contract required for every role

Every versioned role definition must declare:

| Field | Required meaning |
| --- | --- |
| Purpose | The outcome the agent owns and what it must not decide |
| Inputs | Typed work order, protected obligations, context manifest, accepted dependency handoffs, and trust labels |
| Outputs | Typed actions, handoff shape, evidence requirements, and terminal states scoped explicitly to the thread, turn, execution, attempt, or root orchestration |
| Identity and continuity | Stable reusable `AgentThread`/actor identity plus distinct `Turn`, `Execution`, and `Attempt` identities, their causal parents, follow-up rules, and which terminal states preserve or retire the thread |
| Context selection | Exact source conversation and history-fork policy, included and omitted turn/event IDs, dependency inputs, compaction checkpoint, and continuity or reset behavior for each new turn |
| Tool requirements | Capability IDs and minimum adapter features, never inferred from task text |
| Authority ceiling | Read, workspace write, process, network, credential, integration, and publication limits |
| Effective authority | Requested, inherited, policy-resolved, and broker-granted permissions and tool inventory, with denial evidence; task wording or absence of observed writes is not a sandbox attestation |
| Isolation | Four independent axes: model/history context, filesystem snapshot/worktree, peer/candidate visibility, and effective permission/tool isolation |
| Model requirements | Measured capabilities such as coding, vision, tool use, context, platform knowledge, and reasoning class |
| Model resolution | Requested, inherited, eligible, policy-resolved, and backend-attested effective model and reasoning identities, retaining unavailable or operator-declared fields as such |
| Independence policy | Whether the role may share model, deployment, domain, context, or author identity with another role |
| Budget | Model calls, tokens, tool calls, wall/CPU time, artifacts, child count, retry count, and nesting depth |
| Prompt provenance | Immutable prompt ID/version/hash plus generation and local-validation schemas |
| Evaluation history | Frozen fixtures, outcomes, known failure modes, and confidence interval rather than a static “smart/weak” label |

No role receives authority from its own output. A model may request a tool,
child, retry, escalation, or broader scope; the runtime grants only what the
trusted policy already allows or pauses for explicit approval.

An instruction such as “read-only” is behavior requested from the model. The
role is mechanically read-only only when the resolved broker grant excludes
writes and denied-effect evidence proves enforcement. Likewise, completion,
failure, cancellation, interruption, and `OutcomeUnknown` always name their
scope: ending one turn or execution does not silently close a reusable thread
or complete its root orchestration.

## Role families

These are composable role families, not a mandatory fixed pipeline. A planner
may instantiate several independent agents in one family, omit unnecessary
families, or propose a new specialist whose contract is validated before use.
Dedicated isolated writer workspaces, durable typed mailboxes, policy-separated
completion review, and the stricter gates below are BirdCode safety and quality
requirements. Their presence here does not assert that the observed Codex
surface provides the same mechanisms internally.

| Role family | Primary responsibility | Typical output and acceptance boundary |
| --- | --- | --- |
| Root coordinator | Own user intent, protected constraints, plan revisions, delegation, integration choices, and truthful final state | Versioned task graph, bounded work orders, accepted handoffs, unresolved decisions; under BirdCode's beyond-parity acceptance policy, cannot claim completion without the independent completion gate |
| Semantic router | Classify requested action, authority needs, uncertainty, and direct/delegated strategy across languages | Typed route axes with causal evidence; no effect authority |
| Planner / replanner | Decompose semantically, assign eligible profiles, react to evidence, and amend the graph | Validated `Execute`, `Delegate`, `Clarify`, `Escalate`, or `Finish` plus an atomic plan patch |
| Repository explorer | Map relevant files, symbols, dependencies, flows, ownership, and unknowns without modifying state | Bounded findings citing exact tree/read/search observations |
| Requirements analyst | Convert the goal and user decisions into testable protected obligations and expose ambiguity | Obligation proposal, acceptance criteria, clarification requests; user policy remains authoritative |
| Architecture specialist | Evaluate boundaries, data flow, portability, migration, and failure semantics | Evidence-linked design options and tradeoffs, never implicit authority to rewrite scope |
| Dependency / documentation researcher | Resolve current official APIs, versions, platform constraints, and external behavior | Source-linked facts with dates and provenance; repository or web text remains untrusted data |
| Implementer | Produce one scoped code or asset change in a broker-isolated BirdCode workspace | Content-hashed patch/result manifest plus local checks and unresolved risks; workspace isolation is a BirdCode safety requirement, not an inference from a separate model context |
| Candidate implementer | Produce an independent alternative under the same frozen objective and comparable budget | Isolated candidate manifest; under BirdCode's candidate policy, cannot see peer transcripts/worktrees before selection |
| Test designer | Design high-value behavioral, property, adversarial, regression, and platform tests independently of the implementation | Test patch/specification and coverage rationale; cannot turn a failing product into a pass |
| Build / runtime operator | Build, launch, exercise, observe, and clean up real processes and applications | Reproducible command/process receipts, logs, exit state, artifacts, and cleanup proof |
| Debugger | Form and test causal hypotheses from failures, traces, and runtime state | Ranked hypotheses, reproductions, minimal repair recommendation, and disconfirming evidence |
| Security reviewer | Examine trust boundaries, permissions, injection, path/process/network safety, dependencies, and secrets | Prioritized findings with reproductions and explicit threat-model scope; broker-enforced read-only grant by default, not merely a prompt instruction |
| Reliability / performance specialist | Test concurrency, recovery, resource bounds, latency, throughput, and degradation | Measured profiles, traces, statistical results, bottlenecks, and bounded recommendations |
| Accessibility reviewer | Validate accessibility trees, keyboard/focus behavior, labels, contrast, motion, and assistive workflows | Mechanical accessibility evidence plus semantic findings; vision is supplementary |
| UX / visual reviewer | Operate the real interface and judge hierarchy, comprehension, consistency, responsiveness, and polish | Interaction trace, screenshots/video, UX findings, and non-visual state evidence |
| API / data-contract specialist | Validate schemas, compatibility, transactions, migrations, serialization, and real server behavior | Contract tests, request/response/database evidence, and compatibility verdict |
| Platform specialist | Own one declared environment such as web, macOS, Apple simulator, Android, Windows, Linux, CLI, or TUI | Platform-specific build/run/use evidence; support is not claimed from an enum or mock |
| Integration agent | Select or combine accepted results, resolve conflicts, and validate the integrated snapshot | Exclusive integration-workspace manifest and post-integration gates; cannot independently approve its own work |
| Code reviewer | Inspect an immutable candidate or diff for correctness, maintainability, regressions, and missing tests | Prioritized, reproducible findings; repair is a separate actor/attempt |
| Completion reviewer | Judge BirdCode's declared acceptance policy from provider-blind normalized evidence | Typed pass/fail/inconclusive verdict with exact evidence citations and a broker-enforced no-write grant |
| Context curator | Build the smallest lossless next-turn context while retaining all source events and open obligations | Content-addressed context manifest, included/omitted source list, and compaction checkpoint |
| Documentation / release specialist | Keep user-facing claims, usage, migration notes, evidence, packaging, and release metadata exact | Documentation/packaging patch and claim-to-evidence map; publication remains gated |
| Approval guardian | Review one exact authority expansion or destructive/public effect at an existing boundary | Approve/deny/timeout for that request only; cannot broaden the sandbox itself |

Authoritative review roles require policy-separated identity from the producer.
Two explorers or candidate implementers may intentionally share a model when
the experiment says so; that does not make them independent reviewers. Model
ID, deployment, independence domain, prompt lineage, context, and author role
are recorded separately so BirdCode never collapses “different agent” into
“independent judgment.”

## Tool contract required for every capability

Every advertised tool must have a machine-readable descriptor containing:

- stable tool ID, version, input schema, output schema, and adapter version;
- side-effect class: observe, workspace-local, process, network, credential,
  external mutation, integration, publication, or destructive;
- permission scope and exact filesystem/network/device/resource selectors;
- idempotency and a durable pre-effect boundary;
- timeout, cancellation, process-tree cleanup, retry, and unknown-outcome rules;
- request, response, stream, file, match, artifact, and aggregate hard bounds;
- platform and availability evidence rather than guessed environment labels;
- canonical request/observation artifacts, clocks, exit state, logs, hashes, and
  causal agent-thread/turn/work-order/execution/attempt bindings;
- threat assumptions, including what the adapter cannot contain safely.

Each invocation record additionally binds the requesting agent's requested,
inherited, policy-resolved, and effective model/reasoning, permission, sandbox,
and tool-inventory evidence. Those execution facts are not guessed from the
static tool descriptor.

A model output is only a request. The broker resolves paths and resources,
checks grants and ceilings, writes `Prepared`, performs the effect, and writes
exactly one `Observed` or `OutcomeUnknown`. Known denial, validation, I/O, or
limit failures are observed failures—not “unknown” merely because the model did
not like the result.

## Agent identity and lifecycle semantics

BirdCode treats an addressable agent identity and the work performed through it
as different durable objects:

- an `AgentThread` is the reusable coordination identity and mailbox address;
- a `Turn` is one activation of that thread and has its own input boundary and
  terminal state;
- an `Execution` binds one work order, resolved context, model, authority,
  workspace, and budget to work performed during a turn; and
- an `Attempt` is one causally linked inference, tool, retry, repair, or resume
  attempt and never overwrites an earlier attempt.

Lifecycle operations are not aliases:

- `SendMessage` durably queues a bounded message without activating an idle
  thread;
- `FollowUp` targets an existing thread and either starts a new turn when idle
  or performs explicitly ordered steering of its active turn;
- `InterruptTurn` stops the current turn at a recorded boundary but leaves the
  thread addressable and does not by itself prove owned tools were cancelled;
- `CancelExecution` is generation-bound, stops new dispatch, reconciles owned
  model/tool/process work, and records cleanup before `Cancelled`;
- `CancelSubtree` propagates that cancellation through descendants without
  turning late messages into new work; and
- `CloseThread` retires the address only after active work, mail, leases, and
  tools are reconciled, so a later continuation requires a new thread identity.

List and wait projections identify both thread and current/latest turn. They
distinguish idle, running, waiting, completed-turn-but-reusable, interrupted,
failed, cancelled, closed, missing-report, and ambiguous-boundary states.
Timeout is a wait observation, not task failure. A worker that terminates
without its required handoff is an explicit failure, and an ambiguous effect
boundary is `OutcomeUnknown`; neither can be projected as success.

## Tooling Plane families

| Tool family | Required capabilities |
| --- | --- |
| Agent lifecycle | Spawn/delegate; stable thread plus turn/execution/attempt identity; nested bounded delegation; list/status; cursor- or target-bound wait; message without activation; follow-up/new-turn or ordered active-turn steering; turn interruption; execution cancellation; thread close; dependency handoff; retry; budget steering; subtree cancellation and cleanup |
| Planning and policy | Goal create/inspect/terminal update and budget status, distinct from run and plan; plan create/patch/replay; obligation and acceptance catalogs; capability discovery; assignment eligibility; authority request; user clarification; completion gate; and audit dispatch |
| Context and artifacts | Context compile; explicit no-history/all-history/bounded-history or manifest-selected fork; included/omitted source and turn manifest; compaction/checkpoint; content-addressed put/get; bounded paging; artifact verification; evidence normalization; and provenance export |
| Progress and projections | Non-authoritative bounded commentary and progress events, durable state-derived status projections, ordered terminal delivery, truncation/artifact references, and a self-contained final result that never relies on transient progress prose |
| Repository intelligence | Snapshot identity, bounded tree/list, byte-range read, exact literal search, regex search as an explicitly separate granted tool, symbols, references, diagnostics, dependencies, ownership/history, and change-impact graph |
| Change construction | Create/write/patch, move/rename, delete/trash, mode changes, generated assets, structured edits, diff, and patch validation within an isolated workspace |
| Git and workspace isolation | Status/diff/log/blame, immutable snapshot, branch, worktree/overlay, lease, patch export/import, merge/rebase/cherry-pick as separate effects, conflict inspection, cleanup, and publication-ready identity |
| Shell and processes | Typed argv/env/cwd, non-PTY and PTY sessions, stdin, streaming output, process tree, ports, signal/cancel, timeout, resource limits, daemon lifecycle, health, and proven cleanup |
| Build and language intelligence | Package managers, dependency resolution, compiler/linker, formatter, linter, unit/integration/property/fuzz tests, coverage, LSP symbols/references/diagnostics, binary/package inspection, and SBOM/license evidence |
| Web | Browser lifecycle, Playwright navigation/input, DOM, accessibility tree, console, network trace, storage/cookies under policy, screenshot/video, viewport/device profiles, visual comparison, and real server coordination |
| API and server | HTTP/WebSocket/gRPC clients, schema validation, authentication broker, fixtures, database/state inspection, load/fault probes, logs/traces, health/readiness, and shutdown |
| CLI and TUI | Spawn/PTY, input sequences, terminal geometry, ANSI/screen state, exit codes, filesystem effects, accessibility where available, and session recording |
| macOS desktop | Build/sign/package, launch/terminate, Accessibility API tree/actions, window/menu/dialog state, screenshot/video, logs/crashes, filesystem state, and notarization evidence |
| Apple simulators | Simulator lifecycle, install/launch, UI automation/accessibility, device state, permissions, deep links, logs, screenshots/video, networking, and cleanup |
| Android | Emulator/device lifecycle, install/launch, instrumentation/UI automation, accessibility, logcat/crashes, screenshots/video, network/state, and cleanup |
| Windows | Build/package/sign/install, process/service lifecycle, UI Automation, event logs/crashes, filesystem/registry state, screenshots/video, and clean VM/runner evidence |
| Linux | Build/package/install, process/service/container lifecycle, accessibility/UI automation where supported, journal/core logs, display/session state, screenshots/video, and clean runner evidence |
| Data and persistence | SQL/query/transaction/migration, schema diff, fixture lifecycle, backup/restore, object/blob stores, queues, deterministic data hashes, and destructive-operation approval |
| Knowledge and integrations | Official documentation, web/search, repository hosting, issues/PRs/reviews, CI, package registries, design/docs systems, and team communication through purpose-built connectors |
| Security and credentials | Secret references without value disclosure, scoped credential lease, network egress policy, dependency/security scanners, sandbox profile, permission review, audit log, and revocation |
| Media and visual artifacts | Image generation/editing, deterministic vector/code-native assets, screenshot, video, audio where needed, OCR/vision observations, metadata stripping, hashing, and human-review packaging |
| Integration and publication | Candidate comparison, patch selection, merge/conflict workflow, post-integration validation, commit/sign, push, PR/release, package upload, deployment, rollback, and explicit publication approval |

Tool families describe product reach; support is earned adapter by adapter. For
example, a `Windows` enum value is not Windows support, and a screenshot is not
proof that the underlying application state or workflow is correct.
The directly observed Codex collaboration surface did not expose per-child
budget steering, a durable typed mailbox, broker receipts, or isolated writer
workspaces. Those are intentional BirdCode requirements to exceed the observed
surface; they are not recorded as Codex facts without separate evidence.

## Current implemented slice

At the branch-bound observation above, three states must remain separate:
implemented library code, uncommitted/in-flight contracts, and behavior wired
through daemon plus client product surfaces. The dirty branch is not a release
or acceptance pin, and an in-flight type does not upgrade a capability claim.

| Capability | Current implementation | Limit |
| --- | --- | --- |
| Root producer and critic | Product-wired policy-separated semantic `PlanOnly` review and one bounded repair | Runtime still rejects `Execute` and non-zero `max_subagents`; no repository tools or child execution run through the product path |
| Planner/replanner v1 | Versioned typed prompt plus authoritative standalone plan kernel | Not daemon-wired and cannot launch product children |
| Planner/replanner v2 | Dirty-branch prompting contracts distinguish `InitialDelegation` from `EvidenceReplan` and bind accepted-plan or child terminal evidence | **In flight:** prompt/schema/tests only at this observation; no durable Store projection, backend invocation, supervisor transition, or client flow is claimed |
| Repository explorer | Versioned iterative Tree/ReadFile/LiteralSearch/Finish prompt with multilingual injection and evidence-binding tests | Model-backed child runtime is not product-wired, and the prompt contract must be compiled losslessly onto the authoritative Protocol wire before use |
| Repository broker | Real descriptor-relative read-only Tree, bounded byte ReadFile, and exact literal search implementation with prepare-before-effect transcripts, limits, and descriptor/identity checks | Implemented as a library but absent from daemon dependencies and runtime capability advertisement; snapshot immutability remains a caller lease precondition, and Windows needs a handle-relative adapter |
| Standalone orchestration | Actor graph, typed work-order DAG, grants, budgets, overlap, retry/no-effect, cleanup, handoffs, and in-memory journal | Uses generic/test workers; no daemon adapter, durable Store journal, model/tool worker, typed mailbox, or product lifecycle controls |
| Durable child state | Store schema v9 retains Protocol-v6-era child model/tool/handoff/recovery projections | No daemon/CLI/GUI child execution path. Store v9 does not make the dirty Protocol-v7 additions product-wired |
| Protocol v7 additions | Dirty source declares semantic planner-turn/delegation types, broker-v2 authorization/receipt/result/epoch types, exact observed-tool evidence, and a reconnaissance purpose/capability enum | **In flight:** the runtime does not advertise the capability, `ClientCommand` has no child lifecycle API, and Store/tooling/daemon have not been shown to implement one lossless v7 execution wire |
| Execution and validation | Typed manifests, commands, provenance, evidence policy, and review packages | No general process/browser/platform executor yet |

The first accepted runtime milestone is two real model-backed read-only explorers
running concurrently against one immutable snapshot, each performing a durable
model→tool→model loop and returning content-addressed handoffs. The root then
replans from bounded handoff content and exact tool evidence and stops in the
truthful `Waiting` state. It does not claim code implementation, completion, or
Codex parity.

## Prioritized machine-readable registry work

The prose registry above is not the executable registry. The following additive
type families are the priority order; their names describe BirdCode contracts,
not hidden Codex implementation. Semantic selection stays model-produced and
schema-validated. Deterministic code resolves eligibility, containment, bounds,
and effects without model-name, keyword, regular-expression, filename,
extension, or language branches.

| Priority | Machine-readable additions | Acceptance boundary |
| --- | --- | --- |
| P0 — identity and context | `AgentThreadId`, `AgentTurnId`, `AgentExecutionId`, `AgentAttemptId`, causal generation, `HistoryForkPolicyV1`, exact `ContextManifestV1`, and `CompactionCheckpointV1` with included/omitted source IDs | A completed or interrupted turn can be followed up without overwriting history, while context, filesystem, peer visibility, and permissions remain separate axes |
| P0 — role/profile registry | `AgentRoleDefinitionV1` and `ResolvedRoleProfileV1` carrying purpose, typed inputs/outputs, prompt lineage, model requirements, context policy, capabilities, authority ceiling, isolation, independence, budgets, and evaluation history | Runtime can explain why a profile was eligible and selected from measured evidence; a role label grants no authority |
| P0 — tool registry | `ToolDescriptorV1` plus stable tool/version IDs, schema hashes, side-effect class, selectors, bounds, pre-effect rule, idempotency, timeout, cancellation, retry, cleanup, unknown-outcome, platform, and adapter-attestation fields | Every advertised tool is discoverable and every call is validated against the exact retained descriptor version |
| P0 — effective resolution | `RequestedAuthority`, `InheritedAuthority`, `ResolvedAuthority`, `EffectiveAuthorityEvidence`, `ModelProfileSnapshotV1`, `ProfileEligibilityDecisionV1`, and `ResolvedAssignmentV1` | Requested model/reasoning/sandbox/tools remain distinct from backend- and broker-attested effective values, including explicit unavailable/operator-declared states |
| P0 — durable lifecycle | Prepared/observed/unknown events and commands for spawn, list/inspect, message, follow-up, wait cursor, interrupt turn, cancel execution, cancel subtree, close thread, retry, handoff, and terminal delivery | Restart/race tests prove activation, identity reuse, cleanup, timeout-as-observation, missing report, and exactly-once/idempotent boundaries |
| P0 — first runtime vertical | Idempotent caller-identified event append, snapshot lifecycle port, one Protocol/Store/Tooling broker wire, semantic delegation authorization, evidence replan, and `ParallelRepositoryReconnaissanceV1` runtime adapter | Two real model-backed read-only explorers overlap against one immutable snapshot and return durable evidence before a truthful `Waiting` replan |
| P1 — coding and integration | Isolated writer workspace/lease descriptors; file mutation, patch/diff/Git tools; implementer/candidate, tester, reviewer, integrator, and completion-review profiles; immutable review and integration manifests | Parallel writers cannot affect the user checkout or peers, and no producer/integrator certifies its own result |
| P1 — validation breadth | Typed process/PTY/build/test adapters first, then browser/Playwright, API/server, CLI/TUI, macOS/simulators, Android, Windows, and Linux descriptors | Each adapter earns support with retained commands, environment, logs, exit/process state, accessibility/state evidence, artifacts, hashes, and cleanup—not an enum or screenshot alone |

## Evidence required before a role or tool is “supported”

A role/tool pair moves from planned to supported only when retained evidence
shows:

1. the actual prompt/descriptor, requested and resolved model/reasoning,
   backend-effective identity evidence, policy, environment, command or request,
   output, timestamps, scoped exit/terminal state, and artifacts;
2. the selected history fork and exact context inclusion/omission manifest, plus
   the requested, inherited, resolved, and effective permission/tool inventory;
3. success, known failure, missing report, turn interruption, execution and
   subtree cancellation, thread reuse and close, deadline, crash/restart,
   ambiguous boundary, injection, limit, and forged-evidence behavior;
4. replay reproduces the same authoritative state without reinterpreting free
   text;
5. multilingual and adversarial content remains data rather than authority;
6. parallel claims include comparable monotonic intervals, not wall-clock
   inference;
7. an independent review checks cross-contract losslessness in addition to
   isolated unit tests; and
8. user-facing documentation states the exact adapter/platform/model scope and
   remaining threat boundary.

BirdCode will continuously run this matrix against local models, manual control
outputs, and clean-room Codex baselines. The same outcome-based validation
harness judges all candidates blind to provider identity whenever the surface
allows a fair comparison.
