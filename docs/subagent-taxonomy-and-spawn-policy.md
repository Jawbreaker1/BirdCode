# Subagent taxonomy and spawn policy

Document version: `0.1.0`

Observation baseline: `2026-07-21`

Status: normative BirdCode design baseline; clean-room Codex observations are
explicitly separated from BirdCode requirements.

## Purpose and clean-room boundary

This document defines how BirdCode names agent roles and decides whether to
delegate work. It is based only on public product documentation, behavior
visible through supported Codex surfaces, and BirdCode's own source and retained
evidence. It does not inspect or infer private Codex code, prompts, storage,
scheduler logic, or service topology.

Public sources are the [OpenAI Codex manual — Multi-agent operations](https://developers.openai.com/codex/codex-manual.md#multi-agent-operations)
and [OpenAI Subagents documentation](https://learn.chatgpt.com/docs/agent-configuration/subagents).
Repository contracts are the [agent/tool registry](agent-roles-and-tools.md),
[clean-room ledger](clean-room-codex-capability-ledger.md),
[orchestration architecture](orchestration.md), and
[benchmarking protocol](benchmarking.md).

The following claim IDs make this document's own clean-room assertions
traceable. The observation date for this baseline is `2026-07-21`.

| Claim ID | Class | Claim | Evidence |
| --- | --- | --- | --- |
| `SA-DOC-001` | `DOC` | Codex documents the built-ins `default`, `worker`, and `explorer`. | Official Codex manual, “Custom agents”, fetched through the OpenAI Docs workflow on the observation date. |
| `SA-DOC-002` | `DOC` | Custom profiles define name, description, instructions, optional or inherited model, reasoning, sandbox, MCP, skills, and presentation nicknames; a matching custom name can take precedence over a built-in. | Same official manual section. |
| `SA-DOC-003` | `DOC` | Delegation may be explicit or required by applicable project or skill instructions; eligible Ultra operation may delegate proactively when independent work materially improves speed or quality. | Official “Multi-agent operations” activation sections. |
| `SA-DOC-004` | `DOC` | Public guidance favors bounded independent and read-heavy work and warns about coordination conflicts for parallel writers. | Official “Why subagent workflows help” section. |
| `SA-DOC-005` | `DOC` | Public subagent examples include exploration, tests, log analysis, triage, summarization, security review, test-gap review, and maintainability review as delegated workloads. | Official “Why subagent workflows help” and “Triggering subagent workflows” sections. |
| `SA-OBS-001` | `OBS` | This development surface exposes distinct spawn, list, message, follow-up, interrupt, wait, and terminal-result behavior with selected history contexts and a shared checkout. | [Clean-room capability ledger](clean-room-codex-capability-ledger.md#observed-in-this-development-session). |
| `SA-DESIGN-001` | `DESIGN` | BirdCode uses semantic role selection followed by deterministic admission and durable lifecycle control. | This document and the [role registry](agent-roles-and-tools.md). |

This baseline uses normative terms deliberately: **MUST**, **MUST NOT**,
**SHOULD**, and **MAY** describe BirdCode requirements. They are not claims about
an undisclosed Codex implementation.

## Evidence classes

Every assertion about an agent type, activation condition, lifecycle behavior,
or effective runtime property MUST carry one of these classes in retained
evidence:

| Class | Meaning | Permitted claim |
| --- | --- | --- |
| `DOC` | Stated in current public documentation from the product owner. | The documented behavior exists at the cited public surface and date. |
| `OBS` | Directly surfaced or exercised in a version-pinned clean-room session. | The exact visible behavior occurred under the recorded environment and conditions. |
| `DESIGN` | A normative BirdCode requirement or proposed contract. | BirdCode intends to implement and later prove the behavior; it is not parity evidence yet. |
| `UNKNOWN` | Not established by public documentation or retained observation. | No affirmative or negative implementation claim may be made. |

An exposed interface is not automatically an exercised behavior. An exercised
behavior is not automatically durable, isolated, exactly-once, or general
across clients. A `DESIGN` item becomes implemented evidence only through the
acceptance process in the capability ledger; this document does not introduce a
fifth evidence class.

## Public Codex agent taxonomy

### Documented built-ins (`SA-DOC-001`)

The only agent types currently documented as Codex built-ins are:

| Built-in | Documented purpose |
| --- | --- |
| `default` | General-purpose fallback agent. |
| `worker` | Execution-focused agent for implementation and fixes. |
| `explorer` | Read-heavy codebase exploration agent. |

BirdCode MUST NOT describe any other role as a Codex built-in without a newer
official source that explicitly does so. A session task name, display nickname,
prompt description, or observed specialist purpose is not proof of a built-in
type.

### Configurable agents (`SA-DOC-002`)

Codex publicly supports custom agent profiles. A custom profile has a
user-defined `name`, `description`, and `developer_instructions`, and may
configure or inherit model, reasoning effort, sandbox, MCP servers, skills, and
display nicknames. A project or personal custom profile can use the same name as
a built-in and take precedence in that configuration.

A configurable profile is an open extension mechanism, not evidence of a
larger hidden built-in taxonomy. The documented `reviewer` profile and examples
such as documentation research or security-focused review are custom-agent
patterns. Nicknames are presentation-only and MUST NOT be treated as role,
authority, or model identity.

### Functional roles and workflows (`SA-DOC-004`, `SA-DOC-005`)

Public documentation also describes functional subagent work such as
exploration, tests, triage, log analysis, summarization, security review,
test-gap review, and maintainability review. These are workload archetypes and
prompt examples, not additional built-in agent types.

The main/root coordinator is an orchestration responsibility: it retains user
intent and decisions, delegates bounded work, waits as required, and
consolidates results. The documented `default` built-in MUST NOT be assumed to
be the same private object as the main coordinator merely because their
purposes overlap.

## BirdCode functional taxonomy

BirdCode uses composable semantic purposes rather than a closed set of hard-coded
personas. The authoritative detailed responsibilities, authority ceilings,
inputs, outputs, and evidence requirements remain in the
[Agent roles and Tooling Plane registry](agent-roles-and-tools.md#role-families).
This document groups those purposes only for delegation policy:

| Group | Included role families | Delegation intent |
| --- | --- | --- |
| Coordination and intent | Root coordinator, semantic router, planner/replanner, requirements analyst, context curator | Preserve user intent, resolve ambiguity, construct or amend a plan, and compile bounded context. |
| Discovery and design | Repository explorer, architecture specialist, dependency/documentation researcher, API/data-contract specialist, platform specialist | Produce evidence-linked understanding or options without silently expanding scope. |
| Construction | Implementer, candidate implementer, documentation/release specialist | Produce a scoped candidate or artifact under an explicit workspace and authority grant. |
| Validation and diagnosis | Test designer, build/runtime operator, debugger, security reviewer, reliability/performance specialist, accessibility reviewer, UX/visual reviewer, code reviewer, completion reviewer | Generate independent evidence, reproduce behavior, diagnose failures, or judge a declared gate. |
| Integration and governance | Integration agent, approval guardian | Reconcile accepted candidates or adjudicate one exact authority boundary without self-certification or privilege creation. |

These groups are neither a mandatory pipeline nor an exhaustive ontology. A
planner MAY propose multiple agents from one family, omit unnecessary families,
or propose a new specialist purpose. The runtime MUST validate its typed
contract before admission. Semantic purpose does not itself grant tools,
permissions, model access, independence, or workspace ownership.

BirdCode MUST keep these concepts distinct:

1. **Role purpose** — what outcome and judgment the agent owns.
2. **Resolved profile** — instructions, model requirements, context policy,
   capabilities, authority ceiling, isolation, independence, and budgets.
3. **Work order** — the bounded objective, inputs, dependencies, obligations,
   acceptance criteria, and expected handoff for this execution.
4. **Runtime identity** — reusable thread plus distinct turn, execution, and
   attempt identities.

This separation lets a measured model profile serve several purposes and lets
several independent agents share a purpose without pretending that a label is
an implementation class.

### Child planning and nested delegation

A subagent is not restricted to a single opaque execution call. Its admitted
role/profile MAY include local planning, plan revision, tool use, evidence
evaluation, repair, and further bounded delegation. Nested delegation uses the
same semantic proposal and deterministic admission path as root delegation,
with the child's exact thread/turn/execution/attempt as parent.

A child plan cannot rewrite root-owned user intent, protected obligations,
acceptance policy, authority, or budgets. Descendant grants are subsets of the
entire ancestor chain, depth and fan-out remain mechanically bounded, and a
child or subtree can only return a handoff to its parent—it cannot declare the
root run complete. Role composition is therefore per admitted turn/work order,
not a permanent one-persona restriction on an agent thread.

## Documented activation sources (`SA-DOC-003`)

The current public baseline establishes three activation sources:

| Activation source | Documented scope | BirdCode interpretation |
| --- | --- | --- |
| Explicit user request | A user directly asks for subagents or parallel delegation, for example one agent per independent point. | The semantic planner MUST preserve the requested delegation intent, but deterministic admission may reject or pause unsafe, impossible, or over-budget proposals. |
| Applicable project or skill instruction | Local Codex clients may delegate when applicable `AGENTS.md` or skill instructions request it. | BirdCode MUST compile durable project/skill policy into typed trusted inputs; it MUST NOT rediscover delegation intent with keyword or regular-expression matching. |
| Ultra proactive delegation | In eligible Work mode configurations, Ultra may proactively delegate suitable independent work when doing so materially improves speed or quality. | BirdCode MAY support proactive semantic delegation when trusted product policy allows it and the proposal passes the same admission and evidence gates as explicit delegation. |

The public documentation recommends explicit delegation at most intelligence
levels. It separately documents direct or instruction-based activation for
current local Codex clients. BirdCode MUST retain the product surface,
intelligence/reasoning setting, instruction provenance, and exact activation
source rather than collapsing these cases into a generic `auto_spawned` flag.

An instruction such as “use subagents” is not authority to exceed parent
permissions, budgets, thread/depth limits, or user scope. Conversely, the lack
of an explicit request does not permit deterministic code to guess semantic
suitability from filenames, languages, keywords, regular expressions, or model
names.

## Semantic suitability assessment

Delegation suitability is a semantic decision produced by a model through a
versioned structured contract. The model MUST assess the relevant axes and cite
the available goal, plan, policy, repository, runtime, and prior-evidence inputs:

| Axis | Semantic question |
| --- | --- |
| Outcome separability | Can each child own a bounded result without changing the meaning of another child's objective? |
| Dependency readiness | Which work can start now, and which work depends on an unresolved decision or handoff? |
| Parallel benefit | Would concurrent work materially improve elapsed time, coverage, confidence, or final quality? |
| Context benefit | Would isolation keep noisy exploration, logs, traces, or large documents out of the authoritative root context? |
| Specialist benefit | Does a distinct tool, platform, model capability, perspective, or reasoning profile materially improve the result? |
| Independence need | Does an authoritative review, candidate comparison, or risk decision require policy-separated judgment? |
| Handoff clarity | Can the child return a bounded, typed, evidence-citing result that the parent or integrator can consume? |
| Integration cost | Can results be combined without unsafe concurrent mutation, ambiguous ownership, or disproportionate conflict resolution? |
| Authority and isolation | Can the work run under a contained grant and an appropriate snapshot, worktree, device, network, or credential boundary? |
| Verifiability | Can success, failure, missing report, and inconclusive evidence be distinguished mechanically? |
| Resource proportionality | Is the expected quality or speed gain justified by tokens, model calls, tool effects, time, storage, and cleanup cost? |
| Uncertainty reduction | Will a child resolve a material unknown rather than duplicate already sufficient work? |

These axes are not scores for deterministic routing. BirdCode MUST NOT encode a
weighted keyword classifier, regexp router, filename table, language switch, or
model-name branch that substitutes for this assessment. Deterministic code may
validate declared values and hard limits; it may not manufacture the semantic
conclusion.

### Anti-delegation cases

The semantic planner SHOULD propose no new child when one or more of these
conditions materially dominates. It MUST still author `Clarify` or `Escalate`
when that is the truthful current planner directive:

- the outcome is indivisible, dependency-blocked, or small enough that
  coordination would cost more than it saves;
- multiple writers would share mutable state without an admitted isolation and
  integration strategy;
- required authority, environment, capability, workspace, budget, or cleanup
  capacity cannot be granted safely;
- no precise handoff and acceptance boundary can be stated;
- the proposed child would merely duplicate work without an independence,
  candidate-diversity, coverage, or uncertainty-reduction purpose;
- a user clarification, policy decision, destructive approval, or publication
  decision cannot legitimately be delegated, so the planner must request the
  corresponding decision or escalation instead;
- existing children need reconciliation, or the root cannot integrate, review,
  or truthfully validate the result;
- the proposal optimizes agent activity rather than completed outcome quality.

Some cases above are semantic judgments; others become deterministic admission
failures once their typed facts are known. The runtime MUST preserve that
distinction in provenance.

## Conceptual `SpawnProposalV1`

`SpawnProposalV1` is the semantic planner's payload for the existing
`Delegate` directive. BirdCode retains one directive vocabulary:
`Execute | Delegate | Clarify | Escalate | Finish`. A spawn proposal never
introduces a competing direct, clarification, escalation, or defer language.
It is a conceptual contract for implementation planning, not yet a claim about
the repository's active wire schema.

```text
SpawnProposalV1 {
  schema_version, proposal_id
  bindings {
    root_run_id, parent_thread_id, parent_turn_id
    parent_execution_id, parent_attempt_id
    accepted_planner_turn {
      event_id, turn_id, accepted_output_digest, resulting_plan_digest
      root_snapshot_digest, obligation_snapshot_digest
      acceptance_policy_digest, context_manifest_digest
    }
    evidence_packet_digest, planner_policy_digest
    role_registry_digest, capability_registry_digest
    model_profile_snapshot_digest
  }
  activation_source {
    kind: ExplicitUser | ApplicableProjectInstruction |
          ApplicableSkillInstruction | PolicyPermittedProactive
    source_ids[], source_digests[]
  }
  protected_obligation_ids[]
  suitability_assessment {
    axes[] { axis, conclusion, rationale, evidence_refs[] }
    delegation_benefit, coordination_and_integration_risk
    unresolved_uncertainties[]
  }
  children[] {
    local_child_ref
    role_definition_ref { id, version, digest }
    semantic_purpose, objective, non_goals[]
    dependency_handoff_ids[], protected_obligation_ids[]
    profile_requirements, requested_capability_ids[], requested_authority
    context_policy, workspace_and_peer_isolation, independence_requirements
    budget_request, expected_handoff_schema
    evidence_requirements[], acceptance_criteria[]
  }
  orchestration {
    dependency_graph, intended_parallel_sets[]
    wait_policy, steering_policy, retry_or_replan_policy, integration_owner
    review_and_completion_gates[]
  }
  model_output_provenance
}
```

Every semantic conclusion MUST remain attributable to the model output and its
exact prompt, context manifest, model request, backend evidence, and validation
result. `semantic_purpose` explains the model's selection; executable behavior
is bound to the exact trusted `role_definition_ref` and registry digests. A
model may request an unknown specialist purpose, but it cannot author trusted
instructions or grant that purpose authority. Such a request requires a
separate trusted registration or escalation path before admission. Runtime
thread, turn, execution, and attempt identities are allocated only after
admission; `local_child_ref` is local proposal data, never a durable runtime
identity.

The routing-evaluation wire may carry this complete binding as a required
`causal_binding` copied from its trusted input envelope. The deterministic
scorer MUST require exact equality and reject a missing, stale, or foreign
binding before interpreting the semantic proposal.

## Semantic decision versus deterministic admission

The semantic planner owns:

- whether delegation is useful;
- decomposition and child purpose;
- which work should be parallel or dependent;
- specialist, perspective, and independence needs;
- expected handoffs and evidence;
- whether new evidence calls for replanning, clarification, or another child.

Planner output may request a constraint or validation gate, but it cannot prove
that a runtime property already holds. Parallel overlap, filesystem isolation,
fresh builds, cleanup, secret containment, effective model identity, and other
execution facts become evidence only through the deterministic runtime and its
retained observations or artifacts.

The deterministic runtime owns only policy and mechanical truth, including:

- schema, identifier, digest, and causal-binding validation;
- parent/child capability and authority containment;
- configured thread, depth, token, model-call, tool-call, wall-time, storage,
  retry, and cleanup ceilings;
- dependency-DAG validity and admitted prerequisite state;
- availability and attestation of tools, adapters, models, workspaces, devices,
  credentials, and network grants;
- exact context, snapshot, worktree, peer-visibility, and independence policy;
- prepared-before-effect, idempotency, cancellation, and unknown-outcome rules;
- handoff-schema and completion-gate validation.

Admission returns a typed result such as `Admitted`, `RepairableInvalid`,
`PolicyDenied`, `PreconditionUnsatisfied`, `ResourceUnavailable`, or
`AdmissionFailed`. No child effect has occurred at this boundary, so
`OutcomeUnknown` is not an admission result. `PreconditionUnsatisfied` names an
exact typed policy or resource condition; the runtime does not infer a
clarification by interpreting free text. The planner may then author `Clarify`
or `Escalate` from that retained evidence. When a semantic proposal is malformed
or inadmissible, the runtime MAY request bounded model repair or fail closed. It
MUST NOT silently replace the model's decision with a heuristic role or
decomposition.

## Lifecycle and transition triggers

BirdCode separates a reusable agent thread from each turn, execution, and
attempt. The minimum delegated lifecycle is:

| Stage | Entry trigger | Required result or next trigger |
| --- | --- | --- |
| `SuitabilityRequested` | New goal, accepted plan, changed evidence, failed validation, or explicit delegation instruction. | One version-bound planner directive from the existing five-value vocabulary. |
| `SpawnProposed` | Valid `Delegate` output containing `SpawnProposalV1`. | Durable proposal and provenance with one or more local child references. |
| `AdmissionEvaluated` | Proposal is durably prepared for policy validation. | Typed admission result; no child effect on rejection. |
| `ContextAndGrantResolved` | Proposal admitted and prerequisites available. | Exact context manifest, resolved profile, authority grant, budget, and isolation lease. |
| `SpawnPrepared` | All child inputs and causal bindings are durable. | One idempotent dispatch intent per admitted child. |
| `DispatchAttempted` | The prepared dispatch crosses the first child-effect boundary. | Exactly one `DispatchObserved` or `DispatchOutcomeUnknown` terminal for that attempt. |
| `DispatchObserved` | The provider/runtime reports a known accepted or rejected dispatch outcome. | On acceptance, addressable child thread, first turn, execution, and attempt identities; on rejection, a typed known failure. |
| `DispatchOutcomeUnknown` | The dispatch attempt crossed the effect boundary but its outcome cannot be established. | Recovery/reconciliation without blind redispatch of the same prepared attempt. |
| `RunningOrWaiting` | Child begins work or waits on a declared dependency, approval, tool, model, or message. | Durable observations, bounded progress, steering, or terminal transition. |
| `MessageQueued` | A bounded asynchronous message is admitted for an existing thread or active turn. | Ordered mailbox evidence; it does not activate an idle thread or allocate a new turn. |
| `FollowUpAdmitted` | A follow-up targets an existing thread. | A new turn is prepared when idle/completed, or ordered steering is admitted at a declared active-turn boundary. |
| `InterruptedOrCancelled` | User/policy interruption, execution cancellation, subtree cancellation, deadline, budget exhaustion, or shutdown. | Scope-specific terminal state plus reconciliation and cleanup evidence; thread reuse remains explicit. |
| `HandoffReported` | Child emits its required typed terminal result. | Schema/evidence verification or explicit missing/invalid-handoff failure. |
| `Consolidated` | Declared wait policy is satisfied or cannot be satisfied truthfully. | Root/integrator accepts, rejects, compares, or requests repair/replan. |
| `IntegratedAndReviewed` | Accepted prerequisites and candidates are available. | Integration evidence and independent gates required by policy. |
| `Completed`, `Waiting`, or `Failed` | Root completion policy passes, requires external input, or reaches a terminal failure. | Self-contained result and durable provenance; child completion alone never completes the root. |

Recovery after restart is a transition trigger, not a separate semantic role.
It MUST derive the next action from durable prepared/observed/unknown state and
MUST NOT redispatch an ambiguous effect merely because a process restarted.

## Explicit unknowns

The following remain `UNKNOWN` unless a future public source or retained
experiment establishes them:

- whether Codex has private built-in agent types beyond `default`, `worker`, and
  `explorer`;
- Codex's internal classifier, thresholds, prompts, role/profile mapping, or
  scoring algorithm;
- private context, compaction, mailbox, retry, persistence, scheduler, and
  service topology;
- exactly-once, ordering, crash-recovery, and race semantics behind visible
  lifecycle controls;
- effective model, reasoning, permissions, filesystem/worktree, and
  peer-visibility isolation when only requested configuration is visible;
- the quantitative meaning of “materially improve speed or quality” for Ultra
  proactive delegation;
- whether a visible `running` state proves simultaneous backend execution.

Absence from one client or session is not evidence of product-wide absence.
BirdCode MUST state these boundaries rather than filling them with architectural
guesses.

## First product implementation slice

The first implementation MUST be narrower than the full taxonomy while keeping
the general contract intact:

1. Extend the existing planner `Delegate` payload with typed purpose,
   execution shape, role requirement, decision reason, activation source, and
   exact causal bindings. Retain it losslessly through planner acceptance and
   durable Store events.
2. Resolve the proposal against a trusted role/profile registry. The first
   admitted entry is `repository_explorer_v1`; an unknown model-authored role
   request fails closed or returns to semantic replanning.
3. Admit exactly two read-only explorer children only when the accepted model
   proposal requests independent parallel work and all snapshot, authority,
   budget, capability, and context prerequisites are mechanically true.
4. Dispatch both against one immutable snapshot, retain observed overlap and
   bounded evidence-citing handoffs, then feed those handoffs into a new
   planner turn. A missing or inconclusive handoff cannot become `Finish`.
5. Keep the product capability flag false until a daemon-path restart-aware
   end-to-end run proves the complete slice. Later role families reuse this
   contract rather than adding role-name, language, filename, or model-name
   branches.

## Versioned clean-room experiment protocol

Experiments discover observable activation and role behavior; they do not seek
private implementation details. Every experiment suite MUST have a stable suite
ID and semantic version, for example `BC-CODEX-SPAWN-1.0.0`.

The initial structural and multilingual design fixtures are retained in
[`evals/subagent-routing-v1`](../evals/subagent-routing-v1/README.md). They are
test inputs for the future contract, not evidence that the current product can
execute the proposed roles.

### 1. Preregister the fixture

Before execution, retain:

- question, hypothesis, expected evidence class, observable outcomes, and
  disconfirming outcomes;
- exact task, protected obligations, acceptance criteria, and snapshot hash;
- Codex surface/version, account eligibility, selected model and
  intelligence/reasoning, permissions, and available tools;
- explicit user, `AGENTS.md`, skill, and proactive-policy inputs; and
- concurrency, time, token, tool, and retry budgets where visible.

### 2. Use a controlled fixture matrix

Each semantic task family SHOULD include matched variants for:

1. direct explicit delegation;
2. applicable `AGENTS.md` delegation instruction;
3. applicable skill delegation instruction;
4. Ultra proactive eligibility without an explicit delegation request;
5. a non-delegation control whose work is small, sequential, authority-blocked,
   or unsafe to parallelize;
6. read-heavy independent work and write-heavy conflict-prone work;
7. multilingual paraphrases that preserve meaning;
8. adversarial text containing tempting agent keywords without semantic need;
9. semantically equivalent tasks that avoid conventional agent terminology;
10. repeat runs sufficient to expose nondeterminism rather than treating one
    anecdote as policy.

Fixtures MUST NOT infer routing from string matches. Multilingual and
adversarial pairs exist specifically to detect accidental keyword, regexp,
filename, language, or model-name control flow.

### 3. Retain observable provenance

For every run, record where exposed:

- prompt/instruction provenance and requested/effective model/reasoning, with
  unavailable fields explicit;
- root/child identities, relationships, visible purposes, statuses and times,
  including monotonic overlap without equating UI state with backend overlap;
- visible context, tools, permissions, approvals, workspaces and isolation;
- messages, follow-ups, interruptions, waits, timeouts, handoffs and result;
- commands, logs, exits, artifacts, screenshots/traces and hashes; and
- missing, ambiguous, denied, timed-out, interrupted and failed outcomes.

Raw retained evidence MUST be kept separately from the normalized result used
for comparison.

### 4. Classify without overclaiming

The result MUST distinguish:

- documented expectation (`DOC`);
- interface exposed but not exercised (`OBS-exposed`);
- behavior directly exercised (`OBS-exercised`);
- BirdCode target (`DESIGN`);
- unresolved property (`UNKNOWN`).

A task-shaped specialist does not establish a built-in type. A requested model
does not attest the effective backend. A read-only instruction plus no observed
write does not attest mechanical read-only enforcement. A terminal prose result
does not prove typed, durable, or exactly-once handoff semantics.

### 5. Compare outcomes through one harness

When a fixture is used for BirdCode parity evaluation, Codex and BirdCode MUST
receive equivalent declared goals, snapshots, environmental access, and budget
policy. The same provider-blind validation harness MUST judge build results,
tests, real runtime behavior, evidence completeness, failures, and cleanup.
Greater child count or activity is never a superiority result.

### 6. Update append-only evidence

Each run appends an observation with date, suite version, source and environment
identity, hashes, outcome, and limitations to the clean-room capability ledger.
A correction supersedes an earlier entry; it does not silently rewrite history.
No parity gap passes until a commit-pinned BirdCode product-path run retains the
corresponding acceptance evidence.
