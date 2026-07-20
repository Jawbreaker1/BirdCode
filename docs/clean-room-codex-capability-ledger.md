# Clean-room Codex capability ledger

Ledger version: `0.1.0`

Observation date: `2026-07-19`

BirdCode baseline: `2bee9944678dfc4f3e08aa6319e5baba3a6c9112`

Scope: multi-agent behavior, roles, permissions, context, coordination, and
tooling relevant to measurable BirdCode parity

This is a behavioral acceptance ledger, not a reverse-engineering document. It
records public documentation, capabilities surfaced or exercised in a Codex
development session, and behavior proved by the BirdCode repository. It does
not infer Codex's private implementation, prompts, storage layout, scheduler,
or protocols.

BirdCode's objective is outcome parity or superiority, not internal similarity.
A matching class name, agent count, or architecture diagram is never sufficient
evidence. A parity claim requires the measurable behavior in this ledger, and a
superiority claim additionally requires the blind evaluation protocol in
[benchmarking.md](benchmarking.md).

## Evidence classes and source snapshot

Capability claims are grouped under or tagged with one of four explicit
classes. The later role table is a labeled synthesis of those claims, not a
fifth evidence class:

- **Officially documented (`DOC`)**: stated in public OpenAI documentation.
- **Observed in this development session (`OBS`)**: a callable surface,
  session contract, or result directly visible in the session dated above.
- **BirdCode current status (`BC`)**: implemented behavior supported by the
  repository at the pinned baseline commit.
- **Acceptance gap (`GAP`)**: behavior BirdCode must still prove. A gap is not
  evidence about how Codex is implemented internally.

The primary official source is OpenAI's
[Subagents documentation](https://learn.chatgpt.com/docs/agent-configuration/subagents).
The authoring pass used the current consolidated Codex manual's “Multi-agent
operations” section, lines 150–480. Its first sandboxed refresh attempt could
not resolve DNS; the required network-authorized retry succeeded on
`2026-07-19`. The durable BirdCode sources are [README.md](../README.md), [orchestration.md](orchestration.md),
[product-requirements.md](product-requirements.md), and
[crates/orchestrator/README.md](../crates/orchestrator/README.md).

## Officially documented

The following is a compact public behavioral baseline. It deliberately excludes
anything that can only be guessed from product output.

| ID | Documented behavior | Boundary relevant to BirdCode |
| --- | --- | --- |
| `DOC-MA-001` | Codex can spawn specialized subagents in parallel and collect their results into one response. | Parity requires real concurrent model/tool work, not sequential calls described as parallel. |
| `DOC-MA-002` | Each subagent works in an agent thread that supported clients can expose for progress and result inspection. | A child identity and inspectable lifecycle are part of the behavior, not optional telemetry. |
| `DOC-MA-003` | The main agent should remain focused on requirements, decisions, and final output while children handle bounded exploration, tests, triage, log analysis, or summarization and return distilled summaries. | Parity includes context separation and bounded handoff, not only fan-out. |
| `DOC-MA-004` | Codex can delegate after a direct request or applicable project/skill instruction. Public documentation advises explicit delegation for the normal case. | BirdCode must honor typed user/project policy without keyword or regexp routing. |
| `DOC-MA-005` | Codex orchestrates spawning, follow-up routing, waiting, result consolidation, and closing/stopping agent threads. | Lifecycle control must remain available after a child starts. |
| `DOC-MA-006` | Parallel read-heavy work is a recommended starting point; parallel writers require more care because they can conflict and increase coordination cost. | BirdCode should prove isolation and integration before advertising parallel writes. |
| `DOC-MA-007` | Subagents inherit the active sandbox/permission mode. Custom agents may specify an individual sandbox configuration such as read-only. | Child execution must be permission-bound, and role-specific narrowing must be testable. |
| `DOC-MA-008` | Codex ships with `default`, `worker`, and `explorer` agents. Their documented purposes are general fallback, implementation/fixes, and read-heavy exploration respectively. | These are the only three roles in this ledger treated as documented built-ins. |
| `DOC-MA-009` | Custom agent files define `name`, `description`, and `developer_instructions`; optional model, reasoning, sandbox, MCP, and skill settings inherit when omitted. | Reviewer, tester, and integration profiles may be explicit custom roles rather than hard-coded built-ins. |
| `DOC-MA-010` | Agent model and reasoning effort can be selected or inherited. The docs position `gpt-5.6` for demanding work, `gpt-5.6-terra` for faster supporting work, and higher reasoning for complex review. | BirdCode parity is role/capability selection behavior, not use of the same proprietary model. |
| `DOC-MA-011` | `agents.max_threads` bounds open threads and `agents.max_depth` bounds nesting. The documented defaults are six threads and depth one. | Fan-out and recursion require explicit, mechanically enforced ceilings. |
| `DOC-MA-012` | Subagent model/tool work consumes more tokens than a comparable single-agent run. | Budget and usage evidence are first-class acceptance data. |
| `DOC-MA-013` | The documented experimental `spawn_agents_on_csv` workflow creates one worker per input row, waits for the batch, requires one structured result report per worker, and exports combined results under concurrency/runtime bounds. | Behavioral parity can use another typed batch format, but must prove bounded many-item fan-out, per-item identity/result accounting, and explicit missing-result failure. |
| `DOC-MA-014` | `/review` starts a dedicated reviewer over an explicit diff scope and reports prioritized actionable findings without changing the working tree; delivery may remain in the current chat or use a detached review chat. | Independent review needs an immutable subject, explicit scope, no silent repair, and a separately evidenced verdict. |
| `DOC-MA-015` | Auto-review routes an already-required approval to a separate reviewer agent that sees a compact transcript and exact request, may make rare read-only checks, and approves, denies, or times out without expanding the sandbox. | BirdCode needs a distinct permission guardian whose decision changes authorization flow but cannot manufacture capabilities; failure and repeated denial must fail closed. |

The official custom-agent example includes a read-only code explorer, a
high-reasoning read-only reviewer, and a documentation researcher with a
dedicated MCP server. These are examples, not a statement that every reviewer
or documentation agent always uses those exact models or tools.

## Observed in this development session

The current session exposes the following coordination interface. “Exposed”
means the callable contract was present; “exercised” means this authoring task
also observed a result from it. No claim extends beyond this session version.

| ID | Session surface | Observation status | Observable contract or result |
| --- | --- | --- | --- |
| `OBS-MA-001` | `spawn_agent` | Exercised by the parent | A bounded task created this separate child at canonical path `/root/codex_capability_ledger`. The spawn surface accepts a task name, instructions, context-fork choice, and optional model/reasoning overrides. |
| `OBS-MA-002` | Separate child context | Exercised | This child received its own task/thread identity and task-specific instructions while retaining the context selected by the parent. The exact internal context representation was not exposed. |
| `OBS-MA-003` | `list_agents` | Exercised directly | A snapshot returned canonical agent paths and `running` or terminal status. It showed the root, this child, another running specialist, and one completed specialist with a compact terminal result. |
| `OBS-MA-004` | Summary handoff | Exercised by another child; required for this child | The completed specialist's terminal result was visible to the root as a concise summary. This child is likewise required to return a final result to its parent. A list snapshot did not expose the completed child's raw intermediate transcript. |
| `OBS-MA-005` | `followup_task` | Exercised by the parent | The parent reused a completed specialist with a new bounded adversarial-test task, triggering a new turn without allocating another thread identity. |
| `OBS-MA-006` | `send_message` | Exercised by the parent | The parent delivered convergence requests to running specialists without replacing or separately triggering their active turns. |
| `OBS-MA-007` | `interrupt_agent` | Exposed, not exercised in this authoring task | The surface can interrupt a target's current turn and report its prior status while leaving the agent addressable. |
| `OBS-MA-008` | `wait_agent` | Exercised by the parent | Bounded waits returned both timeout results and a later child completion notification without blocking the root indefinitely. |
| `OBS-MA-009` | Shared filesystem/worktree | Session contract and directly usable | Agents in this team share the filesystem and current directory. This task was explicitly scoped to the BirdCode `agent-kernel-worktree` checkout. Separate agent contexts therefore do **not** imply separate writable worktrees in this session. |
| `OBS-MA-010` | Concurrency | Session contract; state observed | This session declared four total concurrency slots including the root. This is an environment-specific limit and does not contradict the documented configurable/default Codex thread cap. |
| `OBS-MA-011` | Model identity and overrides | Override surface exposed; identity not observed | Spawn supports optional model and reasoning selection under context-fork constraints. `list_agents` did not report the exact model or reasoning setting for any listed agent, so this ledger does not infer them. |
| `OBS-MA-012` | Permissions | Session contract and command behavior observed | This child had workspace write access for the scoped BirdCode checkout, read access elsewhere as declared, restricted network access, and approval rules for escalated effects. No child-specific privilege expansion was tested. |
| `OBS-MA-013` | Structured CSV batch fan-out | Officially documented, not surfaced in this session | No `spawn_agents_on_csv` or per-row result-reporting surface appeared in this session's collaboration interface, so its runtime behavior was not observed here. |
| `OBS-MA-014` | Nested specialist delegation | Exercised by a child | The semantic-kernel implementation agent independently spawned `/root/kernel_recovery_hardening/recovery_transition_review` to review a bounded protocol/store recovery transition while its parent continued implementation. This proves that this session allowed a child to refine its own plan and delegate one deeper specialist task; it does not reveal the scheduler or imply that unrestricted recursion is safe. |
| `OBS-MA-015` | Live steering from evidence | Exercised by the root | An explicit CLI bin-test exposed a missed compile error after an earlier `--lib` command had skipped the binary. The root sent that exact evidence to the already-running product-surface validator, then separately asked it to assess whether the GUI truthfully exposed producer/critic readiness. This demonstrates evidence-bearing steering without replacing the child's task identity. |
| `OBS-MA-016` | Requested model/reasoning profile | Exercised at spawn; runtime attestation unavailable | Three bounded specialists were requested with `gpt-5.6-sol` and `ultra` reasoning for kernel recovery, product-surface validation, and runtime lint hardening. The coordination listing did not expose the effective model/reasoning identity, so this is evidence of the requested profile only—not proof of backend execution identity. |

The session therefore demonstrates distinct addressable agent threads, compact
terminal handoff, shared workspace visibility, and a lifecycle-control surface.
It does **not** by itself demonstrate write isolation, durable replay after
process restart, child-specific model attestation, exactly-once message
delivery, or every control's runtime semantics.

## Agent-role ledger

“Role” describes purpose and acceptance behavior. It does not imply a hidden
Codex class. Only roles explicitly named as built-ins in `DOC-MA-008` are
treated as such. Unless the “Standing” column says a detail is documented, the
purpose, authority, and tooling columns define BirdCode's `GAP` acceptance
profile rather than undocumented Codex behavior.

| Role | Standing | Purpose | Context and handoff | Permissions | Model profile | Expected tooling |
| --- | --- | --- | --- | --- | --- | --- |
| Root / main coordinator and `default` fallback | The main-agent pattern and the `default` built-in are officially documented, but they are not asserted to be the same internal object. | Own user intent, constraints, decomposition, delegation, decisions, consolidation, clarification, and final result. | Keeps the authoritative conversation; gives children bounded tasks; consumes summaries and referenced evidence rather than copying all child noise into the root context. | Holds the parent permission envelope and must never manufacture authority through delegation. | Demanding planning and integration need a capable profile and sufficient reasoning; exact selection may inherit or be pinned. | Agent lifecycle controls, plan/state store, repository context, evidence inspection, messaging, acceptance gates, and integration dispatch. |
| Worker / implementer | `worker` is a documented built-in. | Implement or repair a scoped outcome, validate the changed behavior, and return a concrete patch/artifact handoff. | Separate task context with objective, relevant evidence, write scope, and acceptance criteria; returns summary, changes, validation, and unresolved risks. | Workspace-write only for an explicit scope; parallel writers require isolated workspaces before BirdCode may claim safety. | Strong coding/tool-use profile for ambiguous changes; a faster profile is acceptable for narrow, well-measured fixes. | Targeted repository read/write, patching, shell/process control, build/lint/test, Git diff, and artifact/evidence capture. |
| Explorer | `explorer` is a documented built-in. | Map code paths, dependencies, symbols, behavior, and risks without changing product state. | Read-heavy isolated context; returns source-linked findings and a compact map for planners/workers. | Read-only repository and bounded read-only external sources by default. | Fast/efficient profiles are explicitly documented as suitable for scans; capability must still be measured. | Tree/search, targeted file reads, symbols/references, history/diff inspection, documentation lookup, and bounded log analysis. |
| Reviewer / auditor | Not a documented built-in; officially shown as a narrow custom-agent pattern. | Find correctness, security, regression, maintainability, and missing-test risks; judge declared acceptance independently where policy requires it. | Receives an immutable candidate/evidence packet, not the producer's persuasion; returns prioritized findings with reproductions and evidence. | Read-only candidate and evidence access; no authority to silently repair or approve its own authored work. | Higher reasoning is documented as useful for review/edge cases. BirdCode additionally requires an attested independence domain where review is authoritative. | Diff/source inspection, tests and reproductions, static/security tooling, evidence browser, and typed verdict/finding output. |
| Dedicated code-review execution | `/review` is officially documented as a dedicated reviewer flow, not as another named built-in subagent profile. | Inspect a selected base-branch, uncommitted, commit, or custom diff and return prioritized actionable findings without editing it. | Receives the selected repository diff and review criteria; results remain in the current chat or a configured detached review chat. | Read-only for the reviewed working tree. A later repair is a separate action under the chat's normal sandbox and approval policy. | May use a separately configured `review_model`; effective identity still requires runtime evidence. | Git diff/review scopes, source inspection, inline findings, review-pane evidence, and optional detached-chat delivery. |
| Approval reviewer / guardian | Auto-review is officially documented as a separate reviewer agent at an existing approval boundary. | Decide whether one exact boundary-crossing action may run, with rationale and fail-closed handling for review failures. | Receives a compact retained transcript and the exact escalation request; may rarely make bounded read-only checks. | Changes who reviews the request, never the sandbox, filesystem/network limits, or permission envelope. | Separate reviewer invocation; the public behavior does not justify assuming a particular model identity. | Exact approval request, compact transcript/tool evidence, rare read-only inspection, risk/policy evaluation, approve/deny/timeout result, and denial circuit breaker. |
| Custom specialist | Officially documented configurable agent family, not one fixed role. | Supply a narrowly described capability such as documentation research, security review, platform specialization, or repository exploration. | Resolves `name`, `description`, and developer instructions plus explicit or inherited settings before entering the normal child-thread lifecycle. | Optional sandbox and tool configuration may narrow the inherited envelope; omission must not imply extra authority. | Optional model and reasoning selection, otherwise inherited. | Role-specific MCP servers, skills, repository tools, and lifecycle controls selected by the resolved profile. |
| Tester / validator | Not a documented built-in; tests and log analysis are documented subagent workloads. | Execute focused validation, distinguish product failure from infrastructure uncertainty, and report reproducible observations. | Receives target, environment, acceptance checks, and bounds; returns commands, exit/process state, logs, artifacts, and inconclusive checks explicitly. | Usually read-only source plus authority to create bounded test artifacts and operate declared processes/environments. | Efficient profiles can run mechanical flows; semantic/visual evaluation requires an eligible measured profile. | Test runners, build tools, process control, browser/API/CLI/platform adapters, logs/traces/screenshots, and content hashes. |
| Structured batch worker | The experimental CSV fan-out workflow is documented execution behavior, not a semantic built-in role. | Process one typed input row and emit exactly one structured result under a bounded many-item fan-out. | Per-row identity and result accounting; the parent waits for the batch and exports combined results, surfacing missing results. | Inherits the configured worker envelope and remains subject to concurrency/runtime bounds. | Worker profile is selected by the batch workflow; exact effective identity needs evidence. | Typed row input, per-item worker execution, mandatory structured result report, bounded concurrency/runtime, and combined export. |
| Integration / coordinator | Result consolidation by the main agent is documented; a separate integration agent is not documented as a built-in. | Select or combine accepted candidates, resolve conflicts through an explicit workflow, run post-integration gates, and preserve one authoritative result. | Consumes typed handoffs from all prerequisites and produces an integration manifest, resulting snapshot, evidence, and remaining risks. | Exclusive staged-write authority for the integration workspace; cannot act as the sole independent reviewer of its own integration. | Strong reasoning and tool use for multi-source conflicts; exact model should be selected from measured profiles. | Git/worktree or overlay operations, three-way diff/conflict inspection, patch validation, build/test adapters, provenance, and publication gates. |

### Role observations in this session

- `/root` acted as the root/coordinator by delegating bounded, independently
  useful work and retaining responsibility for the combined outcome.
- `/root/codex_capability_ledger` is a specialized documentation worker. Its
  canonical path proves task identity, not selection of the documented Codex
  `worker` built-in.
- A completed specialist ran focused format, test, and Clippy validation and
  returned a compact terminal summary, demonstrating a combined
  worker/tester-shaped task. The listing did not expose its model profile.
- A separate critic-shaped task was concurrently visible. Its presence alone
  is not evidence that reviewer independence, read-only policy, or review
  quality passed.
- No observed metadata identified a built-in `explorer`, a production
  integration actor, or an isolated parallel writing worktree.
- `/root/kernel_recovery_hardening` owned semantic state-machine correctness;
  its nested `recovery_transition_review` specialist separately checked the
  legality of terminal recovery after committed corrupt evidence. Their
  expected tools were targeted source reads, patching, Rust tests, and Clippy.
- `/root/product_surface_validation` owned the CLI/client/desktop projection
  boundary and received test evidence from the root while running. Its expected
  tools were focused code inspection, Rust bin/library tests, TypeScript
  typechecking, and bounded GUI-test execution.
- `/root/runtime_clippy_hardening` owned only prompt-runtime maintainability and
  was prohibited from changing wire or semantic behavior. It reported 32/32
  runtime tests and strict Clippy green after focused Rust refactoring.
- `/root/docs_truth_audit` performed a read-only claim-to-code/assets audit. It
  used repository search, numbered source reads, and local image inspection;
  it made no writes or network requests, and its effective model identity was
  not exposed by result metadata.

## BirdCode status at baseline `2bee9944678dfc4f3e08aa6319e5baba3a6c9112`

This section is pinned to the baseline commit above. Uncommitted work and later
commits must not silently upgrade these claims.

| Capability | BirdCode current status (`BC`) | Honest limit |
| --- | --- | --- |
| Root execution | A durable, product-wired `PlanOnly` turn invokes the exact selected LM Studio model and retains prompt, request, provider evidence, proposal, validation, and accepted plan artifacts. | The live root receives the goal and repository identity, not repository contents or tool observations. It does not yet execute work orders or semantic repair/review. |
| Semantic routing | A standalone LLM router and one bounded evidence-only repair contract are implemented and evaluated without heuristic fallback. | They are not wired into daemon, GUI, or CLI execution. |
| Planning/replanning | A standalone typed planner/replanner supports plan patches and `Execute`, `Delegate`, `Clarify`, `Escalate`, and `Finish` directives. | It is not daemon-wired and does not launch production children. |
| Parallel scheduling | The standalone actor-graph kernel validates a model-authored DAG and executes dependency-ready in-memory/test workers with proven overlap and bounded retries, deadlines, cleanup, budgets, and failure propagation. | There is no model-backed `AgentWorker`, production journal adapter, live mailbox, daemon supervisor flow, or product UI/CLI thread flow. Writes fail closed. |
| Context and handoff contracts | Work orders carry context-manifest digests, and the kernel validates bounded, evidence-referencing handoffs with causal identities. | No production child context compiler, semantic retrieval, compaction, or durable mailbox delivery exists. |
| Permissions and workspace | The standalone policy validates capability-set containment, immutable snapshot leases, read-only access, candidate separation, and reviewer lineage constraints. | There is no production permission broker, atomic write-lease manager, workspace provisioner, worktree/overlay isolation, or credential/network broker. |
| Reviewer/validator foundation | Reviewer independence rules exist in the standalone actor graph. The validation crate defines immutable manifests, hash-linked evidence policy, and blind review packages. | No live semantic critic/reviewer actor or process/platform validation adapter executes through the product. Existing retained reviews do not prove a general runtime. |
| Agent tools | Provider and runtime boundaries are typed. | No repository, filesystem, shell, Git, browser, API, desktop, simulator, or other general tool is exposed to a live BirdCode agent. |
| Lifecycle and observability | The PlanOnly daemon path has durable events, run identity, claims, cancellation, replay, exact token evidence, and GUI/CLI projections. | There are no child-thread list/inspect/steer/interrupt/wait controls, subtree cancellation, child crash recovery, or integration timeline. |
| Model profiles and assignments | Exact LM Studio model discovery is product-wired. The standalone graph binds assignments to trusted-policy-declared model-profile IDs and lineage. | BirdCode has no live evaluation-derived profile registry or backend-attested child-lineage assignment path. Ollama, OpenAI, and the clean-room Codex bridge remain planned. |

The strongest relevant existing proof is narrower than Codex parity: a single
live root-planning turn, standalone semantic-router evaluations, and a
standalone generic scheduler tested with non-production workers. BirdCode must
not advertise these pieces as a functioning multi-agent coding runtime.

## Acceptance gap

Each criterion below is executable. “Parity pass” means retained evidence from
the product path satisfies the proof requirement; a unit type or mock alone is
insufficient unless the row explicitly concerns a mechanical contract.

| Gap ID | Measurable parity criterion | Required retained proof | Baseline state |
| --- | --- | --- | --- |
| `GAP-MA-001` | A root run semantically decomposes one repository task and launches at least two model-backed child executions with distinct actor, execution, attempt, context-manifest, and thread identities. | Daemon events, exact backend/model evidence, work orders, context digests, and child terminal records. | Not product-wired. |
| `GAP-MA-002` | Independent children overlap in wall-clock execution rather than running sequentially. | Monotonic dispatch/start/end evidence showing a non-zero overlap interval, plus configured concurrency ceilings. | Proven only with test workers in the standalone kernel. |
| `GAP-MA-003` | Root and children have isolated model contexts, and root context growth is bounded by typed summaries and artifact references instead of raw child transcripts. | Versioned context manifests, token ledgers, a noisy-output fixture, and assertions that the root receives only the declared handoff packet. | Designed; digest fields exist, runtime absent. |
| `GAP-MA-004` | Every child returns a bounded structured handoff with outcome, decision summary, evidence/artifact references, usage, risks, and next action; the root rejects malformed or unretained handoffs. | Positive and adversarial live-product cases, append-only mailbox/journal events, and hash verification. | Kernel contract exists; durable mailbox/product adapter absent. |
| `GAP-MA-005` | List/inspect, follow-up, asynchronous message, interrupt/cancel, wait, and close lifecycle operations behave consistently for running and terminal children. | End-to-end API/CLI/GUI tests, including a follow-up that changes later child output, interrupt cleanup evidence, terminal error propagation, and race tests. | Product child controls absent. |
| `GAP-MA-006` | A child cannot exceed its parent grant; read-only explorer/reviewer writes and unauthorized network/tool calls fail closed before effects. | Broker-issued grants, denied-effect receipts, path/network boundary tests, and parent/child capability containment checks through the daemon path. | Mechanical set checks only; broker absent. |
| `GAP-MA-007` | Two writing children operate from the same immutable source snapshot in distinct worktrees/overlays and cannot mutate the active user workspace or each other's candidate. | Lease attestations, filesystem probes, independent diffs, conflict fixture, cleanup receipts, and unchanged active-workspace hash. | Writes fail closed; provisioner/integration absent. |
| `GAP-MA-008` | Root/default, implementer, explorer, reviewer, tester, and integrator purposes can be selected through typed semantic planning without keyword, regexp, filename, or language-specific routing. | Multilingual/adversarial role-routing evaluation with raw structured outputs, obligation coverage, and bounded LLM repair/fail-closed cases. | Router/planner kernels are standalone; production role execution absent. |
| `GAP-MA-009` | Role profiles bind instructions, model profile, reasoning policy, permissions, tools, skills/MCP-equivalent capabilities, budgets, and context policy; omitted settings inherit only within explicit trusted bounds. | Versioned profile schema, resolved effective-profile artifacts, exact backend attestation, and privilege-escalation tests. | Partial standalone assignment/policy types; no live registry. |
| `GAP-MA-010` | Reviewer/auditor execution is read-only and independent of every producer it judges; integrator cannot independently certify its own output. | Lineage/deployment attestations, immutable blind packet, conflict rejection tests, and eligible independent verdict or human adjudication. | Standalone policy/validation contracts only. |
| `GAP-MA-011` | Tester/validator agents can build, start, operate, observe, and stop at least one real target, then feed failed evidence into bounded repair/replan and revalidation. | Process-tree disposition, commands, exit state, logs, assertions, artifacts, repair causality, and a passing post-repair run. | Typed validation foundation; no executing adapter. |
| `GAP-MA-012` | An explicit integration owner consumes all prerequisite handoffs, selects or merges candidates, resolves a seeded conflict, and runs post-integration gates before completion. | Integration manifest, three-way inputs, conflict decision, resulting snapshot hash, validation evidence, and separate review verdict. | Target only. |
| `GAP-MA-013` | Child state, token/tool budgets, provenance, active/done status, failures, and cancellations survive daemon restart and are truthfully visible in CLI and GUI. | Kill/restart/reconnect test over an active multi-agent run with event replay and no duplicate effects or false success. | Root PlanOnly durability exists; child durability absent. |
| `GAP-MA-014` | Fan-out, nesting, retries, time, tokens, tool calls, storage, and cleanup are mechanically capped under adversarial model output. | Boundary/fuzz cases plus live exhaustion runs showing deterministic rejection or cancellation without orphaned resources. | Many kernel caps exist; live agent/resource path absent. |
| `GAP-MA-015` | Equivalent tasks can run under the strongest configured Codex baseline and BirdCode with provider identity hidden from scorers. | Preregistered fixture, equal declared environment and budget policy, raw audit bundles, blind deterministic/semantic verdicts, confidence intervals, and failure accounting per [benchmarking.md](benchmarking.md). | Protocol designed; comparative run not executed. |
| `GAP-MA-016` | A bounded batch request fans out many homogeneous work items with stable per-item identity, a typed result schema, configurable concurrency/runtime, and an explicit error when a child terminates without reporting. | Live-product batch fixture with mixed success/failure/timeout rows, one retained terminal record per input item, deterministic combined export, and no lost or duplicate item. | Generic graph concepts exist; no product batch workflow. |

### Beyond-parity gates

The following are BirdCode product requirements, not claims that public Codex
lacks them. They are potential advantages only after proof:

1. Semantic decisions remain model-produced through versioned typed contracts;
   deterministic code never substitutes keyword, regexp, language, or filename
   heuristics for intent, relevance, decomposition, review, or completion.
2. Every plan, dispatch, message, handoff, effect, evidence item, integration,
   review, and terminal state is causally replayable and content-bound across
   restart.
3. Weaker or local models are compensated by measured model profiles,
   decomposition, specialists, candidates, criticism, repair, and escalation,
   not model-name assumptions.
4. Candidate production, integration, and authoritative semantic review use
   distinct eligible identities and declared independence policy.
5. “Better than Codex” is asserted only for a versioned benchmark slice whose
   retained blind results show a statistically and operationally defensible
   advantage in completed outcomes—not greater agent activity.

## Versioned observation log

Entries are append-only. A correction adds a new entry with `supersedes`; it
does not rewrite the earlier observation. A new Codex or BirdCode version must
add observations and update affected gap states before a parity statement.

| Observation ID | Date | Subject | Evidence | Result and limitation |
| --- | --- | --- | --- | --- |
| `O-2026-07-19-001` | 2026-07-19 | Official multi-agent baseline | Consolidated manual section 150–480 plus direct official Subagents-page fetch | Confirmed parallel specialized agents, agent threads, summarized return, orchestration, permission inheritance, built-in roles, custom profiles, and bounded thread/depth settings. No private implementation claim. |
| `O-2026-07-19-002` | 2026-07-19 | Manual freshness | Sandboxed helper attempt followed by its network-authorized retry | The sandboxed refresh failed on DNS. The authorized retry succeeded and returned a current manual snapshot used for the claims above. |
| `O-2026-07-19-003` | 2026-07-19 | Spawn and child identity | Parent-created `/root/codex_capability_ledger` task | Confirmed a separately addressable child with bounded instructions. Did not measure internal context storage or exact model identity. |
| `O-2026-07-19-004` | 2026-07-19 | Agent listing and terminal summary | Direct `list_agents` snapshot | Confirmed canonical paths, running/terminal states, and a concise completed-child result visible to the coordinator. Did not inspect list consistency under races. |
| `O-2026-07-19-005` | 2026-07-19 | Shared checkout | Session execution contract and common working directory | Confirmed shared filesystem/worktree scope. This is not isolated-writer evidence and makes collision avoidance an orchestration responsibility in this session. |
| `O-2026-07-19-006` | 2026-07-19 | Lifecycle controls | Surfaced `followup_task`, `send_message`, `interrupt_agent`, and `wait_agent` contracts | The parent exercised follow-up reuse, asynchronous messaging, and bounded waiting. Interruption remained unexercised. None of these observations is BirdCode parity evidence. |
| `O-2026-07-19-007` | 2026-07-19 | BirdCode baseline | Commit `2bee9944678dfc4f3e08aa6319e5baba3a6c9112` and linked repository status documents | Confirmed product-wired durable root planning and standalone router/planner/scheduler/validation foundations; confirmed absence of a product-wired model child runtime, tools, mailboxes, worktree integration, and live reviewer. |
| `O-2026-07-19-008` | 2026-07-19 | Structured batch fan-out | Current official Subagents page and current session tool inventory | Confirmed the documented experimental CSV batch behavior. No corresponding collaboration tool was surfaced or exercised in this session; BirdCode parity remains `GAP-MA-016`. |
| `O-2026-07-19-009` | 2026-07-19 | Child-authored decomposition | `/root/kernel_recovery_hardening` spawning `/root/kernel_recovery_hardening/recovery_transition_review` | Confirmed one child refined its own work plan and delegated a bounded separate review while continuing implementation. This session-specific observation does not prove durable nesting or any BirdCode behavior. |
| `O-2026-07-19-010` | 2026-07-19 | Evidence-bearing steering | CLI `E0282` bin-test result followed by a live message to `/root/product_surface_validation` | Confirmed a running child can receive a concrete new finding within its existing scope. Delivery was observed at the interface; exactly-once processing and durable mailbox semantics were not measured. |
| `O-2026-07-19-011` | 2026-07-19 | Sol/Ultra comparison-agent request | Three explicit spawn invocations requesting `gpt-5.6-sol` with `ultra` reasoning | Confirmed the orchestration surface accepted the requested specialist profiles. Effective runtime identity was not exposed by list/result metadata, so no model-attestation claim is made. |
| `O-2026-07-19-012` | 2026-07-19 | Documentation truth audit | Read-only `/root/docs_truth_audit` result | Compared active README, architecture, policy, prompt, ledger, and screenshot claims with protocol-v5 code and assets; identified stale screenshots and overstrong live-review/attestation wording. The root corrected the text; image replacement remains a pre-merge gate. |

## Update checklist

When Codex behavior or BirdCode implementation changes:

1. pin the observation date, Codex surface/version where visible, BirdCode
   commit, source URLs, and retained artifact hashes;
2. label each new statement `DOC`, `OBS`, `BC`, or `GAP`;
3. distinguish an exposed interface from an exercised behavior and from a
   repeatable acceptance test;
4. record role purpose, effective context, permissions, model/reasoning profile,
   and tool surface without inferring undisclosed internals;
5. add or supersede observation-log entries rather than silently editing
   history;
6. update a gap to passed only from retained product-path evidence; and
7. keep parity and superiority claims scoped to the exact versioned behaviors
   or benchmark fixtures that were actually measured.
