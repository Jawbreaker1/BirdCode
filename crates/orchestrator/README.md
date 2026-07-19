# BirdCode orchestrator

This crate contains provider-neutral orchestration primitives. It currently
has two standalone execution kernels:

- the semantic task-router executor, including one bounded evidence-only
  repair; and
- the mechanical actor-graph validator and concurrent executor.

Neither kernel is wired to the daemon yet.

## Actor-graph trust boundary

`ActorGraph` is a semantic planner proposal. It may describe objectives,
acceptance criteria, dependencies, candidate groups, roles, assignments, and
requested grants, but it is not authority.

`ActorGraphPolicy` is supplied independently by the runtime, permission broker,
workspace manager, model-profile registry, and budget controller. It contains
the immutable source snapshot, root capability set, broker-attested workspace
leases, attested model lineages, concurrency and aggregate budget ceilings,
and telemetry policy. A graph can execute only after
`ActorGraph::validate_against` proves that every proposal fits this envelope.

The executor never reads user prose or source code. It uses only typed graph
fields and enforces:

- a bounded, acyclic dependency graph with stable priority/ID dispatch order;
- fail-fast structural ceilings before sorting, graph traversal, or hashing;
- full-budget reservation across every authorized retry before dispatch;
- exact capability-set containment and policy-attested workspace leases;
- read-only workspace execution only; proposed writes fail closed until an
  atomic cross-run lease broker exists;
- independent candidate peers with equal objectives, criteria, prerequisites,
  context, authority, access, and budgets, distinct leases, and no direct or
  transitive peer dependencies;
- reviewers on read-only workspaces whose policy-attested independence domain
  differs from every reviewed producer;
- journal acknowledgement before a worker is called;
- UUID v7 actor, execution, attempt, event, and handoff identities;
- content-bound graph, policy, work-order, permission, model, context,
  workspace, and budget dispatch attestations;
- dependency-handoff, per-run root/terminal, and terminal-frontier references;
- bounded deadlines and cleanup windows, typed no-effect-only retries, and
  fail-closed usage and result validation; and
- failure propagation to every transitively blocked work order while unrelated
  siblings continue.

`CleanupUnproven` is different from an ordinary worker failure: it activates a
graph-wide fail-stop. No new work is dispatched, already-started scheduler
futures are drained through their own deadline/cleanup paths, a
`GraphSuspended` event is retained, and no normal `GraphFinished` is emitted.

Malformed worker results retain bounded execution/effect receipts when valid,
usage, and a streaming payload digest alongside every contract violation. They
cannot erase cost or effect-reconciliation evidence by failing another field.

The production `SchedulerJournal` implementation must durably verify graph,
policy, workspace, model, effect, evidence, and artifact receipts before it
acknowledges an event. The included in-memory journal exists for tests only.

## Deliberate non-claims

This crate does not yet provide a model-backed `AgentWorker`, daemon supervisor,
SQLite journal adapter, mailbox, cancellation generation, crash recovery,
workspace provisioning, tool broker, process containment, integration, or GUI
and CLI run flow.

`AgentWorker` is a trusted adapter boundary. Before a worker can execute tools
or processes, its implementation must enforce request ceilings before effects,
verify actual backend identity, index every owned resource by attempt ID, and
implement the bounded `cancel_and_cleanup` channel. A timeout without a valid
cleanup receipt becomes `CleanupUnproven`, never a confirmed deadline cleanup.
The caller must quarantine the attempt's external resource reservation until
reconciliation. The in-memory worker tests do not prove that an arbitrary
detached process stopped. Accordingly, this standalone kernel is not
advertised as the parallel agent runtime capability.

Daemon/transport adapters must cap encoded graph bytes before deserialization;
the kernel then applies its structural hard caps before doing expensive work.

Run its focused gate with:

```sh
cargo test -p birdcode-orchestrator
cargo clippy -p birdcode-orchestrator --all-targets -- -D warnings
```
