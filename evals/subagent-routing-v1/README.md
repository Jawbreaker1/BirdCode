# Subagent routing evaluation v1

This suite evaluates **when** an agentic coding harness should delegate, which
functional purpose each child should receive, and which execution shape is
appropriate. It is a design fixture for the next BirdCode contract. Its
presence does not mean the current product can execute these cases.

The suite deliberately evaluates structured semantic decisions rather than
surface words in the prompt. Implementations must not use keyword lists,
regular expressions, filenames, extensions, locale/language-specific branches,
surface-form matching, or model names to select roles or trigger delegation.
The model is expected to understand natural language semantically.

## What is evaluated

`catalog.v1.json` contains 13 self-contained cases validated by:

- `input-envelope.schema.v1.json` for trust-labeled source sections;
- `normalized-output.schema.v1.json` for the five planner branches and the
  `Delegate`-only spawn payload, exact causal binding, activation source,
  typed decision reasons, requested constraints, and obligation propagation;
  and
- `catalog.schema.v1.json` for typed expected cardinality, role, graph,
  authority, isolation, independence, handoff, and evidence constraints.

The cases contain:

- trusted user, policy, repository, runtime, and model-profile inputs;
- the acceptable top-level decision;
- acceptable functional role families and execution shapes;
- child-count, dependency, authority, isolation, independence, and evidence
  constraints;
- advisory examples of unsafe or heuristic routing that are never parsed; and
- the observable fields to retain from a clean-room Codex comparison.

Expected values are typed structural constraints, not exact generated prose.
A valid
planner may choose different objectives or identifiers while still satisfying
the same protected obligations, authority ceiling, dependency graph, handoff,
and review policy.

`requested_constraints` are requirements proposed for deterministic admission
or later execution; they are not proof that the requirement has already been
satisfied. Actual overlap, fresh builds, isolation, secret containment, and
other runtime facts require separately retained observations or artifacts.

## Evidence boundary

The catalog has status `design_fixture_not_product_evidence`.

- A BirdCode pass requires retained structured model output, local validation,
  admission evidence, and the actual runtime result when the case calls for
  execution.
- A Codex observation records only visible behavior. A task name does not prove
  a built-in agent type, `running` does not prove simultaneous inference, and a
  requested model or read-only instruction is not effective attestation.
- Manual-control and provider baselines use the same normalized outcome shape.
- Provider identity must be hidden from semantic scorers when a case is used in
  comparative evaluation.

Raw prompts, outputs, timestamps, status observations, commands, logs,
artifacts, hashes, and missing or inconclusive evidence are retained outside
the normalized verdict.

## Evaluation rules

For every case:

1. Compile the exact trusted and untrusted inputs into the versioned semantic
   spawn-decision prompt.
2. Validate the returned schema without interpreting rationale text.
3. Require the result's complete `causal_binding` to equal the trusted input,
   including parent attempt, accepted planner output, snapshots, policies,
   registries, and model-profile digest.
4. Validate the catalog and normalized result against their versioned schemas,
   then compare activation source, decision-reason codes, typed fields, and
   requested constraints with `expected`. Advisory failure examples are never
   machine-scored.
5. Validate authority containment, dependency DAG, budgets, profile
   eligibility, context policy, isolation, and independence mechanically.
6. If execution is in scope, validate actual overlap, handoffs, cleanup, and
   terminal state from retained evidence.
7. Mark unavailable or ambiguous evidence as such; never convert it to a pass.

The multilingual group is metamorphic: Swedish, English, Japanese, and Arabic
variants must produce equivalent normalized structure even though identifiers
and prose may differ. The injection case must treat repository content as data.
The weak-model case uses measured capabilities; no model slug appears in its
expected routing logic.

## Relationship to product contracts

The intended semantic output uses BirdCode's existing five-value planner
directive. A `Delegate` directive carries the conceptual `SpawnProposalV1`
described in
[the taxonomy and spawn policy](../../docs/subagent-taxonomy-and-spawn-policy.md).
The detailed functional roles and tool requirements live in
[the agent role registry](../../docs/agent-roles-and-tools.md). Clean-room Codex
claims and unknowns remain in
[the capability ledger](../../docs/clean-room-codex-capability-ledger.md).

## Local validation

The Protocol integration tests compile every schema, validate the catalog,
construct and score one concrete typed witness for every case, verify exact
role/child bounds, graph feasibility and acyclicity, child and parallel-set
references, evidence and obligation closure, and exercise negative cases for
wrong branches, stale attempts, unknown graph members, missing adaptations or
handoff requirements, and invented completion claims:

```sh
cargo test -p birdcode-protocol --test subagent_routing_eval
```
