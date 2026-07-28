# Code health and integration policy

This policy is normative for every BirdCode change. Architecture, code
structure, repository hygiene, and integration safety are acceptance criteria
alongside functional correctness.

## Module boundaries

A module owns one cohesive responsibility and exposes the narrowest practical
surface. Names describe that responsibility. `lib.rs`, `main.rs`, `mod.rs`,
application roots, and public facades should primarily compose modules, define
exports, and wire dependencies.

The following are not acceptable ways to satisfy a size check:

- catch-all `utils`, `misc`, or `helpers` dumping grounds;
- numbered `part1`, `part2`, or similarly arbitrary fragments;
- denser formatting, minification, or removal of tests and documentation;
- moving coupled code without defining an explicit dependency boundary; or
- widening visibility only to make a mechanical move compile.

An extraction should normally move a contiguous responsibility of roughly
150–1,200 lines. It must preserve or reduce visibility and dependency surface.
Behavior-preserving movement and behavioral changes belong in separate commits.

New crates, reversed dependency direction, public protocols, storage schemas,
permission or trust boundaries, and platform adapters require a simultaneous
architecture-document update.

## Size policy

| Authored source | Healthy target | Hard limit for a new file |
| --- | ---: | ---: |
| Rust | 800 lines | 1,500 lines |
| TypeScript, TSX, JavaScript, JSX, MJS/CJS/MTS/CTS | 500 lines | 800 lines |
| Python | 500 lines | 800 lines |
| Shell | 200 lines | 400 lines |
| Swift, Kotlin, Go | 800 lines | 1,200 lines |
| CSS | 500 lines | 800 lines |
| YAML | 300 lines | 500 lines |

The authoritative hard limits and temporary legacy debt ledger live in
`config/repository-health.v1.json`.

Legacy debt is a ratchet, not permission:

- a debt file may never grow;
- its exact ceiling must be lowered in the same change whenever it shrinks;
- a ceiling disappears as soon as the file reaches the normal hard limit;
- new debt entries, raised ceilings, raised limits, and removed language limits
  are rejected against the Git baseline; and
- no new feature behavior enters a debt file before the affected responsibility
  is extracted in a separate preceding commit, except for an urgent correctness
  or security fix.

Every newly authored source language must receive an explicit hard limit in the
same commit. Line limits are not a license for dense or minified source.

## Bounded milestones

Before a writable step begins, record:

1. one behavior slice or one behavior-preserving refactor;
2. its owner and exact writable paths;
3. expected production-file and semantic-diff scope; and
4. the formatter, compilation, tests, and review that prove completion.

A normal milestone:

- touches no more than ten production paths;
- changes no more than 2,500 semantic added-plus-deleted production lines;
- excludes generated outputs, lockfiles, and independently verified unchanged
  moves from that semantic-line budget; and
- produces one cohesive, reviewable commit.

Reassess after 60 minutes without a testable and reviewable increment. Stop and
split or re-scope at 120 minutes, at twice the estimated scope, or when the
path/patch bounds are crossed. Continuing a single autonomous milestone beyond
three hours requires an explicit user decision. Long validation may run longer
after implementation has stopped, provided its state is reported.

## Parallel ownership

One path has one writer at a time. Writable agents declare disjoint path
ownership and use isolated worktrees. Read-only reconnaissance and independent
review may run concurrently.

One integrator owns shared facades, manifests, schemas, generated outputs,
lockfiles, the Git index, commits, and integration decisions. A safety
checkpoint is created and pushed before broad parallel work. Recovery/WIP
checkpoints remain clearly labeled and are never integrated as ordinary product
commits.

## Commit and integration cadence

- Begin and end each writable milestone with a clean worktree.
- Preserve and never stage pre-existing user changes.
- Run `git diff --check`, the applicable formatter, `npm run repo:health`,
  targeted static checks/compilation, and the tests proving the milestone.
- Use broader integration tests when a component boundary or cross-component
  behavior changes.
- Commit only a complete, green milestone—not individual imports, formatting,
  files, or intermediate fixes.
- Push immediately after the validated commit and before the next writable
  milestone. At most one validated milestone may ever remain unpushed.
- Refresh or integrate a topic branch before one working day, five validated
  commits, or 50 changed production paths relative to its integration target,
  whichever happens first.
- Never rewrite a pushed shared branch without coordination.

Mechanical refactors receive an independent semantic-diff review in addition
to deterministic formatting, compilation, and tests. LLM review may classify
whether a change is genuinely behavior-preserving, but builds and tests remain
the primary evidence.

## Enforcement

Run the portable repository gate:

```sh
npm run verify:repository
```

`repo:health` examines tracked and nonignored untracked authored sources,
rejects a repository-local Cargo `target/`, enforces exact legacy ceilings, and
compares policy configuration with committed `HEAD`. In CI it compares with the
push or pull-request integration baseline.

The GitHub repository-health workflow runs the policy and cache tests on every
push and pull request. The workflow must be configured as a required check on
the protected integration branch; the checked-in workflow cannot itself grant
branch protection.
