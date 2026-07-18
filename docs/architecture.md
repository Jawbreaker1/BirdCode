# Target architecture

This document describes the intended system, not a claim that every component
already exists. The current executable slice is listed in the repository
README and advertised mechanically through negotiated runtime capabilities.

## Product shape

BirdCode is being built as a local-first coding-agent system. The desktop client
is the main experience. A CLI will expose a subset of the same capabilities.
Both communicate with a durable local runtime through a versioned protocol.

```text
React/Tauri desktop ─┐
                    ├── versioned local protocol ── Rust daemon
Rust CLI ───────────┘                               ├── agent runtime
                                                    ├── context compiler
                                                    ├── event and artifact store
                                                    ├── tool and permission broker
                                                    └── backend adapters
```

The initial build and distribution target is `aarch64-apple-darwin`. Core
crates must compile independently from the desktop shell. Operating-system
behavior belongs behind platform adapters in the runtime.

## Backend taxonomy

A model backend gives BirdCode control over the agent loop. Initial examples
are Ollama, LM Studio, and the OpenAI API. An agent backend already owns an
inner loop. The local Codex bridge is an agent backend and uses Codex-managed
authentication.

The distinction is represented in capabilities rather than hidden behind a
false least-common-denominator interface.

## Durable state

The append-only event log is authoritative. Large prompts, outputs, terminal
logs, patches, and other artifacts are content-addressed and referenced from
events. Materialized session state and memories are rebuildable projections.
Sequential event reads are bounded pages; callers resume from the last sequence
instead of materializing an arbitrarily long session in memory.

Current run state is maintained atomically as an indexed projection whenever an
authoritative event is appended. Historical schema upgrades are persisted as
small checkpointed phases, so a crash or startup deadline resumes from durable
progress rather than replaying the full database. The online health probe is a
bounded closed-world schema/database/artifact canary, not an O(N) forensic data
audit; affected reads still fail closed if stored state is inconsistent.

The runtime can replay recorded state exactly. Re-running a nondeterministic
model is not expected to reproduce identical tokens.

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

## Subagents

Subagents are isolated actors with their own causal event branches, mailboxes,
budgets, permissions, and delivery contracts. The LLM decides semantically
when and how to delegate through structured actions. The scheduler enforces
mechanical limits and permissions.

Writing agents use isolated worktrees or overlays. Parents receive structured
handoffs containing evidence, artifacts, tests, risks, and unresolved work,
not an unbounded copy of the child transcript.

## Local transport

The transport must support ordered streaming, cancellation, reconnection, and
protocol-version negotiation. Its public types live in `crates/protocol`.
Transport-specific code must not leak into runtime domain types.

Protocol v2 encodes workspace paths with a separately versioned wire value:
Unix paths carry their exact bytes and Windows paths carry exact UTF-16 code
units. This avoids forcing either representation through Unicode text, so
non-UTF-8 POSIX names and unpaired Windows surrogates survive canonical JSON
round trips. A foreign-family path remains valid protocol data but must not be
converted to a native `PathBuf` on an incompatible host.

Mutating requests require a client-stable idempotency key whose result is
recorded atomically with its state change. A lost response may be replayed with
the same key, but an unknown mutation is never retried under a new key. The
foundation protocol currently correlates request IDs but does not yet implement
this durable operation ledger, so automatic reconnect is limited to read-only
health probes.

## Platform strategy

- Phase 1: macOS on Apple Silicon, distributed outside the Mac App Store.
- Phase 2: Windows, including process-tree and PTY adapters.
- Phase 3: Linux, including WebKit and distribution-matrix validation.

Platform support means verified builds and behavior, not merely successful
cross-compilation.
