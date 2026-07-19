<p align="center">
  <img src="apps/desktop/app-icon.svg" alt="BirdCode" width="112" height="112">
</p>

<h1 align="center">BirdCode</h1>

<p align="center"><strong>Own the agent. Keep the history. Choose the model.</strong></p>

<p align="center">
  A local-first agentic coding harness where language models make semantic<br>
  decisions and deterministic Rust code enforces boundaries.
</p>

<p align="center"><code>macOS ARM64 first</code> · <code>Rust + Tauri</code> · <code>LM Studio</code> · <code>pre-alpha</code> · <code>UNLICENSED</code></p>

BirdCode is being built for developers who want the power of a modern coding
agent without surrendering the runtime, history, context strategy, or backend
choice to an opaque service. The product direction is a complete desktop-first
application with a shared CLI, durable long-running sessions, dynamic
subagents, and support for both local models and external agent backends.

The project is currently at the **foundation milestone**. Its local daemon,
protocol, persistence layer, desktop health shell, CLI probes, typed prompt
compiler, semantic router, standalone router executor, and LM Studio adapter
are real and testable. The agent execution loop is not wired yet, so BirdCode
is not currently a usable replacement for Codex or another production coding
agent.

## Why BirdCode

### Semantics belong to the model

User intent, relevance, delegation, and conflict resolution are semantic
problems. BirdCode uses versioned LLM prompts with typed inputs and outputs for
those decisions instead of language-specific keyword lists, regular
expressions, or brittle string parsing. Multilingual requests are a first-class
requirement.

Deterministic code still owns everything mechanical: schemas, permissions,
budgets, state transitions, persistence, hashes, ordering, and protocol
compatibility.

### Durable by construction

The authoritative session history is an append-only SQLite event log. Large
values live as content-addressed artifacts, while event reads are bounded and
resumable. Schema upgrades use durable checkpoints, and current run state is an
atomically maintained indexed projection rather than a scan of an arbitrarily
long history. The planned context compiler and compaction system will optimize
the active prompt without deleting the raw history or its provenance.

### Backend freedom without a false common denominator

BirdCode distinguishes between:

- **model backends**, where BirdCode owns the agent loop; and
- **agent backends**, which already own an inner coding loop.

The provider-neutral model contract and LM Studio adapter exist today. Ollama,
the OpenAI API, and a local Codex bridge are planned. The Codex bridge will use
Codex-managed authentication from the user's installed client; it will not
scrape credentials or copy private implementation code.

### Subagents as a core primitive

The target architecture treats subagents as isolated actors with causal event
branches, explicit budgets, permissions, mailboxes, and structured handoffs.
An LLM decides when delegation is useful; a deterministic scheduler will
enforce concurrency, access, and resource limits. This scheduler and the actual
subagent execution path are still roadmap work.

## Status

BirdCode is pre-alpha and currently optimized and verified first on macOS with
Apple Silicon.

| Area | Status | What works now |
| --- | --- | --- |
| Tauri 2 + React desktop | Implemented foundation | Starts the real daemon sidecar, negotiates the protocol, polls runtime health, and never fabricates model activity |
| Rust CLI | Implemented subset | `doctor` and a durable create/reload session smoke path through the same daemon client |
| Local daemon and client | Implemented foundation | Typed, bounded JSON-lines over stdio, exact protocol negotiation, request deadlines, and conservative reconnect behavior |
| Durable store | Implemented foundation | Append-only events, bounded paging, checkpointed upgrades, O(1) run-state projection, closed-world schema health, and verified content-addressed artifacts |
| Semantic task router | Implemented standalone | LLM-classified action, access, and delegation strategy with typed collect-all validation and no heuristic fallback |
| Standalone router executor | Implemented standalone | First-pass routing plus at most one typed, patch-only evidence repair; fake-backend tested and not daemon-wired |
| LM Studio backend | Implemented standalone | Read-only discovery plus strict structured inference with bounded HTTP behavior and versioned, retained eval reports |
| Agent execution loop | **Not wired** | Run specifications can be persisted, but no backend is invoked by the daemon |
| Context compilation and compaction | Designed | Architecture and invariants are documented; runtime implementation remains |
| Tools and permission broker | Designed | No shell or filesystem tool execution is exposed to an agent yet |
| Dynamic subagents | Designed | Typed route proposals exist; scheduler, worktree isolation, and handoffs remain |
| Ollama and OpenAI adapters | Planned | Provider contract exists; adapters do not |
| Local Codex bridge | Planned | Clean-room adapter direction is documented; no product integration exists yet |
| Windows and Linux | Planned | Core boundaries are portable, but builds and platform behavior are not yet verified |

The semantic router, its portable executor, and the LM Studio backend currently
run through standalone tests and evaluation tools. The executor is
fake-backend validated; it is not connected to the live LM Studio eval and none
of these components yet appears as a daemon capability in the GUI or CLI.

## Architecture

The solid path below exists today. Dashed connections show the next integration
layers rather than current runtime behavior.

```mermaid
flowchart LR
    Desktop["Tauri / React desktop"] --> Client["Typed Rust client"]
    CLI["Rust CLI"] --> Client
    Client -->|"bounded JSONL over stdio"| Daemon["Local Rust daemon"]
    Daemon --> Runtime["Portable runtime"]
    Runtime --> Store["SQLite event log + artifact store"]

    Prompting["Typed prompt compiler<br/>semantic task router"] -->|"standalone live eval"| LMStudio["LM Studio adapter"]
    Prompting --> RouterExecutor["Portable router executor<br/>one evidence-only repair"]
    RouterExecutor -->|"provider-neutral; fake-backend validated"| ModelBackend["Model backend contract"]

    Runtime -.->|"next: real run execution"| AgentLoop["Agent loop"]
    AgentLoop -.-> Prompting
    AgentLoop -.-> LMStudio
    AgentLoop -.-> Context["Context compiler + compaction"]
    AgentLoop -.-> Tools["Tool + permission broker"]
    AgentLoop -.-> Scheduler["Subagent scheduler"]
    AgentLoop -.-> Providers["Ollama · OpenAI · Codex bridge"]
```

The canonical protocol and core runtime are independent of Tauri, operating
system APIs, and provider-specific payloads. Platform behavior belongs behind
adapters so Windows and Linux can be added without replacing the core.

More detail is available in [the target architecture](docs/architecture.md)
and [the validation policy](docs/validation.md).

## Quick start on Apple Silicon

The verified development toolchain is Rust 1.92, pinned by
`rust-toolchain.toml`, and Node.js 22.16.0 (minimum 22.12.0). Native desktop
development also requires the normal macOS/Xcode command-line build tools.

From the repository root:

```sh
npm ci
cargo test --workspace
npm test
npm run typecheck
npm run dev
```

`npm run dev` prepares the host-native daemon sidecar and opens the Tauri
desktop application. The UI reports actual runtime state; disabled agent
controls remain disabled until a backend execution path really exists.

To build and exercise the current CLI subset:

```sh
cargo build --workspace
target/debug/birdcode doctor
target/debug/birdcode session-smoke
```

`session-smoke` creates a multilingual test session, reloads it through the
daemon, and verifies that the durable value is unchanged.

Development path overrides:

- `BIRDCODE_DAEMON` selects a daemon executable.
- `BIRDCODE_DATA_DIR` selects the local state directory.

## LM Studio discovery and live evaluation

The LM Studio tools default to `http://127.0.0.1:1234/`. Discovery is read-only
and never loads, unloads, or downloads a model.

Inspect the model catalog reported by an already-running instance:

```sh
cargo run -p birdcode-backends --example lmstudio_probe
```

Run the small strict-JSON connectivity prompt against an exact model ID
returned by discovery:

```sh
cargo run -p birdcode-backends --example lmstudio_probe -- --infer <exact-model-id>
```

Run the catalog-driven semantic-router evaluation against exactly one already
loaded language model:

```sh
cargo run -p birdcode-prompting --example lmstudio_router_eval -- \
  --infer-loaded \
  --output evals/reports/local-router-eval.json \
  --source-revision "REVISION" \
  --lm-studio-version "VERSION" \
  --lm-studio-version-source "VERSION_SOURCE"
```

Use the exact Git commit or immutable source-snapshot identifier for
`REVISION`. Copy `VERSION` from LM Studio's application UI and describe that
location precisely in `VERSION_SOURCE` (for example, `LM Studio About dialog`);
the discovery API does not report the application version itself.

The current nine-case catalog covers multilingual delegation, clarification
instead of unsafe guessing, repository prompt injection, direct informational
answers, irrelevant repository context that must not be cited, zero-delegation
read-only work, an English direct-change request that requires workspace write
access, intent-bearing Japanese clarification, and intent-bearing Arabic
delegation. Expectations include required and forbidden evidence sections and
bounded clarification/subtask counts, not only route labels. A single case can
be selected explicitly by adding:

```sh
--case semantic-router.arabic-delegation
```

The v4 evidence rubric is causal rather than cite-all. Repository context is
required when it supplies otherwise unnamed delegated targets or when rejecting
a repository control attempt is itself a safety decision. Redundant repository
context is forbidden for the zero-delegation and direct English-change cases;
the Arabic delegation case is user-only. Expected subtask counts are
evaluator-only scoring metadata, separate from the prompted runtime delegation
limit. That limit defaults to four and is zero only in the versioned
zero-delegation fixture.

The runner reserves and syncs a new report path before its first HTTP request.
It then finalizes that reservation as `passed` or `failed`, including discovery,
inference, validation, and semantic-mismatch failures, before returning a
nonzero exit status. The report records its source revision, timestamp,
runner/platform identity, LM Studio version and evidence source, the selected
model's bounded identity/quantization evidence, SHA-256 digests of the complete
discovery response bodies, credential-free endpoints, raw inference evidence,
prompt/case digests, and validated or rejected semantic output. The runner
also records the runtime delegation limit and prints the exact final report
SHA-256. Case identifiers and expectations remain evaluator/report metadata
and are never compiled into model input; model-visible data provenance uses
only opaque, reproducible `eval-fixture:<case SHA-256>:<ordinal>` identifiers.
Existing reports are never overwritten, and full LM Studio model inventories,
local model paths, and unrelated model configuration are not copied into
reports.

Optional configuration:

- `BIRDCODE_LMSTUDIO_URL` changes the server URL.
- `LM_STUDIO_API_TOKEN` supplies a bearer token without placing it in command
  history.

LM Studio URLs containing user information, query strings, fragments, or a
non-root base path are rejected rather than normalized into evidence.

The eval is deliberately opt-in. It fails rather than choosing arbitrarily if
LM Studio reports zero or multiple loaded language models.

## Prompt contracts, not prompt strings

Application prompts are repository data, never instructions to the developer
or coding agent maintaining BirdCode. Every production prompt has a stable ID,
semantic version, declared role, typed invocation schema, generation schema,
authoritative output schema, and evaluation coverage.

The implemented task router returns three independent axes:

- action: `clarify`, `answer`, `inspect`, or `change`;
- strategy: `direct` or `delegate`; and
- required access: `none`, `read_only`, or `workspace_write`.

Repository text and tool output remain separately labelled data with explicit
trust and provenance. Provider-constrained JSON is accepted only after full
local schema validation and cross-field checks against the original runtime
invocation. Router invariants are returned as a typed collect-all report, so a
duplicate citation cannot hide a simultaneous non-repairable defect.

The standalone router executor permits exactly one narrow LLM repair only when
*every* local violation is a duplicate evidence section. The repair model sees
only duplicate section names and their model-generated bases, returns a minimal
replacement patch, and cannot express action, strategy, access, confidence,
questions, or subtasks. BirdCode preserves unique evidence mechanically and
revalidates the complete original router contract after applying the patch. A
caller-provided attempt journal must acknowledge the initial result before any
repair and the repair result before acceptance. The bundled journal is
explicitly in-memory, not a claim of durable persistence. See
[the prompt format](prompts/README.md).

## Security principles

Security work is ongoing and BirdCode has not received an external audit. The
foundation already enforces several important boundaries:

- the React renderer has only Tauri's minimal core capability and receives no
  raw shell, filesystem, credential, or unrestricted IPC access;
- daemon frames, backend request and response bodies, output token counts,
  event payloads, artifacts, and request times are bounded;
- plain HTTP backend URLs are accepted only for loopback hosts; remote servers
  must use HTTPS;
- the LM Studio client disables proxy use and redirect following so sensitive
  prompts and authorization headers stay on the configured origin;
- API tokens use a redacting type and are never included in debug output;
- BirdCode-created state directories use mode `0700` and state files use
  `0600` on Unix; existing roots are preserved only when they are not writable
  by group/others, symlink-sensitive paths are rejected, and artifact hashes
  are verified when content is read;
- schema upgrades are bounded, crash-resumable phases; periodic health checks
  validate the closed-world schema and perform real database and artifact-root
  write/read/fsync/hash canaries without scanning an unbounded event history;
- normalized backend events cannot be committed without a bounded,
  content-addressed, hash-verified raw backend artifact;
- standalone router output is schema- and invariant-validated before
  acceptance; no semantic output is currently connected to tools, and future
  execution paths must additionally pass deterministic permission, budget,
  and state-transition checks; and
- Codex compatibility work follows a clean-room boundary based on public
  documentation and observable behavior.

## Development and verification

Run the full deterministic foundation gate from the repository root:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm test
npm run typecheck
npm run build
```

Create a native bundle for the current host with:

```sh
npm run tauri:build --workspace @birdcode/desktop
```

The current Apple Silicon bundle targets macOS 11 or newer and is ad-hoc
signed by Tauri so the nested daemon and application bundle can be verified
locally. It is not Developer ID signed or notarized; those are separate
distribution gates for a public release.

Immutable development snapshots are independently reviewed with the strongest
available Codex Sol/Ultra configuration. Each retained review records its
source commit, acceptance gate, findings, and limitations; it is a comparison
signal, not a security certification. An LLM is never the sole judge of its
own output, so deterministic checks and focused independent review remain
authoritative wherever possible.

## Repository map

```text
apps/desktop       Tauri 2 + React desktop shell and daemon sidecar manager
apps/cli           Deliberately small CLI over the shared daemon protocol
apps/daemon        Local JSON-lines server
crates/protocol    Provider-, UI-, and OS-independent wire/domain types
crates/client      Bounded daemon process and request client
crates/runtime     Portable mechanical runtime state transitions
crates/store       SQLite event log and content-addressed artifacts
crates/prompting   Versioned prompt registry, compiler, and semantic router
crates/backends    Provider-neutral model contract and LM Studio adapter
crates/orchestrator Provider-neutral standalone routing and typed repair
prompts            Application prompt manifests and schemas
evals              Versioned semantic evaluation cases
docs               Target architecture and validation policy
```

## License status

BirdCode is currently [`UNLICENSED`](LICENSE) while the product and
contribution model are being established. The Rust packages are explicitly
non-publishable, and source availability does not grant reuse or redistribution
rights. Supporting open-source models is a backend goal; it is separate from
the application's eventual license decision.

## Roadmap

1. Wire the semantic router and LM Studio adapter into the daemon for one real,
   observable, read-only run path.
2. Add a durable idempotency ledger, streaming, cancellation, and resumable run
   orchestration.
3. Build the tool and permission broker with repository snapshots and isolated
   write surfaces.
4. Implement dynamic subagents with budgets, causal branches, mailboxes,
   worktree/overlay isolation, and structured handoffs.
5. Implement action-specific context compilation, semantic retrieval, and
   versioned compaction checkpoints without destructive history loss.
6. Add Ollama, OpenAI, and the clean-room local Codex bridge, then comparable
   multi-backend evaluation.
7. Complete the desktop run experience and verify packaging first for macOS
   ARM64, then Windows and Linux through explicit platform adapters.

BirdCode's ambition is high: a complete, inspectable coding-agent system that
can improve with better models without becoming dependent on one provider. The
repository is intentionally honest about the distance between that goal and
the current milestone—and builds the durable boundaries before the autonomous
loop depends on them.
