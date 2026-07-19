# BirdCode Execution & Validation Plane contracts

This crate is the provider-neutral, serializable contract layer for executing
and judging application candidates. It deliberately contains no process,
browser, simulator, device, VM, or desktop adapter yet.

The foundation guarantees:

- explicit typed targets; an adapter kind is selected only from the target
  enum, never from filenames, free text, keywords, regular expressions, or
  detected programming languages;
- argv-based commands with explicit working directory, environment, timeout,
  capture, artifact ceilings, and caller-/adapter-declared resolved byte counts
  even when argv/environment/stdin values are secret-referenced or redacted;
  those counts are mechanically bounded here but are not broker-attested yet;
- lossless Unix-byte and Windows-UTF-16 command paths/arguments, including
  non-UTF-8 Unix paths and unpaired Windows surrogates;
- append-only, hash-chained provenance with UUID v7 run and attempt identities;
- an explicit actor category plus declared provider/model selector,
  environment/toolchain, command, exit, evidence, and SHA-256 artifact metadata;
- a fixed 12-phase lifecycle from prepare/build through cleanup/package and a
  frozen typed phase/check policy whose plan and policy digests are committed;
- deterministic collect-all validation where screenshots and video can
  support or reject a result but can never provide sufficient acceptance
  evidence without a passing primary mechanical/state observation;
- a consuming seal that binds terminal chain hash, immutable run context,
  validation plan/policy, and collect-all report before review;
- random evaluator-local run/candidate/attempt/check/artifact identities and a
  provider-blind projection that excludes producer attribution, commands,
  concrete target details, timings, source hashes/sizes/media types, storage
  locations, and original identities. The evaluator input has its own digest
  for verdict binding; the source-to-blind mapping remains local.

`AdapterCatalog::default()` is empty. The target variants describe required
future capabilities; they do not claim that Playwright or any platform adapter
is installed. An integration layer must register a real adapter explicitly.

Web/API URLs containing userinfo or passwords are rejected at construction and
deserialization. Query data is intentionally not guessed or rewritten; secrets
in query parameters must later be supplied through an explicit secret broker
and must not enter retained target provenance.

Windows environment-name duplicate protection currently covers exact names and
ASCII case aliases. A Windows adapter must additionally apply the platform's
complete native Unicode comparison rules before process launch.

The hash chain and seal are tamper-evident commitments, not signatures or an
authenticated transparency log. Durable storage, authentication, key custody,
and atomic record persistence belong to the controller/storage layer.

## Current limitation

This crate records and validates contracts only. It does not execute a command,
open an application, fetch artifact bytes, redact evidence contents, or provide
durable storage. The caller must persist every appended record and keep the
`BlindDisclosure` mapping away from the evaluator. Content-level anonymization
of screenshots, logs, and traces remains an integration responsibility.
Callers must also enforce a bounded transport frame before deserialization;
the collect-all post-deserialization ceilings are not a defense against an
already allocated hostile payload.

The current lifecycle does not model in-run repair rewinds or cross-phase retry
policy. A repair is represented by a new `RunId`, preserving the failed run as
immutable evidence. Backend implementation/deployment, model revision, weight,
and quantization lineage are a required next integration gate: this foundation
records the declared provider/model selector and optional configuration digest,
but does not claim exact or cryptographically verified model lineage.
Check descriptors likewise do not yet constrain the validator attempt's
orchestration role or independently verify artifact bytes at their storage
location. Role/lineage eligibility, broker receipts, artifact-byte attestation,
validated durable seal reload, and external seal anchoring belong to the next
controller/integration gate.
