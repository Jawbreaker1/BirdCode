# BirdCode model backends

This crate contains provider-neutral contracts plus the initial LM Studio
adapter. It is independent of Tauri, the BirdCode daemon, persistence, tools,
and scheduling.

## Implemented LM Studio capability

- Read-only model discovery starts with `GET /v1/models`. The exact `id`
  returned there is the inference identifier; BirdCode does not normalize or
  guess model names.
- When `GET /api/v1/models` succeeds, records are joined only by exact native
  keys, variants, selected variants, or loaded-instance IDs. This enriches the
  catalog with loaded state, context limits, quantization, vision,
  `trained_for_tool_use`, and public reasoning settings.
  `loaded` is asserted only when the OpenAI ID exactly matches a reported
  loaded-instance ID; a loaded base record reached only through a variant key
  remains `unknown` for that exact inference ID.
- If the native endpoint is absent or unusable, discovery still returns the
  OpenAI-compatible catalog but reports native discovery as unavailable. All
  metadata that only the native endpoint can establish remains `unknown`.
- Non-streamed structured inference uses `POST /v1/chat/completions` with
  `response_format.type = json_schema`, `strict = true`, and `stream = false`.
  Assistant content must decode as JSON and validate against the caller's JSON
  Schema before it is returned.
- Output contracts may declare a provider-facing generation schema separately
  from the authoritative local validation schema. The adapter sends the former
  unchanged and always validates against the latter; it never projects between
  shapes.
- Structured requests can opt into provider-neutral typed reasoning. LM Studio
  maps `off` to its wire value `none`, while `low`, `medium`, and `high` remain
  exact. Provider-neutral `on` is rejected as unsupported because LM Studio's
  chat-completions field has no faithful equivalent. The field is absent by
  default.

The adapter never calls model load, unload, or download endpoints. Discovery
does not claim that an individual model can reliably follow a schema: LM
Studio exposes the endpoint feature, while model behavior still has to be
evaluated. HTTP request/response sizes and deadlines are bounded. Optional API
tokens are stored in a redacting type and only enter a sensitive Authorization
header. Base URLs with user information, query strings, fragments, or a
non-root path are rejected before a client is created.

`BackendId("lmstudio")` identifies the provider implementation, not a unique
configured server. The exact endpoint used by a configured instance is retained
in discovery and inference evidence, and complete response bodies carry a
SHA-256 over the exact bytes received. Discovery has its own shorter deadline
so optional native enrichment cannot inherit a long inference timeout. Products
that persist this evidence are responsible for selecting the minimum necessary
records; BirdCode's eval runner stores only the selected model's bounded
identity evidence plus full-body digests, never the complete inventory.
