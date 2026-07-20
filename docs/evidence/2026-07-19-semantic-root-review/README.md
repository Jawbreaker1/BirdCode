# Local model-inventory observation

Observation date: `2026-07-19`

Host: macOS ARM64 development machine

Endpoint: credential-free loopback `http://127.0.0.1:1234/v1/models`

Command: `curl -fsS http://127.0.0.1:1234/v1/models`

[`lmstudio-models.json`](lmstudio-models.json) contains the exact response body
observed while validating the policy-separated root-review milestone. The
response exposes one exact loaded model ID,
`google/gemma-4-26b-a4b`. BirdCode did not load, unload, or otherwise mutate
the LM Studio instance because it was concurrently used by another project.

This evidence supports only the statement that one model was reported at the
observation time. It does not report the LM Studio application version,
quantization, deployment identity, independence domain, current state at a
later time, or a live two-model semantic-review result.
