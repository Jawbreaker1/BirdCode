# Policy-separated root-planning review

BirdCode's current product path never treats structural plan validity as proof
that a plan is good enough. Every new `PlanOnly` run requires an explicit,
trusted producer/critic role policy before the daemon makes its first model call.

The closed protocol is:

1. the producer creates the initial root plan;
2. the policy-separated critic returns `accept`, `revise`, `clarify`, or `escalate`
   through the versioned typed critic contract;
3. `accept` completes, while `clarify`, `escalate`, or an invalid critic
   contract fails this current non-interactive run;
4. `revise` from the initial review authorizes exactly one complete replacement
   plan from the producer; and
5. the critic reviews that exact replacement once. A final `accept` completes;
   a final `revise`, `clarify`, `escalate`, or invalid contract fails, because
   no second repair is permitted.

That means an accepted run performs exactly two model calls. A repaired and
accepted run performs exactly four. There is no keyword, regular-expression,
or prose parser that chooses these branches: the model returns the typed
semantic verdict, while protocol and Store code enforce the legal state
transitions, exact artifact bindings, budgets, identities, and call ceiling.

## Configure it

Copy [the example policy](../examples/root-planning-policy.json) and
[backend manifest](../examples/backend-manifest.json) outside the repository
or to ignored local paths and replace every `REPLACE_WITH_...` value. The
producer and critic must have distinct exact model IDs, deployment IDs, and
independence-domain IDs. Each policy deployment must resolve to its exact
configured backend route, the manifest's explicit primary must be the producer,
and both models must be discoverable before inference begins. The model selected
for the run must exactly match `producer.model_id`. If a caller sets an aggregate
`max_output_tokens` ceiling, it must be at least the sum of all four fixed stage
budgets, even when the direct acceptance path will use only the first two
stages. The desktop always supplies a ceiling (16,384 by default and maximum);
the checked-in example policy totals 12,288 tokens.

For the CLI, pass the file explicitly:

```sh
target/debug/birdcode plan \
  --model-policy /absolute/path/to/root-planning-policy.json \
  --backend-config /absolute/path/to/backend-manifest.json \
  --model EXACT_PRODUCER_MODEL_ID \
  --goal "Plan the complete outcome" \
  --workspace /absolute/path/to/repository
```

For the macOS desktop application, set the path before starting BirdCode:

```sh
export BIRDCODE_MODEL_POLICY=/absolute/path/to/root-planning-policy.json
export BIRDCODE_BACKEND_CONFIG=/absolute/path/to/backend-manifest.json
npm run dev
```

If the desktop application was already started with another environment,
restart the application after changing either path. BirdCode shows the
policy state in Run setup and disables plan submission when no policy is
configured. “Policy configured” means only that an explicit path was supplied;
the daemon validates the policy, manifest, exact producer/critic routes,
producer-primary binding, and aggregate stage budget. The UI deliberately does
not present that validation as already passed.

## Trust boundary

The policy file is operator-trusted configuration, not model output. Prompt
identities are intentionally absent from the JSON; the daemon derives their
digests from BirdCode's bundled prompt registry so a policy file cannot swap
the root planner, critic, or repair contract.

The current LM Studio adapter records and enforces its configured deployment,
canonical endpoint origin, instance digest, and exact catalog- and
completion-reported model ID. The registry resolves producer and critic by
exact `(backend_id, deployment_id)` with no primary fallback, and rejects two
LM Studio routes that alias one canonical origin. LM Studio does **not** attest
the policy's independence-domain labels; those remain trusted operator
assertions, and BirdCode must not describe them as provider-attested until a
backend supplies such evidence. Cross-provider review belongs to a later
adapter milestone.

Each Prepared call and retained response is bound to its full backend instance,
so transport substitution at that call boundary fails before inference or at
observation. One hardening gap remains: the first discovery does not yet retain
both role-instance attestations as one durable preflight record. A daemon
restart before a role's first Prepared event can therefore rebind the same
configured deployment ID to a changed origin. Closing that restart boundary is
required before the separation claim is considered complete.

The stable protocol-v5 wire identifiers `IndependentSemanticReviewV1` and
`IndependentCritic` predate this wording clarification. In this release,
“independent” in those identifiers means eligibility under the configured
distinct-role/model/deployment/domain policy; it is not a claim that the
provider attested deployment identity, weights, or independence.

A single loaded local model is sufficient for discovery and standalone prompt
evaluation, but it is deliberately insufficient for policy-separated
root-plan acceptance.
