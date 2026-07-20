# Protocol-v4 root-planner live evidence

This directory retains the exact content-addressed artifacts from the final
live `PlanOnly` run for source commit
`006786caec7f484a07a3d8fb1851e0246e56e154`.

## Invocation

- Host: macOS on Apple Silicon (`aarch64`)
- Backend: LM Studio at `http://127.0.0.1:1234`
- Exact loaded model: `google/gemma-4-26b-a4b`
- Reported context: 262,144 tokens
- Reasoning: off

```sh
target/debug/birdcode plan \
  --model google/gemma-4-26b-a4b \
  --goal 'Planera nästa BirdCode-slice: koppla den testade modelldrivna planner/replanner-kärnan till daemonen så att root-agenten först skapar en egen typad plan, därefter delegerar två oberoende read-only repository-audits parallellt med separata kontexter och till sist samlar strukturerade handoffs utan att använda språkberoende nyckelord eller reguljära uttryck. Bevara hela den kausala historiken och säkerställ att sessionen kan fortsätta efter compaction. 日本語の制約も意味を失わず保持すること。' \
  --workspace /Users/johanengwall/Documents/BirdCode/agent-kernel-worktree \
  --max-output-tokens 4096 \
  --max-wall-time-seconds 300 \
  --reasoning off \
  --data-dir /tmp/birdcode-live-v4-final.p2XC8h
```

The command exited `0`. The durable run
`019f7bdc-f4a1-7d40-84d3-347ab32013e8` belongs to session
`019f7bdc-f49f-76c2-a85a-27e6317aaebd`, reached `Completed`, and retained eight
ordered run events. LM Studio reported 1,866 input plus 1,046 output tokens,
2,912 total. The SHA-256 of the exact HTTP response body was
`5db21fca4de108fbeb01a988e02cff68f8f3f29983ebf0df409d66ebefa057db`.

## Result interpretation

The runtime accepted the output mechanically: its schema, immutable bindings,
obligation references, authority, budgets, artifact hashes, and dependency DAG
were valid. A later out-of-band read-only coding-agent review—not the v4 daemon
path—did **not** accept it as fulfillment of the user goal. The model proposed
two sequential repository-discovery orders, not two parallel audit orders with
structured handoffs.

That distinction is intentional evidence. This run proves the protocol-v4
transport, persistence, inference, validation, and replay path at the pinned
source snapshot. It also proves
that mechanical acceptance alone is insufficient; a model-driven semantic
critic and repair/replanning loop are required before BirdCode can claim robust
planning quality.

## Retained artifacts

| File | Original media role | SHA-256 | Bytes |
| --- | --- | --- | ---: |
| `compiled-prompt.json` | compiled root prompt | `cb00f02c270e7440351e64c8123676ac4ec17ceeb0cce0a388b5e99499f302f6` | 17,639 |
| `inference-request.json` | canonical provider-neutral structured inference request | `c978b0edd3e1a99533233b9cd9953e40e1bc68b8ba4a1c488784379ecdcd8321` | 13,454 |
| `provider-evidence.json` | parsed provider response and exact-body hash | `711cb17e7baa1caeefd0f7a359b20c2085e193045add148b790ebc74fa6a1bbd` | 9,596 |
| `model-proposal.json` | model proposal | `86e469458bfc56953364f2e0c1a3c86add82f432e86dc981cd7ad837c95e1030` | 2,959 |
| `accepted-plan.json` | mechanically accepted plan | `f9a4ad5959912bdeede1683666904a6aa79273c66caeabd72125b73165e77077` | 2,388 |
| `validation.json` | deterministic validation report | `30f5de6c69d11b8c3753b8f68222a8dda1147c3586183f1083c28ee925141b99` | 37 |

The original SQLite database and temporary runtime path are not committed.
The commit-pinned, hash-addressed artifact payloads needed to inspect the model
interaction are retained here under their verified content hashes; the ordered
event chain and causal IDs are recorded in the associated release review.
