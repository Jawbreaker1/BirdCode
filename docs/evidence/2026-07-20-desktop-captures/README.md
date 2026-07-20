# Protocol-v5 desktop renderer captures

Source commit: `78a77b40483b3a6949bab8301a62483168e13d5a`

Capture date: `2026-07-20`

These images render the production React `App` and production CSS through the
Vite development server in Codex's in-app browser at a `1400×860` viewport. A
development-only bridge, guarded by `import.meta.env.DEV`, supplies the
checked-in read-only runtime-health and LM Studio inventory observation. The
bridge is absent from the production bundle and deliberately has no
`startPlan` implementation, so it cannot fabricate model output or a completed
run.

The policy-configured fixture proves only that the renderer received
`semanticPolicyConfigured=true`. It does not prove that a policy file exists,
that its contents are valid, or that daemon preflight accepted its model and
budget bindings. The retained one-model inventory cannot satisfy the current
distinct-model producer/critic policy.

The browser capture bytes were mechanically converted to PNG without visual
editing. A production build was scanned for the bridge name, fixture modes,
fixture text, and retained model ID; it contained none of them. These are exact
renderer captures, not OS-level screenshots of a native Tauri window. The
native macOS shell is validated separately in the commit-pinned release gate.

| Asset | Dimensions | SHA-256 |
| --- | ---: | --- |
| `desktop-root-planner-ready.png` | 1400×860 | `35f3966b698e00506788b2480648095021f3a77a230d2f9aa85ed09a27609daa` |
| `desktop-root-planner-policy-configured.png` | 1400×860 | `69bc982e1b042eaa3289ec66a10bba10b7e369e29e8614360328d8e57654e4da` |
| `desktop-root-planner-inspector.png` | 286×860 | `3852f0386c2c0f29d82f4cfd0629afafbad13a9801900bbb7d9862691283c6cd` |

The assets themselves live in [`docs/assets/screenshots`](../../assets/screenshots/).
