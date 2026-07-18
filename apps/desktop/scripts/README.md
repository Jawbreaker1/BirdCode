# Desktop build scripts

These scripts deliberately package the daemon for the build host and currently
target the phase-one macOS/Apple Silicon workflow. They require a POSIX shell.

Windows support needs an equivalent native script and verified process-tree
shutdown behavior before the desktop bundle can be labelled Windows-ready.
Cross-compiling a sidecar is intentionally rejected rather than silently
packaging a stale host binary.
