# BirdCode workspace manager

`birdcode-workspace` is the macOS-v1 adapter for creating an immutable,
read-only repository view without writing BirdCode's Store itself. It returns
exact Protocol payloads and retained artifact bytes at every durable boundary;
the daemon owns artifact persistence and idempotent event append.

This adapter deliberately does **not** claim APFS snapshot atomicity. Its v1
guarantee is narrower and testable:

1. An internal cooperative writer lease reaches zero active writers and is
   revoked with a monotonically increasing generation.
2. The source is walked through directory descriptors (`openat`, `NOFOLLOW`)
   before and after `hdiutil create`. Both canonical content manifests, their
   digests and the source-root identity must be identical.
3. The resulting image is hashed and attached with the exact no-shell command:

   ```text
   /usr/bin/hdiutil attach -readonly -mountpoint <exact mount> -noautoopen -plist <exact image>
   ```

4. The mounted filesystem must report `MNT_RDONLY`, and a descriptor-relative
   write/create probe must fail with Darwin `EROFS` (`30`).
5. Its descriptor-confined mounted content manifest must be byte-identical to
   the post-capture source manifest before a snapshot lease can be issued.
6. Release uses the exact bound mount path, and a separate root-identity
   observation must prove that detach took effect before
   `unmounted_verified: true` is emitted.

## Persist-before-effect phases

The API intentionally cannot perform the whole lifecycle in one opaque call.
Durable identities are allocated by the caller, never minted by the manager.
The normal flow is:

```text
prepare_snapshot
  -> revoke_writers
  -> persist RepositoryWriterLeaseRevoked
  -> confirm_writer_revocation
  -> prepare_capture        (journal fsync before create)
  -> execute_capture
  -> prepare_attach         (journal fsync before attach)
  -> execute_attach
  -> persist RepositorySnapshotLeaseIssued
  -> confirm_snapshot_lease
  -> activate_snapshot_lease
  -> prepare_release        (journal fsync before detach)
  -> execute_release
  -> persist RepositorySnapshotLeaseReleased
  -> confirm_release        (only now delete image/local journal)
```

The authority value binds session, run, actor, claim event, claim identity,
claim generation, runtime instance and cancellation generation. Writer,
snapshot-lease and release event IDs, snapshot lease ID, and the release causal
parent are all caller-preallocated.

## Closed Store wiring

The attach command's raw plist is structurally decoded as a plist value. The
single mounted leaf is selected only by its exact `mount-point` field;
unmounted entities are not guessed from device-name or content-hint text.

The Store-facing attach receipt has an important closed-wire rule:

- `attach_receipt.stdout_artifact` and `attach_plist_artifact` are the same
  canonical `RepositoryMacOsAttachEvidenceV1` artifact;
- the original `hdiutil` plist bytes are retained separately for provenance;
- `post_mount_manifest_artifact` is the canonical snapshot-manifest document;
- the additional source and mounted content-manifest artifacts expose the exact
  byte comparison performed locally.

## Recovery

The cleanup journal is confined to an open directory descriptor. Records are
canonical, checksummed JSON written through a `0600` temporary file, file fsync,
descriptor-relative rename and directory fsync. Reads and removals use
`openat`/`unlinkat` with `NOFOLLOW`. Only structurally valid, bounded orphan
temporary files created by this journal are removed.

Create, attach and detach each have explicit prepared and outcome-unknown
states. A restart never upgrades an uncertain command to success, and it never
claims `DetachedObserved` without a separate mount-root observation.

Recovery is a closed two-step API:

1. call `WorkspaceManager::recovery_inspections` and reconcile every exact
   lease/event ID against the durable Store;
2. pass that unchanged inspection set to
   `WorkspaceManager::recover_inspections`, with exactly one typed directive per
   lease: either `ResumeCommittedLease` carrying the exact committed event and
   retained lease bytes, or the explicit failed-run policy
   `AbandonForFreshCapture`. The request also carries the current recovery
   runtime identity, so new command observations are never timestamped inside
   the abandoned process's old monotonic-clock domain.

The executor takes a non-blocking OS-level exclusive lock in the
descriptor-confined journal and holds it across re-read, comparison, commands,
cleanup and journal removal. A concurrent process receives typed
`RecoveryAlreadyRunning`; it cannot race after the inspection comparison. The
executor rejects stale/substituted inspections and requires every recorded
source/image/mount path to equal the manager's canonical, lease-derived paths.
Before any detach or deletion it runs the bounded, no-shell
`/usr/bin/hdiutil info -plist` observation and structurally requires one exact
image path to map bijectively to one exact mount point and one closed
`/dev/disk<digits>[s<digits>]` device path. Ambiguous images, mounts owned by
another image, or an image still attached without the expected mount return a
typed blocked outcome and preserve raw plist/stdout/stderr evidence; no image,
mount, or journal is removed.

Resumption additionally verifies canonical lease bytes, the committed event,
the current image hash, kernel read-only mount identity/device and a freshly
recomputed mounted-content/snapshot-manifest digest before reconstructing a
usable `ActiveSnapshotLease`. Abandonment never repeats create or attach. It
rechecks exact topology and mount identity immediately before detaching the
validated device path (never a reusable mount-path string), reinspects after
detach, then deletes only the exact regular image and exact empty unmounted
directory before fsyncing journal removal. Repeating recovery after any cleanup
crash cut is idempotent.

## Platform and tests

macOS is the only implemented platform in v1. Other targets compile but
`WorkspaceManager::open_system` returns a typed `UnsupportedPlatform` error.
Command, artifact and monotonic-clock boundaries are injectable for adversarial
tests.

```bash
cargo test -p birdcode-workspace
cargo clippy -p birdcode-workspace --all-targets -- -D warnings

# Explicitly creates, mounts read-only and detaches a temporary real disk image.
BIRDCODE_RUN_MACOS_HDIUTIL_SMOKE=1 \
  cargo test -p birdcode-workspace --test macos_snapshot_smoke -- --ignored --nocapture
```
