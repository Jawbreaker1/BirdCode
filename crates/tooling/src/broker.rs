use crate::model::{
    ObservedRepositoryToolCallV2, PreparedRepositoryToolCallV2, RepositoryBrokerErrorV2,
    RepositoryToolExecuteErrorV2, RepositoryToolExecuteInputV2, RepositoryToolInterruptionInputV2,
    RepositoryToolPrepareInputV2, RepositoryToolRestartReconciliationInputV2,
    RepositoryToolTerminalV2, RetainedArtifactV2, UnknownRepositoryToolCallV2, digest,
};
use birdcode_protocol::{
    ChildToolObservedV2, ChildToolOperation, ChildToolOutcomeUnknownV2, ChildToolPreparedV2,
    ChildToolUnknownBoundary, ChildToolUnknownReason, REPOSITORY_BROKER_CONTRACT_VERSION,
    REPOSITORY_TOOL_CANONICAL_PARAMETERS_V2_MEDIA_TYPE,
    REPOSITORY_TOOL_DENIAL_EVIDENCE_V2_MEDIA_TYPE, REPOSITORY_TOOL_FAILURE_EVIDENCE_V2_MEDIA_TYPE,
    REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES, REPOSITORY_TOOL_HARD_MAX_CALLS_PER_BROKER,
    REPOSITORY_TOOL_HARD_MAX_COMPONENT_BYTES, REPOSITORY_TOOL_HARD_MAX_DIRECTORY_ENTRIES_SCANNED,
    REPOSITORY_TOOL_HARD_MAX_DIRECTORY_NAME_BYTES_SCANNED, REPOSITORY_TOOL_HARD_MAX_PATH_BYTES,
    REPOSITORY_TOOL_HARD_MAX_PATH_COMPONENTS, REPOSITORY_TOOL_HARD_MAX_READ_BYTES,
    REPOSITORY_TOOL_HARD_MAX_REQUEST_BYTES, REPOSITORY_TOOL_HARD_MAX_SEARCH_BYTES_PER_FILE,
    REPOSITORY_TOOL_HARD_MAX_SEARCH_DEPTH, REPOSITORY_TOOL_HARD_MAX_SEARCH_FILES,
    REPOSITORY_TOOL_HARD_MAX_SEARCH_MATCHES, REPOSITORY_TOOL_HARD_MAX_SEARCH_PATTERN_BYTES,
    REPOSITORY_TOOL_HARD_MAX_SEARCH_TOTAL_BYTES, REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES,
    REPOSITORY_TOOL_HARD_MAX_TREE_DEPTH, REPOSITORY_TOOL_HARD_MAX_TREE_ENTRIES,
    REPOSITORY_TOOL_OBSERVED_RECEIPT_V2_MEDIA_TYPE, REPOSITORY_TOOL_POLICY_MEDIA_TYPE,
    REPOSITORY_TOOL_PREPARED_RECEIPT_V2_MEDIA_TYPE, REPOSITORY_TOOL_RESULT_V2_MEDIA_TYPE,
    REPOSITORY_TOOL_UNKNOWN_EVIDENCE_V2_MEDIA_TYPE, REPOSITORY_TOOL_UNKNOWN_RECEIPT_V2_MEDIA_TYPE,
    RepositoryBrokerClockV1, RepositoryBrokerEpochStateV1, RepositoryBrokerInstanceId,
    RepositoryCleanupDispositionV1, RepositoryCleanupRecoveryV1, RepositoryCleanupReportV2,
    RepositoryFileIdentityV1, RepositoryFilesystemEffectV1, RepositoryInterruptionBoundaryV1,
    RepositoryIoFailureKindV1, RepositoryLimitKindV1, RepositoryLimitKindV2,
    RepositoryToolAuthorizationDecisionV2, RepositoryToolBoundsV1, RepositoryToolDenialEvidenceV1,
    RepositoryToolEvidenceCodecErrorV2, RepositoryToolFailureEvidenceV1, RepositoryToolFailureV1,
    RepositoryToolObservedReceiptV2, RepositoryToolObservedTerminalV2,
    RepositoryToolPreparedReceiptV2, RepositoryToolReceiptAuthorityV2, RepositoryToolResultV2,
    RepositoryToolUnknownEvidenceV1, RepositoryToolUnknownReceiptV2, RepositoryToolUnknownTimingV2,
    RepositoryUnretainedEvidenceDigestV1, Sha256Digest, decode_repository_tool_denial_evidence_v2,
    decode_repository_tool_failure_evidence_v2, decode_repository_tool_unknown_evidence_v2,
    encode_repository_tool_denial_evidence_v2, encode_repository_tool_failure_evidence_v2,
    encode_repository_tool_result_v2, encode_repository_tool_unknown_evidence_v2,
    evaluate_repository_tool_authorization_v1,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;
use thiserror::Error;

#[cfg(unix)]
use std::os::fd::OwnedFd;

/// Failure to establish one descriptor-backed Protocol-v7 broker epoch.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BrokerOpenError {
    #[error("repository authority has an invalid {limit:?} ceiling")]
    InvalidAuthorityBound {
        limit: RepositoryLimitKindV2,
        value: u64,
        hard_maximum: u64,
    },
    #[error("repository policy artifact does not bind the exact policy digest/media type")]
    PolicyArtifactMismatch,
    #[error("active broker epoch occurs in its own closed epoch set")]
    ActiveBrokerAlreadyClosed,
    #[error("closed broker epoch list contains a duplicate id")]
    DuplicateClosedBrokerEpoch,
    #[error("repository root could not be opened with read-only descriptor authority")]
    RootUnavailable {
        kind: RepositoryIoFailureKindV1,
        raw_os_error: Option<i32>,
    },
    #[error("opened root descriptor identity differs from the issued Protocol authority")]
    RootIdentityMismatch {
        expected: RepositoryFileIdentityV1,
        observed: RepositoryFileIdentityV1,
    },
    #[error("repository tooling has no secure descriptor-confined adapter for this platform")]
    UnsupportedPlatform,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IssuedCall {
    prepared_receipt_sha256: Sha256Digest,
    consumed: bool,
}

#[derive(Default)]
struct BrokerPrepareState {
    last_published_sequence: u64,
    issued_calls: BTreeMap<birdcode_protocol::ChildToolCallId, IssuedCall>,
}

/// Descriptor-confined, read-only repository broker using only Protocol-v7
/// authority, operations, evaluator, result codec and receipt wires.
///
/// The caller must persist both artifacts returned by `prepare` and append the
/// durable Prepared event before it calls `execute` or `record_interruption`.
/// The broker cannot prove that external ordering, so its API makes the
/// boundary explicit and consumes each exact Prepared at most once. Successful
/// Prepare publication is serialized inside this broker and an error never
/// advances its call sequence. Ordering publication through the caller's
/// durable Store acknowledgement remains an external service obligation.
pub struct RepositoryToolBroker {
    authority: RepositoryToolReceiptAuthorityV2,
    epoch: RepositoryBrokerEpochStateV1,
    started_at: Instant,
    root_identity: RepositoryFileIdentityV1,
    prepare_state: Mutex<BrokerPrepareState>,
    reconciled_prepared: Mutex<
        BTreeSet<(
            RepositoryBrokerInstanceId,
            birdcode_protocol::ChildToolCallId,
            Sha256Digest,
        )>,
    >,
    #[cfg(unix)]
    root: OwnedFd,
}

impl RepositoryToolBroker {
    /// Opens the exact authority root without following a root symlink.
    ///
    /// # Errors
    ///
    /// Rejects malformed epoch state, invalid broker ceilings, policy binding
    /// mismatch, unsupported platforms and any descriptor identity mismatch.
    pub fn open(
        root: impl AsRef<Path>,
        authority: RepositoryToolReceiptAuthorityV2,
        epoch: RepositoryBrokerEpochStateV1,
    ) -> Result<Self, BrokerOpenError> {
        validate_authority(&authority)?;
        validate_epoch(&epoch)?;

        #[cfg(unix)]
        {
            let root = crate::unix::open_root(root.as_ref()).map_err(|failure| {
                BrokerOpenError::RootUnavailable {
                    kind: failure.kind,
                    raw_os_error: failure.raw_os_error,
                }
            })?;
            let root_identity = crate::unix::descriptor_identity(&root).map_err(|failure| {
                BrokerOpenError::RootUnavailable {
                    kind: failure.kind,
                    raw_os_error: failure.raw_os_error,
                }
            })?;
            if root_identity != authority.root.descriptor_identity {
                return Err(BrokerOpenError::RootIdentityMismatch {
                    expected: authority.root.descriptor_identity,
                    observed: root_identity,
                });
            }
            Ok(Self {
                authority,
                epoch,
                started_at: Instant::now(),
                root_identity,
                prepare_state: Mutex::new(BrokerPrepareState::default()),
                reconciled_prepared: Mutex::new(BTreeSet::new()),
                root,
            })
        }

        #[cfg(not(unix))]
        {
            let _ = root;
            Err(BrokerOpenError::UnsupportedPlatform)
        }
    }

    #[must_use]
    pub fn authority(&self) -> &RepositoryToolReceiptAuthorityV2 {
        &self.authority
    }

    #[must_use]
    pub fn epoch(&self) -> &RepositoryBrokerEpochStateV1 {
        &self.epoch
    }

    #[must_use]
    pub const fn broker_instance_id(&self) -> RepositoryBrokerInstanceId {
        self.epoch.active_broker_instance_id
    }

    /// Creates the canonical parameters and Prepared-v2 artifacts.
    ///
    /// This method performs no per-call filesystem access. All lifecycle IDs,
    /// bindings, action identity, grant identity and ordinal come from the
    /// caller's exact Protocol parameters. The shared broker instance allocates
    /// only its run-global call sequence and broker-local monotonic observation;
    /// a caller-provided tool ordinal remains local to its child attempt. The
    /// sequence and issued-call record become visible together only after every
    /// fallible Prepared encoding and size check has succeeded.
    ///
    /// # Errors
    ///
    /// Fails before Prepared when canonical bytes exceed the hard artifact
    /// boundary, a receipt cannot be encoded within 256 KiB, the call ID is a
    /// duplicate, or broker state is unavailable.
    pub fn prepare(
        &self,
        input: RepositoryToolPrepareInputV2,
    ) -> Result<PreparedRepositoryToolCallV2, RepositoryBrokerErrorV2> {
        let parameter_bytes = canonical_json(&input.parameters, "canonical parameters")?;
        let parameter_size = u64::try_from(parameter_bytes.len()).unwrap_or(u64::MAX);
        if parameter_size > REPOSITORY_TOOL_HARD_MAX_REQUEST_BYTES {
            return Err(RepositoryBrokerErrorV2::CanonicalParametersTooLarge {
                actual: parameter_size,
                maximum: REPOSITORY_TOOL_HARD_MAX_REQUEST_BYTES,
            });
        }
        let canonical_parameters = RetainedArtifactV2::from_bytes(
            REPOSITORY_TOOL_CANONICAL_PARAMETERS_V2_MEDIA_TYPE,
            parameter_bytes,
        );
        let canonical_parameters_digest = digest(&canonical_parameters.bytes);
        let mut state = self
            .prepare_state
            .lock()
            .map_err(|_| RepositoryBrokerErrorV2::BrokerStateUnavailable)?;
        if state
            .issued_calls
            .contains_key(&input.parameters.tool_call_id)
        {
            return Err(RepositoryBrokerErrorV2::DuplicateToolCallId);
        }
        let broker_call_sequence = next_broker_call_sequence(state.last_published_sequence)
            .ok_or(RepositoryBrokerErrorV2::BrokerStateUnavailable)?;
        let authorization = evaluate_repository_tool_authorization_v1(
            &self.authority.broker_bounds,
            &self.authority.tool_grants,
            &input.parameters,
            parameter_size,
            broker_call_sequence,
        );
        let receipt = RepositoryToolPreparedReceiptV2 {
            schema_version: REPOSITORY_BROKER_CONTRACT_VERSION,
            binding: input.parameters.binding.clone(),
            tool_call_id: input.parameters.tool_call_id,
            tool_ordinal: input.parameters.tool_ordinal,
            action_binding: input.parameters.action_binding.clone(),
            operation: input.parameters.operation.clone(),
            authority: self.authority.clone(),
            canonical_parameters_artifact: canonical_parameters.artifact.clone(),
            canonical_parameters_digest,
            authorization,
            broker_call_sequence,
            broker_prepared_at: self.moment(),
            runtime_prepared_at: input.runtime_prepared_at,
        };
        let receipt_bytes = canonical_json(&receipt, "prepared receipt")?;
        check_prepared_receipt_size(&receipt_bytes)?;
        let prepared_receipt = RetainedArtifactV2::from_bytes(
            REPOSITORY_TOOL_PREPARED_RECEIPT_V2_MEDIA_TYPE,
            receipt_bytes,
        );

        state.issued_calls.insert(
            receipt.tool_call_id,
            IssuedCall {
                prepared_receipt_sha256: digest(&prepared_receipt.bytes),
                consumed: false,
            },
        );
        state.last_published_sequence = broker_call_sequence;
        Ok(PreparedRepositoryToolCallV2 {
            receipt,
            canonical_parameters,
            prepared_receipt,
        })
    }

    /// Executes one exact Prepared call at most once.
    ///
    /// Authorization denial returns a canonical Observed-v2 denial without a
    /// filesystem access attempt. Authorized calls use only descriptor-relative
    /// Unix operations and return result bytes separately from the small receipt.
    /// The finish-clock callback is invoked exactly once after that effect
    /// boundary and its reading is bound into the terminal receipt. It is not
    /// invoked when validation or consumption rejects the Prepared record.
    ///
    /// # Errors
    ///
    /// Rejects substituted, unissued, cross-epoch or consumed Prepared records,
    /// unavailable broker state, and any canonical encoding/cap violation.
    pub fn execute<F>(
        &self,
        input: RepositoryToolExecuteInputV2,
        runtime_finished_at: F,
    ) -> Result<RepositoryToolTerminalV2, RepositoryBrokerErrorV2>
    where
        F: FnOnce() -> birdcode_protocol::RuntimeClockReading,
    {
        self.execute_classified(input, runtime_finished_at)
            .map_err(RepositoryToolExecuteErrorV2::into_broker_error)
    }

    /// Executes one exact Prepared call while preserving whether a failure
    /// occurred before or after the one-shot effect boundary.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryToolExecuteErrorV2::NotStarted`] only while the
    /// Prepared call remains safe to close through `record_interruption`.
    /// [`RepositoryToolExecuteErrorV2::OutcomeIndeterminate`] means the call
    /// was consumed and must be reconciled by a different runtime.
    pub fn execute_classified<F>(
        &self,
        input: RepositoryToolExecuteInputV2,
        runtime_finished_at: F,
    ) -> Result<RepositoryToolTerminalV2, RepositoryToolExecuteErrorV2>
    where
        F: FnOnce() -> birdcode_protocol::RuntimeClockReading,
    {
        let RepositoryToolExecuteInputV2 {
            prepared,
            prepared_event_id,
        } = input;
        self.validate_active_prepared(&prepared)
            .map_err(RepositoryToolExecuteErrorV2::NotStarted)?;
        self.consume(&prepared)
            .map_err(RepositoryToolExecuteErrorV2::NotStarted)?;

        if let RepositoryToolAuthorizationDecisionV2::Denied { denial } =
            &prepared.receipt.authorization
        {
            let effect = RepositoryFilesystemEffectV1::NoFilesystemAccessAttempted;
            let runtime_finished_at = runtime_finished_at();
            let evidence = retained_protocol_evidence(
                REPOSITORY_TOOL_DENIAL_EVIDENCE_V2_MEDIA_TYPE,
                encode_repository_tool_denial_evidence_v2(&RepositoryToolDenialEvidenceV1 {
                    call_id: prepared.receipt.tool_call_id,
                    denial: denial.clone(),
                    effect,
                }),
                "authorization denial evidence",
            )
            .map_err(RepositoryToolExecuteErrorV2::OutcomeIndeterminate)?;
            let terminal = RepositoryToolObservedTerminalV2::AuthorizationDenied {
                denial: denial.clone(),
                evidence_artifact: evidence.artifact.clone(),
            };
            return self
                .observed(
                    &prepared,
                    prepared_event_id,
                    runtime_finished_at,
                    terminal,
                    effect,
                    vec![evidence],
                )
                .map_err(RepositoryToolExecuteErrorV2::OutcomeIndeterminate);
        }

        #[cfg(unix)]
        let result = self.execute_unix(&prepared.receipt.operation);
        #[cfg(not(unix))]
        let result = Err(RepositoryToolFailureV1::UnsupportedPlatform);
        let runtime_finished_at = runtime_finished_at();

        let terminal = match result {
            Ok(result) => {
                self.observed_success(&prepared, prepared_event_id, runtime_finished_at, &result)
            }
            Err(failure) => self.observed_failure(
                &prepared,
                prepared_event_id,
                runtime_finished_at,
                failure,
                RepositoryFilesystemEffectV1::ReadOnlyFilesystemAccessAttempted,
                None,
            ),
        };
        terminal.map_err(RepositoryToolExecuteErrorV2::OutcomeIndeterminate)
    }

    /// Closes one exact, durable Prepared call before execution in this active
    /// broker epoch. The resulting timing is broker-recorded and the effect is
    /// known to be `NoFilesystemAccessAttempted`.
    ///
    /// # Errors
    ///
    /// Rejects substituted, unissued, cross-epoch or consumed Prepared records
    /// and any evidence/terminal encoding or size violation.
    pub fn record_interruption(
        &self,
        input: RepositoryToolInterruptionInputV2,
    ) -> Result<RepositoryToolTerminalV2, RepositoryBrokerErrorV2> {
        validate_interruption_metadata(input.boundary, input.cancellation.as_ref())?;
        self.validate_active_prepared(&input.prepared)?;
        let recorded_at = self.moment();
        let elapsed_nanoseconds = recorded_at
            .monotonic_nanos
            .saturating_sub(input.prepared.receipt.broker_prepared_at.monotonic_nanos);
        let terminal = Self::unknown(
            &input.prepared,
            input.prepared_event_id,
            input.boundary,
            input.cancellation,
            input.runtime_boundary_at,
            RepositoryToolUnknownTimingV2::BrokerRecorded {
                recorded_at,
                elapsed_nanoseconds,
            },
            RepositoryFilesystemEffectV1::NoFilesystemAccessAttempted,
            RepositoryCleanupReportV2::Completed {
                disposition: RepositoryCleanupDispositionV1::NoPersistentResourcesCreated,
                persistent_resources_created: 0,
                temporary_resources_created: 0,
            },
        )?;
        self.consume(&input.prepared)?;
        Ok(terminal)
    }

    /// Reconciles a Prepared call from an explicitly closed broker epoch.
    ///
    /// No old monotonic reading or no-effect claim is fabricated. The canonical
    /// Unknown-v2 receipt records runtime reconciliation, indeterminate effect
    /// and indeterminate cleanup.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical Prepared artifacts, authority mismatch, a broker ID
    /// not present in the closed epoch set, and evidence/receipt cap failures.
    pub fn reconcile_abandoned_prepared(
        &self,
        input: RepositoryToolRestartReconciliationInputV2,
    ) -> Result<RepositoryToolTerminalV2, RepositoryBrokerErrorV2> {
        validate_interruption_metadata(input.boundary, input.cancellation.as_ref())?;
        self.validate_prepared_bundle(&input.prepared)?;
        let abandoned = input.prepared.receipt.broker_prepared_at.broker_instance_id;
        if abandoned == self.broker_instance_id()
            || !self.epoch.closed_broker_instance_ids.contains(&abandoned)
        {
            return Err(RepositoryBrokerErrorV2::BrokerEpochNotClosed {
                broker_instance_id: abandoned,
            });
        }
        let reconciliation_key = (
            abandoned,
            input.prepared.receipt.tool_call_id,
            digest(&input.prepared.prepared_receipt.bytes),
        );
        let mut reconciled = self
            .reconciled_prepared
            .lock()
            .map_err(|_| RepositoryBrokerErrorV2::BrokerStateUnavailable)?;
        if !reconciled.insert(reconciliation_key) {
            return Err(RepositoryBrokerErrorV2::PreparedCallAlreadyConsumed);
        }
        drop(reconciled);
        Self::unknown(
            &input.prepared,
            input.prepared_event_id,
            input.boundary,
            input.cancellation,
            input.runtime_boundary_at,
            RepositoryToolUnknownTimingV2::RuntimeReconciled {
                abandoned_broker_instance_id: abandoned,
            },
            RepositoryFilesystemEffectV1::Indeterminate,
            RepositoryCleanupReportV2::Indeterminate {
                recovery: RepositoryCleanupRecoveryV1::RuntimeReconciliationRequired,
                recovery_evidence: None,
            },
        )
    }

    fn validate_active_prepared(
        &self,
        prepared: &PreparedRepositoryToolCallV2,
    ) -> Result<(), RepositoryBrokerErrorV2> {
        self.validate_prepared_bundle(prepared)?;
        if prepared.receipt.broker_prepared_at.broker_instance_id != self.broker_instance_id() {
            return Err(RepositoryBrokerErrorV2::WrongBrokerEpoch);
        }
        let state = self
            .prepare_state
            .lock()
            .map_err(|_| RepositoryBrokerErrorV2::BrokerStateUnavailable)?;
        let Some(record) = state.issued_calls.get(&prepared.receipt.tool_call_id) else {
            return Err(RepositoryBrokerErrorV2::UnissuedPreparedCall);
        };
        if record.prepared_receipt_sha256 != digest(&prepared.prepared_receipt.bytes) {
            return Err(RepositoryBrokerErrorV2::PreparedSubstitution);
        }
        Ok(())
    }

    fn validate_prepared_bundle(
        &self,
        prepared: &PreparedRepositoryToolCallV2,
    ) -> Result<(), RepositoryBrokerErrorV2> {
        let _ = decode_exact_prepared_parameters(prepared)?;
        if prepared.receipt.authority != self.authority {
            return Err(RepositoryBrokerErrorV2::PreparedSubstitution);
        }
        Ok(())
    }

    fn consume(
        &self,
        prepared: &PreparedRepositoryToolCallV2,
    ) -> Result<(), RepositoryBrokerErrorV2> {
        let mut state = self
            .prepare_state
            .lock()
            .map_err(|_| RepositoryBrokerErrorV2::BrokerStateUnavailable)?;
        let Some(record) = state.issued_calls.get_mut(&prepared.receipt.tool_call_id) else {
            return Err(RepositoryBrokerErrorV2::UnissuedPreparedCall);
        };
        if record.consumed {
            return Err(RepositoryBrokerErrorV2::PreparedCallAlreadyConsumed);
        }
        record.consumed = true;
        Ok(())
    }

    fn moment(&self) -> RepositoryBrokerClockV1 {
        RepositoryBrokerClockV1 {
            broker_instance_id: self.broker_instance_id(),
            monotonic_nanos: duration_ns(self.started_at.elapsed()),
        }
    }

    fn observed_success(
        &self,
        prepared: &PreparedRepositoryToolCallV2,
        prepared_event_id: birdcode_protocol::EventId,
        runtime_finished_at: birdcode_protocol::RuntimeClockReading,
        result: &RepositoryToolResultV2,
    ) -> Result<RepositoryToolTerminalV2, RepositoryBrokerErrorV2> {
        if !result_is_coherent(
            &prepared.receipt.operation,
            result,
            &prepared.receipt.authority.broker_bounds,
        ) {
            return self.observed_failure(
                prepared,
                prepared_event_id,
                runtime_finished_at,
                RepositoryToolFailureV1::BrokerStateUnavailable,
                RepositoryFilesystemEffectV1::ReadOnlyFilesystemAccessAttempted,
                None,
            );
        }
        let encoded = encode_repository_tool_result_v2(result);
        let result_bytes = match encoded {
            Ok(bytes) => bytes,
            Err(birdcode_protocol::RepositoryToolResultCodecErrorV2::ArtifactTooLarge {
                actual,
                ..
            }) => {
                let bytes = canonical_json(result, "oversized result")?;
                let partial = RepositoryUnretainedEvidenceDigestV1 {
                    media_type: REPOSITORY_TOOL_RESULT_V2_MEDIA_TYPE.to_owned(),
                    byte_len: u64::try_from(bytes.len()).unwrap_or(actual),
                    sha256: digest(&bytes),
                };
                return self.observed_failure(
                    prepared,
                    prepared_event_id,
                    runtime_finished_at,
                    RepositoryToolFailureV1::LimitExceeded {
                        limit: RepositoryLimitKindV1::ArtifactBytes,
                        requested: actual,
                        maximum: REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES,
                    },
                    RepositoryFilesystemEffectV1::ReadOnlyFilesystemAccessAttempted,
                    Some(partial),
                );
            }
            Err(_) => {
                return self.observed_failure(
                    prepared,
                    prepared_event_id,
                    runtime_finished_at,
                    RepositoryToolFailureV1::EvidenceEncodingFailed,
                    RepositoryFilesystemEffectV1::ReadOnlyFilesystemAccessAttempted,
                    None,
                );
            }
        };
        let result_size = u64::try_from(result_bytes.len()).unwrap_or(u64::MAX);
        if result_size > prepared.receipt.authority.broker_bounds.max_artifact_bytes {
            return self.observed_failure(
                prepared,
                prepared_event_id,
                runtime_finished_at,
                RepositoryToolFailureV1::LimitExceeded {
                    limit: RepositoryLimitKindV1::ArtifactBytes,
                    requested: result_size,
                    maximum: prepared.receipt.authority.broker_bounds.max_artifact_bytes,
                },
                RepositoryFilesystemEffectV1::ReadOnlyFilesystemAccessAttempted,
                Some(RepositoryUnretainedEvidenceDigestV1 {
                    media_type: REPOSITORY_TOOL_RESULT_V2_MEDIA_TYPE.to_owned(),
                    byte_len: result_size,
                    sha256: digest(&result_bytes),
                }),
            );
        }
        let result_artifact =
            RetainedArtifactV2::from_bytes(REPOSITORY_TOOL_RESULT_V2_MEDIA_TYPE, result_bytes);
        self.observed(
            prepared,
            prepared_event_id,
            runtime_finished_at,
            RepositoryToolObservedTerminalV2::Succeeded {
                result_artifact: result_artifact.artifact.clone(),
            },
            RepositoryFilesystemEffectV1::ReadOnlyFilesystemAccessAttempted,
            vec![result_artifact],
        )
    }

    fn observed_failure(
        &self,
        prepared: &PreparedRepositoryToolCallV2,
        prepared_event_id: birdcode_protocol::EventId,
        runtime_finished_at: birdcode_protocol::RuntimeClockReading,
        failure: RepositoryToolFailureV1,
        effect: RepositoryFilesystemEffectV1,
        unretained_partial: Option<RepositoryUnretainedEvidenceDigestV1>,
    ) -> Result<RepositoryToolTerminalV2, RepositoryBrokerErrorV2> {
        let evidence = retained_protocol_evidence(
            REPOSITORY_TOOL_FAILURE_EVIDENCE_V2_MEDIA_TYPE,
            encode_repository_tool_failure_evidence_v2(&RepositoryToolFailureEvidenceV1 {
                call_id: prepared.receipt.tool_call_id,
                failure: failure.clone(),
                effect,
            }),
            "failure evidence",
        )?;
        self.observed(
            prepared,
            prepared_event_id,
            runtime_finished_at,
            RepositoryToolObservedTerminalV2::Failed {
                failure,
                evidence_artifact: evidence.artifact.clone(),
                unretained_partial,
            },
            effect,
            vec![evidence],
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "all canonical terminal bindings remain explicit"
    )]
    fn observed(
        &self,
        prepared: &PreparedRepositoryToolCallV2,
        prepared_event_id: birdcode_protocol::EventId,
        runtime_finished_at: birdcode_protocol::RuntimeClockReading,
        terminal: RepositoryToolObservedTerminalV2,
        effect: RepositoryFilesystemEffectV1,
        supporting_artifacts: Vec<RetainedArtifactV2>,
    ) -> Result<RepositoryToolTerminalV2, RepositoryBrokerErrorV2> {
        let completed_at = self.moment();
        let receipt = RepositoryToolObservedReceiptV2 {
            schema_version: REPOSITORY_BROKER_CONTRACT_VERSION,
            binding: prepared.receipt.binding.clone(),
            tool_call_id: prepared.receipt.tool_call_id,
            prepared_event_id,
            action_binding: prepared.receipt.action_binding.clone(),
            prepared_receipt_artifact: prepared.prepared_receipt.artifact.clone(),
            prepared_receipt_digest: digest(&prepared.prepared_receipt.bytes),
            terminal,
            broker_completed_at: completed_at,
            elapsed_nanoseconds: completed_at
                .monotonic_nanos
                .saturating_sub(prepared.receipt.broker_prepared_at.monotonic_nanos),
            effect,
            cleanup: cleanup_for_effect(effect),
            runtime_finished_at,
        };
        let terminal_receipt = retained_terminal(
            REPOSITORY_TOOL_OBSERVED_RECEIPT_V2_MEDIA_TYPE,
            &receipt,
            "observed receipt",
        )?;
        Ok(RepositoryToolTerminalV2::Observed(
            ObservedRepositoryToolCallV2 {
                receipt,
                terminal_receipt,
                supporting_artifacts,
            },
        ))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "all canonical unknown bindings and provenance remain explicit"
    )]
    fn unknown(
        prepared: &PreparedRepositoryToolCallV2,
        prepared_event_id: birdcode_protocol::EventId,
        boundary: RepositoryInterruptionBoundaryV1,
        cancellation: Option<birdcode_protocol::ChildCancellationCauseV1>,
        runtime_boundary_at: birdcode_protocol::RuntimeClockReading,
        timing: RepositoryToolUnknownTimingV2,
        effect: RepositoryFilesystemEffectV1,
        cleanup: RepositoryCleanupReportV2,
    ) -> Result<RepositoryToolTerminalV2, RepositoryBrokerErrorV2> {
        let evidence = retained_protocol_evidence(
            REPOSITORY_TOOL_UNKNOWN_EVIDENCE_V2_MEDIA_TYPE,
            encode_repository_tool_unknown_evidence_v2(&RepositoryToolUnknownEvidenceV1 {
                call_id: prepared.receipt.tool_call_id,
                boundary,
                effect,
            }),
            "unknown evidence",
        )?;
        let receipt = RepositoryToolUnknownReceiptV2 {
            schema_version: REPOSITORY_BROKER_CONTRACT_VERSION,
            binding: prepared.receipt.binding.clone(),
            tool_call_id: prepared.receipt.tool_call_id,
            prepared_event_id,
            action_binding: prepared.receipt.action_binding.clone(),
            prepared_receipt_artifact: prepared.prepared_receipt.artifact.clone(),
            prepared_receipt_digest: digest(&prepared.prepared_receipt.bytes),
            boundary,
            cancellation,
            unknown_evidence_artifact: evidence.artifact.clone(),
            timing,
            effect,
            cleanup,
            runtime_boundary_at,
        };
        let terminal_receipt = retained_terminal(
            REPOSITORY_TOOL_UNKNOWN_RECEIPT_V2_MEDIA_TYPE,
            &receipt,
            "unknown receipt",
        )?;
        Ok(RepositoryToolTerminalV2::Unknown(
            UnknownRepositoryToolCallV2 {
                receipt,
                terminal_receipt,
                supporting_artifacts: vec![evidence],
            },
        ))
    }

    #[cfg(unix)]
    fn execute_unix(
        &self,
        operation: &ChildToolOperation,
    ) -> Result<RepositoryToolResultV2, RepositoryToolFailureV1> {
        let observed_root = crate::unix::descriptor_identity(&self.root)
            .map_err(crate::unix::UnixFailure::into_boundary)?;
        if observed_root != self.root_identity {
            return Err(RepositoryToolFailureV1::SnapshotIdentityChanged {
                expected: self.root_identity,
                observed: observed_root,
            });
        }
        let bounds = &self.authority.broker_bounds;
        let result = match operation {
            ChildToolOperation::RepositoryTree {
                path,
                max_depth,
                max_entries,
            } => crate::unix::tree(&self.root, path, *max_depth, *max_entries, bounds)
                .map(RepositoryToolResultV2::RepositoryTree),
            ChildToolOperation::RepositoryFileRead {
                path,
                offset_bytes,
                max_bytes,
            } => crate::unix::read_file(&self.root, path, *offset_bytes, *max_bytes, bounds)
                .map(RepositoryToolResultV2::RepositoryFileRead),
            ChildToolOperation::LiteralSearch {
                path,
                literal_utf8,
                max_depth,
                max_files,
                max_matches,
                max_bytes_per_file,
                max_total_bytes,
            } => crate::unix::literal_search(
                &self.root,
                path,
                literal_utf8,
                *max_depth,
                *max_files,
                *max_matches,
                *max_bytes_per_file,
                *max_total_bytes,
                bounds,
            )
            .map(RepositoryToolResultV2::LiteralSearch),
        }
        .map_err(crate::unix::UnixFailure::into_boundary)?;
        let final_root = crate::unix::descriptor_identity(&self.root)
            .map_err(crate::unix::UnixFailure::into_boundary)?;
        if final_root != observed_root {
            return Err(RepositoryToolFailureV1::NodeChangedDuringObservation {
                before: observed_root,
                after: final_root,
            });
        }
        Ok(result)
    }
}

const fn next_broker_call_sequence(last_published_sequence: u64) -> Option<u64> {
    last_published_sequence.checked_add(1)
}

fn validate_authority(authority: &RepositoryToolReceiptAuthorityV2) -> Result<(), BrokerOpenError> {
    if authority.policy_artifact.media_type != REPOSITORY_TOOL_POLICY_MEDIA_TYPE
        || authority.policy_artifact.sha256 != authority.policy_digest.as_str()
    {
        return Err(BrokerOpenError::PolicyArtifactMismatch);
    }
    validate_bounds(&authority.broker_bounds)
}

fn validate_epoch(epoch: &RepositoryBrokerEpochStateV1) -> Result<(), BrokerOpenError> {
    let mut closed = BTreeSet::new();
    for broker in &epoch.closed_broker_instance_ids {
        if *broker == epoch.active_broker_instance_id {
            return Err(BrokerOpenError::ActiveBrokerAlreadyClosed);
        }
        if !closed.insert(*broker) {
            return Err(BrokerOpenError::DuplicateClosedBrokerEpoch);
        }
    }
    Ok(())
}

fn validate_bounds(bounds: &RepositoryToolBoundsV1) -> Result<(), BrokerOpenError> {
    let limits = [
        (
            RepositoryLimitKindV2::BrokerCalls,
            bounds.max_calls_per_broker,
            REPOSITORY_TOOL_HARD_MAX_CALLS_PER_BROKER,
        ),
        (
            RepositoryLimitKindV2::RequestBytes,
            bounds.max_request_bytes,
            REPOSITORY_TOOL_HARD_MAX_REQUEST_BYTES,
        ),
        (
            RepositoryLimitKindV2::PathComponents,
            u64::from(bounds.max_path_components),
            u64::from(REPOSITORY_TOOL_HARD_MAX_PATH_COMPONENTS),
        ),
        (
            RepositoryLimitKindV2::PathBytes,
            bounds.max_path_bytes,
            REPOSITORY_TOOL_HARD_MAX_PATH_BYTES,
        ),
        (
            RepositoryLimitKindV2::ComponentBytes,
            bounds.max_component_bytes,
            REPOSITORY_TOOL_HARD_MAX_COMPONENT_BYTES,
        ),
        (
            RepositoryLimitKindV2::ReadBytes,
            bounds.max_read_bytes,
            REPOSITORY_TOOL_HARD_MAX_READ_BYTES,
        ),
        (
            RepositoryLimitKindV2::TreeDepth,
            u64::from(bounds.max_tree_depth),
            u64::from(REPOSITORY_TOOL_HARD_MAX_TREE_DEPTH),
        ),
        (
            RepositoryLimitKindV2::TreeEntries,
            u64::from(bounds.max_tree_entries),
            u64::from(REPOSITORY_TOOL_HARD_MAX_TREE_ENTRIES),
        ),
        (
            RepositoryLimitKindV2::DirectoryEntriesScanned,
            u64::from(bounds.max_directory_entries_scanned),
            u64::from(REPOSITORY_TOOL_HARD_MAX_DIRECTORY_ENTRIES_SCANNED),
        ),
        (
            RepositoryLimitKindV2::DirectoryNameBytesScanned,
            bounds.max_directory_name_bytes_scanned,
            REPOSITORY_TOOL_HARD_MAX_DIRECTORY_NAME_BYTES_SCANNED,
        ),
        (
            RepositoryLimitKindV2::SearchPatternBytes,
            bounds.max_search_pattern_bytes,
            REPOSITORY_TOOL_HARD_MAX_SEARCH_PATTERN_BYTES,
        ),
        (
            RepositoryLimitKindV2::SearchDepth,
            u64::from(bounds.max_search_depth),
            u64::from(REPOSITORY_TOOL_HARD_MAX_SEARCH_DEPTH),
        ),
        (
            RepositoryLimitKindV2::SearchFiles,
            u64::from(bounds.max_search_files),
            u64::from(REPOSITORY_TOOL_HARD_MAX_SEARCH_FILES),
        ),
        (
            RepositoryLimitKindV2::SearchMatches,
            u64::from(bounds.max_search_matches),
            u64::from(REPOSITORY_TOOL_HARD_MAX_SEARCH_MATCHES),
        ),
        (
            RepositoryLimitKindV2::SearchBytesPerFile,
            bounds.max_search_bytes_per_file,
            REPOSITORY_TOOL_HARD_MAX_SEARCH_BYTES_PER_FILE,
        ),
        (
            RepositoryLimitKindV2::SearchTotalBytes,
            bounds.max_search_total_bytes,
            REPOSITORY_TOOL_HARD_MAX_SEARCH_TOTAL_BYTES,
        ),
        (
            RepositoryLimitKindV2::ArtifactBytes,
            bounds.max_artifact_bytes,
            REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES,
        ),
    ];
    for (limit, value, hard_maximum) in limits {
        if value == 0 || value > hard_maximum {
            return Err(BrokerOpenError::InvalidAuthorityBound {
                limit,
                value,
                hard_maximum,
            });
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "every canonical Prepared parameter, authority decision and artifact binding is explicit"
)]
fn decode_exact_prepared_parameters(
    prepared: &PreparedRepositoryToolCallV2,
) -> Result<birdcode_protocol::RepositoryToolCanonicalParametersV1, RepositoryBrokerErrorV2> {
    if !prepared.canonical_parameters.is_exact()
        || prepared.canonical_parameters.artifact.media_type
            != REPOSITORY_TOOL_CANONICAL_PARAMETERS_V2_MEDIA_TYPE
    {
        return Err(RepositoryBrokerErrorV2::ArtifactBindingMismatch {
            artifact: "canonical parameters",
        });
    }
    if prepared.canonical_parameters.artifact.size_bytes > REPOSITORY_TOOL_HARD_MAX_REQUEST_BYTES {
        return Err(RepositoryBrokerErrorV2::CanonicalParametersTooLarge {
            actual: prepared.canonical_parameters.artifact.size_bytes,
            maximum: REPOSITORY_TOOL_HARD_MAX_REQUEST_BYTES,
        });
    }
    if !prepared.prepared_receipt.is_exact()
        || prepared.prepared_receipt.artifact.media_type
            != REPOSITORY_TOOL_PREPARED_RECEIPT_V2_MEDIA_TYPE
    {
        return Err(RepositoryBrokerErrorV2::ArtifactBindingMismatch {
            artifact: "prepared receipt",
        });
    }
    check_prepared_receipt_size(&prepared.prepared_receipt.bytes)?;
    let parameters =
        serde_json::from_slice::<birdcode_protocol::RepositoryToolCanonicalParametersV1>(
            &prepared.canonical_parameters.bytes,
        )
        .map_err(|_| RepositoryBrokerErrorV2::PreparedSubstitution)?;
    if canonical_json(&parameters, "canonical parameters")? != prepared.canonical_parameters.bytes
        || parameters.schema_version != REPOSITORY_BROKER_CONTRACT_VERSION
        || prepared.receipt.schema_version != REPOSITORY_BROKER_CONTRACT_VERSION
        || prepared.receipt.binding != parameters.binding
        || prepared.receipt.tool_call_id != parameters.tool_call_id
        || prepared.receipt.tool_ordinal != parameters.tool_ordinal
        || prepared.receipt.action_binding != parameters.action_binding
        || prepared.receipt.operation != parameters.operation
        || prepared.receipt.canonical_parameters_artifact != prepared.canonical_parameters.artifact
        || prepared.receipt.canonical_parameters_digest
            != digest(&prepared.canonical_parameters.bytes)
        || prepared.receipt.authorization
            != evaluate_repository_tool_authorization_v1(
                &prepared.receipt.authority.broker_bounds,
                &prepared.receipt.authority.tool_grants,
                &parameters,
                prepared.canonical_parameters.artifact.size_bytes,
                prepared.receipt.broker_call_sequence,
            )
        || canonical_json(&prepared.receipt, "prepared receipt")? != prepared.prepared_receipt.bytes
    {
        return Err(RepositoryBrokerErrorV2::PreparedSubstitution);
    }
    Ok(parameters)
}

fn cleanup_for_effect(effect: RepositoryFilesystemEffectV1) -> RepositoryCleanupReportV2 {
    match effect {
        RepositoryFilesystemEffectV1::NoFilesystemAccessAttempted => {
            RepositoryCleanupReportV2::Completed {
                disposition: RepositoryCleanupDispositionV1::NoPersistentResourcesCreated,
                persistent_resources_created: 0,
                temporary_resources_created: 0,
            }
        }
        RepositoryFilesystemEffectV1::ReadOnlyFilesystemAccessAttempted => {
            RepositoryCleanupReportV2::Completed {
                disposition:
                    RepositoryCleanupDispositionV1::TransientDescriptorsClosedByOwnershipScope,
                persistent_resources_created: 0,
                temporary_resources_created: 0,
            }
        }
        RepositoryFilesystemEffectV1::Indeterminate => RepositoryCleanupReportV2::Indeterminate {
            recovery: RepositoryCleanupRecoveryV1::RuntimeReconciliationRequired,
            recovery_evidence: None,
        },
    }
}

fn validate_interruption_metadata(
    boundary: RepositoryInterruptionBoundaryV1,
    cancellation: Option<&birdcode_protocol::ChildCancellationCauseV1>,
) -> Result<(), RepositoryBrokerErrorV2> {
    if matches!(boundary, RepositoryInterruptionBoundaryV1::Cancellation) != cancellation.is_some()
    {
        return Err(RepositoryBrokerErrorV2::InvalidInterruptionMetadata);
    }
    Ok(())
}

fn projected_interruption_boundary(
    reason: ChildToolUnknownReason,
    boundary: ChildToolUnknownBoundary,
) -> Option<RepositoryInterruptionBoundaryV1> {
    match (reason, boundary) {
        (
            ChildToolUnknownReason::RuntimeRestartedBeforeObservation,
            ChildToolUnknownBoundary::Restart,
        ) => Some(RepositoryInterruptionBoundaryV1::RuntimeRestart),
        (
            ChildToolUnknownReason::RuntimeRestartedBeforeObservation,
            ChildToolUnknownBoundary::Shutdown,
        ) => Some(RepositoryInterruptionBoundaryV1::RuntimeShutdown),
        (
            ChildToolUnknownReason::ClaimExpiredBeforeObservation,
            ChildToolUnknownBoundary::ClaimRenewalFailed | ChildToolUnknownBoundary::Deadline,
        ) => Some(RepositoryInterruptionBoundaryV1::Deadline),
        (
            ChildToolUnknownReason::EvidenceCommitIndeterminate,
            ChildToolUnknownBoundary::Shutdown | ChildToolUnknownBoundary::Deadline,
        ) => Some(RepositoryInterruptionBoundaryV1::EvidenceCommitIndeterminate),
        (
            ChildToolUnknownReason::ExecutionCancelledBeforeObservation,
            ChildToolUnknownBoundary::Cancelled,
        ) => Some(RepositoryInterruptionBoundaryV1::Cancellation),
        _ => None,
    }
}

fn canonical_json<T: Serialize>(
    value: &T,
    artifact: &'static str,
) -> Result<Vec<u8>, RepositoryBrokerErrorV2> {
    serde_json::to_vec(value).map_err(|_| RepositoryBrokerErrorV2::CanonicalEncoding { artifact })
}

fn retained_protocol_evidence(
    media_type: &str,
    encoded: Result<Vec<u8>, RepositoryToolEvidenceCodecErrorV2>,
    artifact: &'static str,
) -> Result<RetainedArtifactV2, RepositoryBrokerErrorV2> {
    match encoded {
        Ok(bytes) => Ok(RetainedArtifactV2::from_bytes(media_type, bytes)),
        Err(RepositoryToolEvidenceCodecErrorV2::ArtifactTooLarge { actual, maximum }) => {
            Err(RepositoryBrokerErrorV2::TerminalReceiptTooLarge { actual, maximum })
        }
        Err(
            RepositoryToolEvidenceCodecErrorV2::CanonicalEncoding
            | RepositoryToolEvidenceCodecErrorV2::NonCanonicalEncoding,
        ) => Err(RepositoryBrokerErrorV2::CanonicalEncoding { artifact }),
    }
}

fn retained_terminal<T: Serialize>(
    media_type: &str,
    value: &T,
    artifact: &'static str,
) -> Result<RetainedArtifactV2, RepositoryBrokerErrorV2> {
    let bytes = canonical_json(value, artifact)?;
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES {
        return Err(RepositoryBrokerErrorV2::TerminalReceiptTooLarge {
            actual,
            maximum: REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES,
        });
    }
    Ok(RetainedArtifactV2::from_bytes(media_type, bytes))
}

fn check_prepared_receipt_size(bytes: &[u8]) -> Result<(), RepositoryBrokerErrorV2> {
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES {
        return Err(RepositoryBrokerErrorV2::PreparedReceiptTooLarge {
            actual,
            maximum: REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES,
        });
    }
    Ok(())
}

fn duration_ns(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn path_has_prefix_with_depth(
    path: &birdcode_protocol::RepositoryRelativePathV1,
    prefix: &birdcode_protocol::RepositoryRelativePathV1,
    max_depth: u32,
) -> bool {
    let path = path.unix_components();
    let prefix = prefix.unix_components();
    path.starts_with(prefix)
        && path.len() > prefix.len()
        && path.len().saturating_sub(prefix.len())
            <= usize::try_from(max_depth).unwrap_or(usize::MAX)
}

#[allow(
    clippy::too_many_lines,
    reason = "closed per-operation coherence checks are intentionally explicit"
)]
fn result_is_coherent(
    operation: &ChildToolOperation,
    result: &RepositoryToolResultV2,
    bounds: &RepositoryToolBoundsV1,
) -> bool {
    if !result.mechanically_matches_operation(operation) {
        return false;
    }
    match (operation, result) {
        (
            ChildToolOperation::RepositoryTree {
                path,
                max_depth,
                max_entries,
            },
            RepositoryToolResultV2::RepositoryTree(result),
        ) => {
            result.entries.len() <= usize::try_from(*max_entries).unwrap_or(usize::MAX)
                && result.directory_entries_scanned
                    <= u64::from(bounds.max_directory_entries_scanned)
                && result.directory_name_bytes_scanned <= bounds.max_directory_name_bytes_scanned
                && result
                    .entries
                    .windows(2)
                    .all(|pair| pair[0].path < pair[1].path)
                && result.entries.iter().all(|entry| {
                    path_has_prefix_with_depth(&entry.path, path, *max_depth)
                        && match entry.kind {
                            birdcode_protocol::RepositoryNodeKindV1::RegularFile => {
                                entry.byte_len.is_some()
                            }
                            _ => entry.byte_len.is_none(),
                        }
                })
        }
        (
            ChildToolOperation::RepositoryFileRead {
                offset_bytes,
                max_bytes,
                ..
            },
            RepositoryToolResultV2::RepositoryFileRead(result),
        ) => {
            let bytes = u64::try_from(result.bytes.len()).unwrap_or(u64::MAX);
            result.offset_bytes == *offset_bytes
                && result.offset_bytes <= result.file_byte_len
                && bytes <= *max_bytes
                && result.offset_bytes.saturating_add(bytes) <= result.file_byte_len
                && result.truncated
                    == (result.offset_bytes.saturating_add(bytes) < result.file_byte_len)
        }
        (
            ChildToolOperation::LiteralSearch {
                path,
                literal_utf8,
                max_depth,
                max_files,
                max_matches,
                max_bytes_per_file,
                max_total_bytes,
            },
            RepositoryToolResultV2::LiteralSearch(result),
        ) => {
            let scan_bytes = result
                .file_scans
                .iter()
                .try_fold(0_u64, |total, scan| total.checked_add(scan.bytes_scanned));
            result.file_scans.len() <= usize::try_from(*max_files).unwrap_or(usize::MAX)
                && result.matches.len() <= usize::try_from(*max_matches).unwrap_or(usize::MAX)
                && result.files_scanned
                    == u64::try_from(result.file_scans.len()).unwrap_or(u64::MAX)
                && scan_bytes == Some(result.bytes_scanned)
                && result.bytes_scanned <= *max_total_bytes
                && result.directory_entries_scanned
                    <= u64::from(bounds.max_directory_entries_scanned)
                && result.directory_name_bytes_scanned <= bounds.max_directory_name_bytes_scanned
                && result
                    .file_scans
                    .windows(2)
                    .all(|pair| pair[0].path < pair[1].path)
                && result.file_scans.iter().all(|scan| {
                    path_has_prefix_with_depth(&scan.path, path, *max_depth)
                        && scan.bytes_scanned <= *max_bytes_per_file
                        && scan.bytes_scanned <= scan.file_byte_len
                        && scan.truncated == (scan.bytes_scanned < scan.file_byte_len)
                })
                && result.matches.windows(2).all(|pair| {
                    pair[0].path < pair[1].path
                        || (pair[0].path == pair[1].path
                            && pair[0].byte_offset < pair[1].byte_offset)
                })
                && result.matches.iter().all(|matched| {
                    result
                        .file_scans
                        .iter()
                        .find(|scan| scan.path == matched.path)
                        .is_some_and(|scan| {
                            matched
                                .byte_offset
                                .checked_add(u64::try_from(literal_utf8.len()).unwrap_or(u64::MAX))
                                .is_some_and(|end| end <= scan.bytes_scanned)
                        })
                })
        }
        _ => false,
    }
}

/// Builds the exact durable pre-effect event projection from a canonical
/// Prepared bundle. The caller must persist both retained artifacts before it
/// appends this value to Store.
///
/// # Errors
///
/// Rejects any mutated, noncanonical or incorrectly bound Prepared artifact.
pub fn project_prepared_event_v2(
    prepared: &PreparedRepositoryToolCallV2,
) -> Result<ChildToolPreparedV2, RepositoryBrokerErrorV2> {
    decode_exact_prepared_parameters(prepared)?;
    Ok(ChildToolPreparedV2 {
        binding: prepared.receipt.binding.clone(),
        tool_call_id: prepared.receipt.tool_call_id,
        tool_ordinal: prepared.receipt.tool_ordinal,
        action_binding: prepared.receipt.action_binding.clone(),
        operation: prepared.receipt.operation.clone(),
        authorization: prepared.receipt.authorization.clone(),
        broker_instance_id: prepared.receipt.broker_prepared_at.broker_instance_id,
        broker_call_sequence: prepared.receipt.broker_call_sequence,
        prepared_receipt_artifact: prepared.prepared_receipt.artifact.clone(),
        prepared_receipt_digest: digest(&prepared.prepared_receipt.bytes),
        prepared_at: prepared.receipt.runtime_prepared_at.clone(),
    })
}

/// Builds the exact durable known-terminal event projection after validating
/// every terminal, evidence and Prepared binding.
///
/// # Errors
///
/// Rejects any mutated or incoherent broker output.
pub fn project_observed_event_v2(
    prepared: &PreparedRepositoryToolCallV2,
    observed: &ObservedRepositoryToolCallV2,
) -> Result<ChildToolObservedV2, RepositoryBrokerErrorV2> {
    if !verify_terminal_output_v2(
        prepared,
        &RepositoryToolTerminalV2::Observed(observed.clone()),
    ) {
        return Err(RepositoryBrokerErrorV2::InvalidDurableProjection);
    }
    Ok(ChildToolObservedV2 {
        binding: observed.receipt.binding.clone(),
        tool_call_id: observed.receipt.tool_call_id,
        prepared_event_id: observed.receipt.prepared_event_id,
        action_binding: observed.receipt.action_binding.clone(),
        prepared_receipt_digest: observed.receipt.prepared_receipt_digest.clone(),
        terminal_receipt_artifact: observed.terminal_receipt.artifact.clone(),
        terminal_receipt_digest: digest(&observed.terminal_receipt.bytes),
        finished_at: observed.receipt.runtime_finished_at.clone(),
        terminal: observed.receipt.terminal.clone(),
    })
}

/// Builds the exact durable unknowable-terminal event projection. The daemon
/// supplies Protocol's typed lifecycle reason and boundary; Tooling checks the
/// closed mapping mechanically and never derives either value from prose.
///
/// # Errors
///
/// Rejects mutated broker output, an invalid typed reason/boundary pair, or a
/// pair that does not exactly map to the broker receipt boundary.
pub fn project_unknown_event_v2(
    prepared: &PreparedRepositoryToolCallV2,
    unknown: &UnknownRepositoryToolCallV2,
    reason: ChildToolUnknownReason,
    boundary: ChildToolUnknownBoundary,
) -> Result<ChildToolOutcomeUnknownV2, RepositoryBrokerErrorV2> {
    if !verify_terminal_output_v2(
        prepared,
        &RepositoryToolTerminalV2::Unknown(unknown.clone()),
    ) {
        return Err(RepositoryBrokerErrorV2::InvalidDurableProjection);
    }
    if projected_interruption_boundary(reason, boundary) != Some(unknown.receipt.boundary)
        || matches!(boundary, ChildToolUnknownBoundary::Cancelled)
            != unknown.receipt.cancellation.is_some()
    {
        return Err(RepositoryBrokerErrorV2::UnknownProjectionMismatch);
    }
    Ok(ChildToolOutcomeUnknownV2 {
        binding: unknown.receipt.binding.clone(),
        tool_call_id: unknown.receipt.tool_call_id,
        prepared_event_id: unknown.receipt.prepared_event_id,
        action_binding: unknown.receipt.action_binding.clone(),
        prepared_receipt_digest: unknown.receipt.prepared_receipt_digest.clone(),
        terminal_receipt_artifact: unknown.terminal_receipt.artifact.clone(),
        terminal_receipt_digest: digest(&unknown.terminal_receipt.bytes),
        boundary_at: unknown.receipt.runtime_boundary_at.clone(),
        reason,
        boundary,
        cancellation: unknown.receipt.cancellation,
        timing: unknown.receipt.timing,
    })
}

/// Verifies every exact artifact binding in a broker output and checks that a
/// successful result decodes through Protocol's canonical v2 codec and remains
/// coherent with the exact Prepared operation. This is intended for daemon and
/// Store integration tests; it does not replace Store's causal validation.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the verifier checks each closed Protocol terminal branch and typed evidence codec"
)]
pub fn verify_terminal_output_v2(
    prepared: &PreparedRepositoryToolCallV2,
    terminal: &RepositoryToolTerminalV2,
) -> bool {
    if decode_exact_prepared_parameters(prepared).is_err() {
        return false;
    }
    match terminal {
        RepositoryToolTerminalV2::Observed(observed) => {
            if !observed.terminal_receipt.is_exact()
                || observed.receipt.schema_version != REPOSITORY_BROKER_CONTRACT_VERSION
                || observed.receipt.binding != prepared.receipt.binding
                || observed.receipt.tool_call_id != prepared.receipt.tool_call_id
                || observed.receipt.action_binding != prepared.receipt.action_binding
                || observed.terminal_receipt.artifact.media_type
                    != REPOSITORY_TOOL_OBSERVED_RECEIPT_V2_MEDIA_TYPE
                || observed.terminal_receipt.bytes
                    != serde_json::to_vec(&observed.receipt).unwrap_or_default()
                || observed.terminal_receipt.artifact.size_bytes
                    > REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES
                || observed.receipt.prepared_receipt_artifact != prepared.prepared_receipt.artifact
                || observed.receipt.prepared_receipt_digest
                    != digest(&prepared.prepared_receipt.bytes)
                || observed.receipt.broker_completed_at.broker_instance_id
                    != prepared.receipt.broker_prepared_at.broker_instance_id
                || observed.receipt.elapsed_nanoseconds
                    != observed
                        .receipt
                        .broker_completed_at
                        .monotonic_nanos
                        .saturating_sub(prepared.receipt.broker_prepared_at.monotonic_nanos)
                || observed.receipt.cleanup != cleanup_for_effect(observed.receipt.effect)
                || observed.supporting_artifacts.len() != 1
                || observed
                    .supporting_artifacts
                    .iter()
                    .any(|artifact| !artifact.is_exact())
            {
                return false;
            }
            match &observed.receipt.terminal {
                RepositoryToolObservedTerminalV2::Succeeded { result_artifact } => {
                    observed.receipt.effect
                        == RepositoryFilesystemEffectV1::ReadOnlyFilesystemAccessAttempted
                        && result_artifact.media_type == REPOSITORY_TOOL_RESULT_V2_MEDIA_TYPE
                        && observed
                            .supporting_artifacts
                            .iter()
                            .find(|artifact| artifact.artifact == *result_artifact)
                            .and_then(|artifact| {
                                birdcode_protocol::decode_repository_tool_result_v2(&artifact.bytes)
                                    .ok()
                            })
                            .is_some_and(|result| {
                                result_is_coherent(
                                    &prepared.receipt.operation,
                                    &result,
                                    &prepared.receipt.authority.broker_bounds,
                                )
                            })
                }
                RepositoryToolObservedTerminalV2::Failed {
                    evidence_artifact,
                    failure,
                    ..
                } => observed
                    .supporting_artifacts
                    .iter()
                    .find(|artifact| artifact.artifact == *evidence_artifact)
                    .is_some_and(|artifact| {
                        observed.receipt.effect
                            == RepositoryFilesystemEffectV1::ReadOnlyFilesystemAccessAttempted
                            && artifact.artifact.media_type
                                == REPOSITORY_TOOL_FAILURE_EVIDENCE_V2_MEDIA_TYPE
                            && decode_repository_tool_failure_evidence_v2(&artifact.bytes)
                                .is_ok_and(|evidence| {
                                    evidence.call_id == prepared.receipt.tool_call_id
                                        && evidence.failure == *failure
                                        && evidence.effect == observed.receipt.effect
                                })
                    }),
                RepositoryToolObservedTerminalV2::AuthorizationDenied {
                    evidence_artifact,
                    denial,
                } => observed
                    .supporting_artifacts
                    .iter()
                    .find(|artifact| artifact.artifact == *evidence_artifact)
                    .is_some_and(|artifact| {
                        observed.receipt.effect
                            == RepositoryFilesystemEffectV1::NoFilesystemAccessAttempted
                            && artifact.artifact.media_type
                                == REPOSITORY_TOOL_DENIAL_EVIDENCE_V2_MEDIA_TYPE
                            && decode_repository_tool_denial_evidence_v2(&artifact.bytes).is_ok_and(
                                |evidence| {
                                    evidence.call_id == prepared.receipt.tool_call_id
                                        && evidence.denial == *denial
                                        && evidence.effect == observed.receipt.effect
                                },
                            )
                    }),
            }
        }
        RepositoryToolTerminalV2::Unknown(unknown) => {
            unknown.terminal_receipt.is_exact()
                && unknown.receipt.schema_version == REPOSITORY_BROKER_CONTRACT_VERSION
                && unknown.receipt.binding == prepared.receipt.binding
                && unknown.receipt.tool_call_id == prepared.receipt.tool_call_id
                && unknown.receipt.action_binding == prepared.receipt.action_binding
                && unknown.terminal_receipt.artifact.media_type
                    == REPOSITORY_TOOL_UNKNOWN_RECEIPT_V2_MEDIA_TYPE
                && unknown.terminal_receipt.bytes
                    == serde_json::to_vec(&unknown.receipt).unwrap_or_default()
                && unknown.terminal_receipt.artifact.size_bytes
                    <= REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES
                && unknown.receipt.prepared_receipt_artifact == prepared.prepared_receipt.artifact
                && unknown.receipt.prepared_receipt_digest
                    == digest(&prepared.prepared_receipt.bytes)
                && unknown.receipt.cleanup == cleanup_for_effect(unknown.receipt.effect)
                && match unknown.receipt.timing {
                    RepositoryToolUnknownTimingV2::BrokerRecorded {
                        recorded_at,
                        elapsed_nanoseconds,
                    } => {
                        unknown.receipt.effect
                            == RepositoryFilesystemEffectV1::NoFilesystemAccessAttempted
                            && recorded_at.broker_instance_id
                                == prepared.receipt.broker_prepared_at.broker_instance_id
                            && elapsed_nanoseconds
                                == recorded_at.monotonic_nanos.saturating_sub(
                                    prepared.receipt.broker_prepared_at.monotonic_nanos,
                                )
                    }
                    RepositoryToolUnknownTimingV2::RuntimeReconciled {
                        abandoned_broker_instance_id,
                    } => {
                        unknown.receipt.effect == RepositoryFilesystemEffectV1::Indeterminate
                            && abandoned_broker_instance_id
                                == prepared.receipt.broker_prepared_at.broker_instance_id
                    }
                }
                && unknown.supporting_artifacts.len() == 1
                && unknown
                    .supporting_artifacts
                    .iter()
                    .all(RetainedArtifactV2::is_exact)
                && unknown
                    .supporting_artifacts
                    .iter()
                    .find(|artifact| artifact.artifact == unknown.receipt.unknown_evidence_artifact)
                    .is_some_and(|artifact| {
                        artifact.artifact.media_type
                            == REPOSITORY_TOOL_UNKNOWN_EVIDENCE_V2_MEDIA_TYPE
                            && decode_repository_tool_unknown_evidence_v2(&artifact.bytes)
                                .is_ok_and(|evidence| {
                                    evidence.call_id == prepared.receipt.tool_call_id
                                        && evidence.boundary == unknown.receipt.boundary
                                        && evidence.effect == unknown.receipt.effect
                                })
                    })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{RepositoryBrokerErrorV2, next_broker_call_sequence, retained_terminal};
    use birdcode_protocol::REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES;

    #[test]
    fn broker_sequence_increment_is_checked_and_never_saturates() {
        assert_eq!(next_broker_call_sequence(u64::MAX - 1), Some(u64::MAX));
        assert_eq!(next_broker_call_sequence(u64::MAX), None);
    }

    #[test]
    fn oversized_terminal_fails_closed() {
        let value = "x".repeat(
            usize::try_from(REPOSITORY_TOOL_HARD_MAX_TERMINAL_RECEIPT_BYTES)
                .expect("terminal ceiling fits usize"),
        );
        assert!(matches!(
            retained_terminal("application/json", &value, "test terminal"),
            Err(RepositoryBrokerErrorV2::TerminalReceiptTooLarge { .. })
        ));
    }
}
