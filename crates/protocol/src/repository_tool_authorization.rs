use super::{
    ChildToolOperation, REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES,
    REPOSITORY_TOOL_HARD_MAX_CALLS_PER_BROKER, REPOSITORY_TOOL_HARD_MAX_COMPONENT_BYTES,
    REPOSITORY_TOOL_HARD_MAX_PATH_BYTES, REPOSITORY_TOOL_HARD_MAX_PATH_COMPONENTS,
    REPOSITORY_TOOL_HARD_MAX_READ_BYTES, REPOSITORY_TOOL_HARD_MAX_REQUEST_BYTES,
    REPOSITORY_TOOL_HARD_MAX_SEARCH_BYTES_PER_FILE, REPOSITORY_TOOL_HARD_MAX_SEARCH_DEPTH,
    REPOSITORY_TOOL_HARD_MAX_SEARCH_FILES, REPOSITORY_TOOL_HARD_MAX_SEARCH_MATCHES,
    REPOSITORY_TOOL_HARD_MAX_SEARCH_PATTERN_BYTES, REPOSITORY_TOOL_HARD_MAX_SEARCH_TOTAL_BYTES,
    REPOSITORY_TOOL_HARD_MAX_TREE_DEPTH, REPOSITORY_TOOL_HARD_MAX_TREE_ENTRIES,
    RepositoryLimitKindV2, RepositoryPathViolationV1, RepositoryRelativePathV1,
    RepositoryToolAuthorizationDecisionV2, RepositoryToolBoundsV1,
    RepositoryToolCanonicalParametersV1, RepositoryToolGrantV1, RepositoryToolPreparationDenialV2,
    repository_tool_result_v2_preflight_size,
};

pub(super) fn repository_tool_denied_v2(
    denial: RepositoryToolPreparationDenialV2,
) -> RepositoryToolAuthorizationDecisionV2 {
    RepositoryToolAuthorizationDecisionV2::Denied { denial }
}

fn repository_tool_limit_v2(
    limit: RepositoryLimitKindV2,
    requested: u64,
    maximum: u64,
    positive: bool,
) -> Option<RepositoryToolAuthorizationDecisionV2> {
    if positive && requested == 0 {
        Some(repository_tool_denied_v2(
            RepositoryToolPreparationDenialV2::LimitMustBePositive { limit },
        ))
    } else if requested > maximum {
        Some(repository_tool_denied_v2(
            RepositoryToolPreparationDenialV2::LimitExceeded {
                limit,
                requested,
                maximum,
            },
        ))
    } else {
        None
    }
}

fn repository_tool_path_decision_v2(
    path: &RepositoryRelativePathV1,
    require_file: bool,
    max_components: u32,
    max_path_bytes: u64,
    max_component_bytes: u64,
) -> Option<RepositoryToolAuthorizationDecisionV2> {
    let components = path.unix_components();
    if require_file && components.is_empty() {
        return Some(repository_tool_denied_v2(
            RepositoryToolPreparationDenialV2::InvalidPath {
                violation: RepositoryPathViolationV1::EmptyFilePath,
                component_index: None,
            },
        ));
    }
    let component_count = u64::try_from(components.len()).unwrap_or(u64::MAX);
    if let Some(decision) = repository_tool_limit_v2(
        RepositoryLimitKindV2::PathComponents,
        component_count,
        u64::from(max_components),
        false,
    ) {
        return Some(decision);
    }
    let mut path_bytes = 0_u64;
    for (index, component) in components.iter().enumerate() {
        let violation = if component.is_empty() {
            Some(RepositoryPathViolationV1::EmptyComponent)
        } else if component.as_slice() == b"." {
            Some(RepositoryPathViolationV1::CurrentDirectoryComponent)
        } else if component.as_slice() == b".." {
            Some(RepositoryPathViolationV1::ParentTraversal)
        } else if component.contains(&b'/') {
            Some(RepositoryPathViolationV1::EmbeddedSeparator)
        } else if component.contains(&0) {
            Some(RepositoryPathViolationV1::EmbeddedNul)
        } else {
            None
        };
        if let Some(violation) = violation {
            return Some(repository_tool_denied_v2(
                RepositoryToolPreparationDenialV2::InvalidPath {
                    violation,
                    component_index: Some(u32::try_from(index).unwrap_or(u32::MAX)),
                },
            ));
        }
        let component_bytes = u64::try_from(component.len()).unwrap_or(u64::MAX);
        if let Some(decision) = repository_tool_limit_v2(
            RepositoryLimitKindV2::ComponentBytes,
            component_bytes,
            max_component_bytes,
            false,
        ) {
            return Some(decision);
        }
        path_bytes = path_bytes
            .checked_add(component_bytes)
            .and_then(|value| value.checked_add(1))
            .unwrap_or(u64::MAX);
    }
    repository_tool_limit_v2(
        RepositoryLimitKindV2::PathBytes,
        path_bytes,
        max_path_bytes,
        false,
    )
}

/// Evaluates one exact canonical repository invocation without filesystem
/// access or semantic text classification.
///
/// The denial order is part of the contract: broker call sequence, canonical
/// request bytes, missing tool kind, mismatched/duplicate grant identity,
/// then path checks. Path checks are `EmptyFilePath`, component count, and for
/// each component in wire order: empty, `.`, `..`, slash, NUL, component byte
/// ceiling; aggregate path bytes are last. Operation fields then follow their
/// serialized order. A worst-width empty successful result envelope is checked
/// last so an authorized call can always produce an in-budget typed result.
/// Every maximum is the narrowest of hard, broker and exact grant ceilings.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the closed operation match makes the authorization precedence directly auditable"
)]
pub fn evaluate_repository_tool_authorization_v1(
    bounds: &RepositoryToolBoundsV1,
    grants: &[RepositoryToolGrantV1],
    parameters: &RepositoryToolCanonicalParametersV1,
    canonical_parameters_size_bytes: u64,
    broker_call_sequence: u64,
) -> RepositoryToolAuthorizationDecisionV2 {
    if let Some(decision) = repository_tool_limit_v2(
        RepositoryLimitKindV2::BrokerCalls,
        broker_call_sequence,
        bounds
            .max_calls_per_broker
            .min(REPOSITORY_TOOL_HARD_MAX_CALLS_PER_BROKER),
        true,
    ) {
        return decision;
    }
    if let Some(decision) = repository_tool_limit_v2(
        RepositoryLimitKindV2::RequestBytes,
        canonical_parameters_size_bytes,
        bounds
            .max_request_bytes
            .min(REPOSITORY_TOOL_HARD_MAX_REQUEST_BYTES),
        true,
    ) {
        return decision;
    }

    let tool = parameters.operation.kind();
    if !grants.iter().any(|grant| grant.kind() == tool) {
        return repository_tool_denied_v2(RepositoryToolPreparationDenialV2::ToolNotGranted {
            tool,
        });
    }
    // Grant identities form one globally unique authority namespace. A
    // duplicate sibling identity invalidates the complete authority list even
    // when the requested identity itself occurs only once; selecting around a
    // malformed sibling list would make authorization depend on list pruning.
    for (index, grant) in grants.iter().enumerate() {
        if grants[..index]
            .iter()
            .any(|prior| prior.tool_grant_id() == grant.tool_grant_id())
        {
            return repository_tool_denied_v2(
                RepositoryToolPreparationDenialV2::GrantIdentityMismatch,
            );
        }
    }
    let Some(grant) = grants
        .iter()
        .find(|grant| grant.tool_grant_id() == parameters.tool_grant_id)
    else {
        return repository_tool_denied_v2(RepositoryToolPreparationDenialV2::GrantIdentityMismatch);
    };
    if grant.kind() != tool {
        return repository_tool_denied_v2(RepositoryToolPreparationDenialV2::GrantIdentityMismatch);
    }

    match (&parameters.operation, grant.clone()) {
        (
            ChildToolOperation::RepositoryTree {
                path,
                max_depth,
                max_entries,
            },
            RepositoryToolGrantV1::RepositoryTree {
                max_path_components,
                max_path_bytes,
                max_component_bytes,
                max_depth: grant_depth,
                max_entries: grant_entries,
                ..
            },
        ) => {
            if let Some(decision) = repository_tool_path_decision_v2(
                path,
                false,
                bounds
                    .max_path_components
                    .min(max_path_components)
                    .min(REPOSITORY_TOOL_HARD_MAX_PATH_COMPONENTS),
                bounds
                    .max_path_bytes
                    .min(max_path_bytes)
                    .min(REPOSITORY_TOOL_HARD_MAX_PATH_BYTES),
                bounds
                    .max_component_bytes
                    .min(max_component_bytes)
                    .min(REPOSITORY_TOOL_HARD_MAX_COMPONENT_BYTES),
            ) {
                return decision;
            }
            if let Some(decision) = repository_tool_limit_v2(
                RepositoryLimitKindV2::TreeDepth,
                u64::from(*max_depth),
                u64::from(
                    bounds
                        .max_tree_depth
                        .min(grant_depth)
                        .min(REPOSITORY_TOOL_HARD_MAX_TREE_DEPTH),
                ),
                false,
            ) {
                return decision;
            }
            if let Some(decision) = repository_tool_limit_v2(
                RepositoryLimitKindV2::TreeEntries,
                u64::from(*max_entries),
                u64::from(
                    bounds
                        .max_tree_entries
                        .min(grant_entries)
                        .min(REPOSITORY_TOOL_HARD_MAX_TREE_ENTRIES),
                ),
                true,
            ) {
                return decision;
            }
        }
        (
            ChildToolOperation::RepositoryFileRead {
                path,
                offset_bytes,
                max_bytes,
            },
            RepositoryToolGrantV1::RepositoryFileRead {
                max_path_components,
                max_path_bytes,
                max_component_bytes,
                max_offset_bytes,
                max_bytes: grant_bytes,
                ..
            },
        ) => {
            if let Some(decision) = repository_tool_path_decision_v2(
                path,
                true,
                bounds
                    .max_path_components
                    .min(max_path_components)
                    .min(REPOSITORY_TOOL_HARD_MAX_PATH_COMPONENTS),
                bounds
                    .max_path_bytes
                    .min(max_path_bytes)
                    .min(REPOSITORY_TOOL_HARD_MAX_PATH_BYTES),
                bounds
                    .max_component_bytes
                    .min(max_component_bytes)
                    .min(REPOSITORY_TOOL_HARD_MAX_COMPONENT_BYTES),
            ) {
                return decision;
            }
            if let Some(decision) = repository_tool_limit_v2(
                RepositoryLimitKindV2::ReadOffsetBytes,
                *offset_bytes,
                max_offset_bytes,
                false,
            ) {
                return decision;
            }
            if let Some(decision) = repository_tool_limit_v2(
                RepositoryLimitKindV2::ReadBytes,
                *max_bytes,
                bounds
                    .max_read_bytes
                    .min(grant_bytes)
                    .min(REPOSITORY_TOOL_HARD_MAX_READ_BYTES),
                true,
            ) {
                return decision;
            }
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
            RepositoryToolGrantV1::LiteralSearch {
                max_path_components,
                max_path_bytes,
                max_component_bytes,
                max_literal_bytes,
                max_depth: grant_depth,
                max_files: grant_files,
                max_matches: grant_matches,
                max_bytes_per_file: grant_bytes_per_file,
                max_total_bytes: grant_total_bytes,
                ..
            },
        ) => {
            if let Some(decision) = repository_tool_path_decision_v2(
                path,
                false,
                bounds
                    .max_path_components
                    .min(max_path_components)
                    .min(REPOSITORY_TOOL_HARD_MAX_PATH_COMPONENTS),
                bounds
                    .max_path_bytes
                    .min(max_path_bytes)
                    .min(REPOSITORY_TOOL_HARD_MAX_PATH_BYTES),
                bounds
                    .max_component_bytes
                    .min(max_component_bytes)
                    .min(REPOSITORY_TOOL_HARD_MAX_COMPONENT_BYTES),
            ) {
                return decision;
            }
            if literal_utf8.is_empty() {
                return repository_tool_denied_v2(
                    RepositoryToolPreparationDenialV2::EmptyLiteralPattern,
                );
            }
            if let Some(decision) = repository_tool_limit_v2(
                RepositoryLimitKindV2::SearchPatternBytes,
                u64::try_from(literal_utf8.len()).unwrap_or(u64::MAX),
                bounds
                    .max_search_pattern_bytes
                    .min(max_literal_bytes)
                    .min(REPOSITORY_TOOL_HARD_MAX_SEARCH_PATTERN_BYTES),
                false,
            ) {
                return decision;
            }
            let ordered_fields = [
                (
                    RepositoryLimitKindV2::SearchDepth,
                    u64::from(*max_depth),
                    u64::from(
                        bounds
                            .max_search_depth
                            .min(grant_depth)
                            .min(REPOSITORY_TOOL_HARD_MAX_SEARCH_DEPTH),
                    ),
                    false,
                ),
                (
                    RepositoryLimitKindV2::SearchFiles,
                    u64::from(*max_files),
                    u64::from(
                        bounds
                            .max_search_files
                            .min(grant_files)
                            .min(REPOSITORY_TOOL_HARD_MAX_SEARCH_FILES),
                    ),
                    true,
                ),
                (
                    RepositoryLimitKindV2::SearchMatches,
                    u64::from(*max_matches),
                    u64::from(
                        bounds
                            .max_search_matches
                            .min(grant_matches)
                            .min(REPOSITORY_TOOL_HARD_MAX_SEARCH_MATCHES),
                    ),
                    true,
                ),
                (
                    RepositoryLimitKindV2::SearchBytesPerFile,
                    *max_bytes_per_file,
                    bounds
                        .max_search_bytes_per_file
                        .min(grant_bytes_per_file)
                        .min(REPOSITORY_TOOL_HARD_MAX_SEARCH_BYTES_PER_FILE),
                    true,
                ),
                (
                    RepositoryLimitKindV2::SearchTotalBytes,
                    *max_total_bytes,
                    bounds
                        .max_search_total_bytes
                        .min(grant_total_bytes)
                        .min(REPOSITORY_TOOL_HARD_MAX_SEARCH_TOTAL_BYTES),
                    true,
                ),
            ];
            for (limit, requested, maximum, positive) in ordered_fields {
                if let Some(decision) =
                    repository_tool_limit_v2(limit, requested, maximum, positive)
                {
                    return decision;
                }
            }
        }
        _ => {
            return repository_tool_denied_v2(
                RepositoryToolPreparationDenialV2::GrantIdentityMismatch,
            );
        }
    }
    if let Some(decision) = repository_tool_limit_v2(
        RepositoryLimitKindV2::ArtifactBytes,
        repository_tool_result_v2_preflight_size(&parameters.operation),
        bounds
            .max_artifact_bytes
            .min(REPOSITORY_TOOL_HARD_MAX_ARTIFACT_BYTES),
        false,
    ) {
        return decision;
    }
    RepositoryToolAuthorizationDecisionV2::Authorized
}
