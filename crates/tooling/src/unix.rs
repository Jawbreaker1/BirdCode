use birdcode_protocol::{
    ChildToolOperation, RepositoryExpectedNodeKindV1, RepositoryFileIdentityV1,
    RepositoryIoFailureKindV1, RepositoryIoOperationV1, RepositoryLimitKindV1,
    RepositoryLiteralFileScanV1, RepositoryLiteralMatchV1, RepositoryLiteralSearchResultV1,
    RepositoryNodeKindV1, RepositoryReadFileResultV2, RepositoryRelativePathV1,
    RepositoryToolBoundsV1, RepositoryToolFailureV1 as ToolFailure, RepositoryToolResultV2,
    RepositoryTreeEntryV1, RepositoryTreeResultV1, RepositoryUnixFileIdentityV1,
    repository_tool_result_v2_preflight_size,
};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, fstat, open, openat, statat};
use rustix::io::{Errno, dup};
use serde::Serialize;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::fd::OwnedFd;
use std::path::Path;

pub(crate) struct UnixFailure {
    operation: RepositoryIoOperationV1,
    pub(crate) kind: RepositoryIoFailureKindV1,
    pub(crate) raw_os_error: Option<i32>,
    boundary: Option<Box<ToolFailure>>,
}

impl UnixFailure {
    fn errno(operation: RepositoryIoOperationV1, error: Errno) -> Self {
        let kind = if error == Errno::LOOP {
            RepositoryIoFailureKindV1::SymlinkRejected
        } else if error == Errno::NOENT {
            RepositoryIoFailureKindV1::NotFound
        } else if error == Errno::ACCESS || error == Errno::PERM {
            RepositoryIoFailureKindV1::PermissionDenied
        } else if error == Errno::NOTDIR || error == Errno::ISDIR {
            RepositoryIoFailureKindV1::WrongFileType
        } else if error == Errno::INTR {
            RepositoryIoFailureKindV1::Interrupted
        } else {
            map_error_kind(error.kind())
        };
        Self {
            operation,
            kind,
            raw_os_error: Some(error.raw_os_error()),
            boundary: None,
        }
    }

    fn std_io(operation: RepositoryIoOperationV1, error: &std::io::Error) -> Self {
        Self {
            operation,
            kind: map_error_kind(error.kind()),
            raw_os_error: error.raw_os_error(),
            boundary: None,
        }
    }

    fn boundary(boundary: ToolFailure) -> Self {
        Self {
            operation: RepositoryIoOperationV1::StatDescriptor,
            kind: RepositoryIoFailureKindV1::Other,
            raw_os_error: None,
            boundary: Some(Box::new(boundary)),
        }
    }

    fn resource_exhausted(operation: RepositoryIoOperationV1) -> Self {
        Self {
            operation,
            kind: RepositoryIoFailureKindV1::ResourceExhausted,
            raw_os_error: None,
            boundary: None,
        }
    }

    pub(crate) fn into_boundary(self) -> ToolFailure {
        self.boundary.map_or_else(
            || ToolFailure::Io {
                operation: self.operation,
                kind: self.kind,
                raw_os_error: self.raw_os_error,
            },
            |boundary| *boundary,
        )
    }
}

pub(crate) fn open_root(root: &Path) -> Result<OwnedFd, UnixFailure> {
    open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| UnixFailure::errno(RepositoryIoOperationV1::OpenRoot, error))
}

pub(crate) fn descriptor_identity(fd: &OwnedFd) -> Result<RepositoryFileIdentityV1, UnixFailure> {
    fstat(fd)
        .map(identity)
        .map_err(|error| UnixFailure::errno(RepositoryIoOperationV1::StatDescriptor, error))
}

pub(crate) fn tree(
    root: &OwnedFd,
    path: &RepositoryRelativePathV1,
    max_depth: u32,
    max_entries: u32,
    bounds: &RepositoryToolBoundsV1,
) -> Result<RepositoryTreeResultV1, UnixFailure> {
    let request = TreeRequest {
        path,
        max_depth,
        max_entries,
    };
    let operation = ChildToolOperation::RepositoryTree {
        path: path.clone(),
        max_depth,
        max_entries,
    };
    let artifact_budget = CanonicalResultBudget::new(
        repository_tool_result_v2_preflight_size(&operation),
        bounds.max_artifact_bytes,
    )?;
    let root_device = unix_identity(descriptor_identity(root)?).device;
    let start = open_directory(root, request.path, root_device)?;
    let entries = Vec::new();
    let mut walker = TreeWalker {
        request: &request,
        bounds,
        entries,
        artifact_budget,
        directory_entries_scanned: 0,
        directory_name_bytes_scanned: 0,
        truncated: false,
        root_device,
    };
    walker.walk(&start, request.path, 0)?;
    Ok(RepositoryTreeResultV1 {
        entries: walker.entries,
        directory_entries_scanned: walker.directory_entries_scanned,
        directory_name_bytes_scanned: walker.directory_name_bytes_scanned,
        truncated: walker.truncated,
    })
}

pub(crate) fn read_file(
    root: &OwnedFd,
    path: &RepositoryRelativePathV1,
    offset_bytes: u64,
    max_bytes: u64,
    bounds: &RepositoryToolBoundsV1,
) -> Result<RepositoryReadFileResultV2, UnixFailure> {
    let operation = ChildToolOperation::RepositoryFileRead {
        path: path.clone(),
        offset_bytes,
        max_bytes,
    };
    CanonicalResultBudget::new(
        repository_tool_result_v2_preflight_size(&operation),
        bounds.max_artifact_bytes,
    )?;
    let root_device = unix_identity(descriptor_identity(root)?).device;
    let fd = open_file(root, path, root_device)?;
    let before_stat = fstat(&fd)
        .map_err(|error| UnixFailure::errno(RepositoryIoOperationV1::StatDescriptor, error))?;
    let before = identity(before_stat);
    ensure_same_device(root_device, unix_identity(before).device)?;
    let kind = node_kind(before_stat.st_mode);
    if kind != RepositoryNodeKindV1::RegularFile {
        return Err(UnixFailure::boundary(ToolFailure::WrongFileType {
            expected: RepositoryExpectedNodeKindV1::RegularFile,
            observed: kind,
        }));
    }
    let file_byte_len = u64::try_from(unix_identity(before).byte_len).unwrap_or(0);
    if offset_bytes > file_byte_len {
        return Err(UnixFailure::boundary(ToolFailure::InvalidReadRange {
            offset_bytes,
            file_byte_len,
        }));
    }

    let empty_result = RepositoryToolResultV2::RepositoryFileRead(RepositoryReadFileResultV2 {
        path: path.clone(),
        offset_bytes,
        bytes: Vec::new(),
        file_byte_len,
        truncated: false,
    });
    let fixed_bytes = canonical_len(&empty_result)?;
    let encoded_content_bytes = bounds.max_artifact_bytes.saturating_sub(fixed_bytes);
    let raw_content_budget = encoded_content_bytes
        .checked_div(4)
        .unwrap_or(0)
        .saturating_mul(3);
    let bytes_to_read = file_byte_len
        .saturating_sub(offset_bytes)
        .min(max_bytes)
        .min(raw_content_budget);
    let mut file = std::fs::File::from(fd);
    file.seek(SeekFrom::Start(offset_bytes))
        .map_err(|error| UnixFailure::std_io(RepositoryIoOperationV1::SeekFile, &error))?;
    let mut bytes = bounded_buffer(bytes_to_read, RepositoryIoOperationV1::ReadFile)?;
    (&mut file)
        .take(bytes_to_read)
        .read_to_end(&mut bytes)
        .map_err(|error| UnixFailure::std_io(RepositoryIoOperationV1::ReadFile, &error))?;
    let after = fstat(&file)
        .map(identity)
        .map_err(|error| UnixFailure::errno(RepositoryIoOperationV1::StatDescriptor, error))?;
    if before != after {
        return Err(UnixFailure::boundary(
            ToolFailure::NodeChangedDuringObservation { before, after },
        ));
    }
    let observed_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    Ok(RepositoryReadFileResultV2 {
        path: path.clone(),
        offset_bytes,
        bytes,
        file_byte_len,
        truncated: offset_bytes.saturating_add(observed_bytes) < file_byte_len,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the closed Protocol operation fields are passed losslessly without a duplicate request type"
)]
pub(crate) fn literal_search(
    root: &OwnedFd,
    path: &RepositoryRelativePathV1,
    literal_utf8: &str,
    max_depth: u32,
    max_files: u32,
    max_matches: u32,
    max_bytes_per_file: u64,
    max_total_bytes: u64,
    bounds: &RepositoryToolBoundsV1,
) -> Result<RepositoryLiteralSearchResultV1, UnixFailure> {
    if literal_utf8.is_empty() {
        return Err(UnixFailure::boundary(ToolFailure::EmptyLiteralPattern));
    }
    let request = LiteralSearchRequest {
        path,
        pattern: literal_utf8.as_bytes(),
        max_depth,
        max_files,
        max_matches,
        max_bytes_per_file,
        max_total_bytes,
    };
    let operation = ChildToolOperation::LiteralSearch {
        path: path.clone(),
        literal_utf8: literal_utf8.to_owned(),
        max_depth,
        max_files,
        max_matches,
        max_bytes_per_file,
        max_total_bytes,
    };
    let artifact_budget = CanonicalResultBudget::new(
        repository_tool_result_v2_preflight_size(&operation),
        bounds.max_artifact_bytes,
    )?;
    let root_device = unix_identity(descriptor_identity(root)?).device;
    let start = open_directory(root, request.path, root_device)?;
    let prefix = literal_prefix_table(request.pattern);
    let matches = Vec::new();
    let file_scans = Vec::new();
    let mut searcher = LiteralSearcher {
        request: &request,
        bounds,
        prefix: &prefix,
        matches,
        file_scans,
        artifact_budget,
        directories_scanned: 0,
        files_scanned: 0,
        bytes_scanned: 0,
        directory_entries_scanned: 0,
        directory_name_bytes_scanned: 0,
        symlinks_skipped: 0,
        special_nodes_skipped: 0,
        truncated: false,
        stopped: false,
        root_device,
    };
    searcher.walk(&start, request.path, 0)?;
    Ok(RepositoryLiteralSearchResultV1 {
        matches: searcher.matches,
        file_scans: searcher.file_scans,
        directories_scanned: searcher.directories_scanned,
        directory_entries_scanned: searcher.directory_entries_scanned,
        directory_name_bytes_scanned: searcher.directory_name_bytes_scanned,
        files_scanned: searcher.files_scanned,
        bytes_scanned: searcher.bytes_scanned,
        symlinks_skipped: searcher.symlinks_skipped,
        special_nodes_skipped: searcher.special_nodes_skipped,
        truncated: searcher.truncated,
    })
}

struct TreeRequest<'a> {
    path: &'a RepositoryRelativePathV1,
    max_depth: u32,
    max_entries: u32,
}

struct LiteralSearchRequest<'a> {
    path: &'a RepositoryRelativePathV1,
    pattern: &'a [u8],
    max_depth: u32,
    max_files: u32,
    max_matches: u32,
    max_bytes_per_file: u64,
    max_total_bytes: u64,
}

/// Additive byte accounting for the two canonical result arrays. `base_bytes`
/// is the exact tagged JSON result with empty arrays, widest counters and the
/// longer `false` spelling. Serializing each candidate exactly once gives the
/// complete result length without repeatedly serializing the growing result.
struct CanonicalResultBudget {
    ceiling: u64,
    used: u64,
    primary_items: u64,
    secondary_items: u64,
}

impl CanonicalResultBudget {
    fn new(base_bytes: u64, ceiling: u64) -> Result<Self, UnixFailure> {
        if base_bytes > ceiling {
            return Err(UnixFailure::boundary(ToolFailure::LimitExceeded {
                limit: RepositoryLimitKindV1::ArtifactBytes,
                requested: base_bytes,
                maximum: ceiling,
            }));
        }
        Ok(Self {
            ceiling,
            used: base_bytes,
            primary_items: 0,
            secondary_items: 0,
        })
    }

    fn primary_cost<T: Serialize>(&self, value: &T) -> Result<u64, UnixFailure> {
        canonical_array_item_cost(value, self.primary_items)
    }

    fn secondary_cost<T: Serialize>(&self, value: &T) -> Result<u64, UnixFailure> {
        canonical_array_item_cost(value, self.secondary_items)
    }

    fn admits(&self, cost: u64) -> bool {
        self.used
            .checked_add(cost)
            .is_some_and(|total| total <= self.ceiling)
    }

    fn commit_primary(&mut self, cost: u64) {
        self.used = self.used.saturating_add(cost);
        self.primary_items = self.primary_items.saturating_add(1);
    }

    fn commit_secondary(&mut self, cost: u64) {
        self.used = self.used.saturating_add(cost);
        self.secondary_items = self.secondary_items.saturating_add(1);
    }
}

fn canonical_len<T: Serialize>(value: &T) -> Result<u64, UnixFailure> {
    serde_json::to_vec(value)
        .map(|bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX))
        .map_err(|_| UnixFailure::boundary(ToolFailure::EvidenceEncodingFailed))
}

fn canonical_array_item_cost<T: Serialize>(
    value: &T,
    existing_items: u64,
) -> Result<u64, UnixFailure> {
    canonical_len(value).map(|length| length.saturating_add(u64::from(existing_items > 0)))
}

struct TreeWalker<'a> {
    request: &'a TreeRequest<'a>,
    bounds: &'a RepositoryToolBoundsV1,
    entries: Vec<RepositoryTreeEntryV1>,
    artifact_budget: CanonicalResultBudget,
    directory_entries_scanned: u64,
    directory_name_bytes_scanned: u64,
    truncated: bool,
    root_device: u64,
}

impl TreeWalker<'_> {
    fn walk(
        &mut self,
        directory: &OwnedFd,
        path: &RepositoryRelativePathV1,
        depth: u32,
    ) -> Result<(), UnixFailure> {
        if self.truncated || depth >= self.request.max_depth {
            return Ok(());
        }
        let before = descriptor_identity(directory)?;
        let names = directory_names(
            directory,
            &mut self.directory_entries_scanned,
            &mut self.directory_name_bytes_scanned,
            self.bounds,
        )?;
        for name in names {
            if self.entries.len() >= usize::try_from(self.request.max_entries).unwrap_or(usize::MAX)
            {
                self.truncated = true;
                break;
            }
            let stat =
                statat(directory, name.as_slice(), AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
                    UnixFailure::errno(RepositoryIoOperationV1::StatDirectoryEntry, error)
                })?;
            let kind = node_kind(stat.st_mode);
            let listed_identity = identity(stat);
            ensure_same_device(self.root_device, unix_identity(listed_identity).device)?;
            let child_path = appended_path(path, name.clone());
            ensure_discovered_path_bound(&child_path, self.bounds)?;
            let entry = RepositoryTreeEntryV1 {
                path: child_path.clone(),
                kind,
                byte_len: if kind == RepositoryNodeKindV1::RegularFile {
                    u64::try_from(stat.st_size).ok()
                } else {
                    None
                },
            };
            let entry_cost = self.artifact_budget.primary_cost(&entry)?;
            if !self.artifact_budget.admits(entry_cost) {
                self.truncated = true;
                break;
            }
            self.entries.try_reserve(1).map_err(|_| {
                UnixFailure::resource_exhausted(RepositoryIoOperationV1::ReadDirectory)
            })?;
            self.artifact_budget.commit_primary(entry_cost);
            self.entries.push(entry);
            let child_depth = depth.saturating_add(1);
            if kind == RepositoryNodeKindV1::Directory && child_depth < self.request.max_depth {
                let child = open_child_directory(directory, &name, self.root_device)?;
                let opened_identity = descriptor_identity(&child)?;
                if opened_identity != listed_identity {
                    return Err(UnixFailure::boundary(
                        ToolFailure::NodeChangedDuringObservation {
                            before: listed_identity,
                            after: opened_identity,
                        },
                    ));
                }
                self.walk(&child, &child_path, child_depth)?;
                if self.truncated {
                    break;
                }
            }
        }
        let after = descriptor_identity(directory)?;
        if before != after {
            return Err(UnixFailure::boundary(
                ToolFailure::NodeChangedDuringObservation { before, after },
            ));
        }
        Ok(())
    }
}

struct LiteralSearcher<'a> {
    request: &'a LiteralSearchRequest<'a>,
    bounds: &'a RepositoryToolBoundsV1,
    prefix: &'a [usize],
    matches: Vec<RepositoryLiteralMatchV1>,
    file_scans: Vec<RepositoryLiteralFileScanV1>,
    artifact_budget: CanonicalResultBudget,
    directories_scanned: u64,
    files_scanned: u64,
    bytes_scanned: u64,
    directory_entries_scanned: u64,
    directory_name_bytes_scanned: u64,
    symlinks_skipped: u64,
    special_nodes_skipped: u64,
    truncated: bool,
    stopped: bool,
    root_device: u64,
}

impl LiteralSearcher<'_> {
    fn walk(
        &mut self,
        directory: &OwnedFd,
        path: &RepositoryRelativePathV1,
        depth: u32,
    ) -> Result<(), UnixFailure> {
        if self.stopped || depth >= self.request.max_depth {
            return Ok(());
        }
        self.directories_scanned = self.directories_scanned.saturating_add(1);
        let before = descriptor_identity(directory)?;
        let names = directory_names(
            directory,
            &mut self.directory_entries_scanned,
            &mut self.directory_name_bytes_scanned,
            self.bounds,
        )?;
        for name in names {
            if self.stopped {
                break;
            }
            let stat =
                statat(directory, name.as_slice(), AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
                    UnixFailure::errno(RepositoryIoOperationV1::StatDirectoryEntry, error)
                })?;
            let kind = node_kind(stat.st_mode);
            let listed_identity = identity(stat);
            ensure_same_device(self.root_device, unix_identity(listed_identity).device)?;
            let child_path = appended_path(path, name.clone());
            ensure_discovered_path_bound(&child_path, self.bounds)?;
            match kind {
                RepositoryNodeKindV1::Directory
                    if depth.saturating_add(1) < self.request.max_depth =>
                {
                    let child = open_child_directory(directory, &name, self.root_device)?;
                    let opened_identity = descriptor_identity(&child)?;
                    if opened_identity != listed_identity {
                        return Err(UnixFailure::boundary(
                            ToolFailure::NodeChangedDuringObservation {
                                before: listed_identity,
                                after: opened_identity,
                            },
                        ));
                    }
                    self.walk(&child, &child_path, depth.saturating_add(1))?;
                }
                RepositoryNodeKindV1::Directory => {}
                RepositoryNodeKindV1::RegularFile => {
                    self.search_file(directory, &name, &child_path, listed_identity)?;
                }
                RepositoryNodeKindV1::Symlink => {
                    self.symlinks_skipped = self.symlinks_skipped.saturating_add(1);
                }
                RepositoryNodeKindV1::Other => {
                    self.special_nodes_skipped = self.special_nodes_skipped.saturating_add(1);
                }
            }
        }
        let after = descriptor_identity(directory)?;
        if before != after {
            return Err(UnixFailure::boundary(
                ToolFailure::NodeChangedDuringObservation { before, after },
            ));
        }
        Ok(())
    }

    fn search_file(
        &mut self,
        directory: &OwnedFd,
        name: &[u8],
        path: &RepositoryRelativePathV1,
        listed_identity: RepositoryFileIdentityV1,
    ) -> Result<(), UnixFailure> {
        if self.files_scanned >= u64::from(self.request.max_files) {
            self.truncated = true;
            self.stopped = true;
            return Ok(());
        }
        let total_remaining = self
            .request
            .max_total_bytes
            .saturating_sub(self.bytes_scanned);
        if total_remaining == 0 {
            self.truncated = true;
            self.stopped = true;
            return Ok(());
        }
        let file_len = u64::try_from(unix_identity(listed_identity).byte_len).unwrap_or(0);
        let read_limit = file_len
            .min(self.request.max_bytes_per_file)
            .min(total_remaining);
        let planned_scan = RepositoryLiteralFileScanV1 {
            path: path.clone(),
            bytes_scanned: read_limit,
            file_byte_len: file_len,
            truncated: read_limit < file_len,
        };
        let planned_scan_cost = self.artifact_budget.secondary_cost(&planned_scan)?;
        if !self.artifact_budget.admits(planned_scan_cost) {
            self.truncated = true;
            self.stopped = true;
            return Ok(());
        }
        let (bytes, opened_identity) = read_child_prefix(directory, name, read_limit)?;
        if opened_identity != listed_identity {
            return Err(UnixFailure::boundary(
                ToolFailure::NodeChangedDuringObservation {
                    before: listed_identity,
                    after: opened_identity,
                },
            ));
        }
        self.files_scanned = self.files_scanned.saturating_add(1);
        let observed_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.bytes_scanned = self.bytes_scanned.saturating_add(observed_bytes);
        let file_truncated = observed_bytes < file_len;
        let file_scan = RepositoryLiteralFileScanV1 {
            path: path.clone(),
            bytes_scanned: observed_bytes,
            file_byte_len: file_len,
            truncated: file_truncated,
        };
        let file_scan_cost = self.artifact_budget.secondary_cost(&file_scan)?;
        if !self.artifact_budget.admits(file_scan_cost) {
            return Err(UnixFailure::boundary(ToolFailure::BrokerStateUnavailable));
        }
        self.file_scans
            .try_reserve(1)
            .map_err(|_| UnixFailure::resource_exhausted(RepositoryIoOperationV1::ReadFile))?;
        self.artifact_budget.commit_secondary(file_scan_cost);
        self.file_scans.push(file_scan);
        if file_truncated {
            self.truncated = true;
        }

        self.retain_literal_matches(&bytes, path)?;
        if self.matches.len() >= usize::try_from(self.request.max_matches).unwrap_or(usize::MAX)
            || self.bytes_scanned >= self.request.max_total_bytes
        {
            self.truncated = true;
            self.stopped = true;
        }
        Ok(())
    }

    fn retain_literal_matches(
        &mut self,
        bytes: &[u8],
        path: &RepositoryRelativePathV1,
    ) -> Result<(), UnixFailure> {
        let mut pattern_bytes_matched = 0_usize;
        for (index, byte) in bytes.iter().copied().enumerate() {
            while pattern_bytes_matched > 0 && byte != self.request.pattern[pattern_bytes_matched] {
                pattern_bytes_matched = self.prefix[pattern_bytes_matched - 1];
            }
            if byte == self.request.pattern[pattern_bytes_matched] {
                pattern_bytes_matched += 1;
            }
            if pattern_bytes_matched != self.request.pattern.len() {
                continue;
            }

            let offset = index + 1 - self.request.pattern.len();
            let matched = RepositoryLiteralMatchV1 {
                path: path.clone(),
                byte_offset: u64::try_from(offset).unwrap_or(u64::MAX),
            };
            let match_cost = self.artifact_budget.primary_cost(&matched)?;
            if !self.artifact_budget.admits(match_cost) {
                self.truncated = true;
                self.stopped = true;
                break;
            }
            self.matches
                .try_reserve(1)
                .map_err(|_| UnixFailure::resource_exhausted(RepositoryIoOperationV1::ReadFile))?;
            self.artifact_budget.commit_primary(match_cost);
            self.matches.push(matched);
            if self.matches.len() >= usize::try_from(self.request.max_matches).unwrap_or(usize::MAX)
            {
                break;
            }
            pattern_bytes_matched = self.prefix[pattern_bytes_matched - 1];
        }
        Ok(())
    }
}

fn open_directory(
    root: &OwnedFd,
    path: &RepositoryRelativePathV1,
    root_device: u64,
) -> Result<OwnedFd, UnixFailure> {
    let mut current = dup(root).map_err(|error| {
        UnixFailure::errno(RepositoryIoOperationV1::DuplicateRootDescriptor, error)
    })?;
    for component in path.unix_components() {
        current = open_child_directory(&current, component, root_device)?;
    }
    Ok(current)
}

fn open_child_directory(
    parent: &OwnedFd,
    component: &[u8],
    root_device: u64,
) -> Result<OwnedFd, UnixFailure> {
    let child = openat(
        parent,
        component,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| UnixFailure::errno(RepositoryIoOperationV1::OpenDirectory, error))?;
    ensure_same_device(
        root_device,
        unix_identity(descriptor_identity(&child)?).device,
    )?;
    Ok(child)
}

fn open_file(
    root: &OwnedFd,
    path: &RepositoryRelativePathV1,
    root_device: u64,
) -> Result<OwnedFd, UnixFailure> {
    let (file_name, parents) = path.unix_components().split_last().ok_or_else(|| {
        UnixFailure::boundary(ToolFailure::InvalidPath {
            violation: birdcode_protocol::RepositoryPathViolationV1::EmptyFilePath,
            component_index: None,
        })
    })?;
    let mut current = dup(root).map_err(|error| {
        UnixFailure::errno(RepositoryIoOperationV1::DuplicateRootDescriptor, error)
    })?;
    for component in parents {
        current = open_child_directory(&current, component, root_device)?;
    }
    openat(
        &current,
        file_name.as_slice(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| UnixFailure::errno(RepositoryIoOperationV1::OpenFile, error))
}

fn ensure_same_device(root_device: u64, observed_device: u64) -> Result<(), UnixFailure> {
    if root_device != observed_device {
        return Err(UnixFailure::boundary(ToolFailure::CrossDeviceBoundary {
            root_device,
            observed_device,
        }));
    }
    Ok(())
}

fn read_child_prefix(
    parent: &OwnedFd,
    name: &[u8],
    limit: u64,
) -> Result<(Vec<u8>, RepositoryFileIdentityV1), UnixFailure> {
    let fd = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| UnixFailure::errno(RepositoryIoOperationV1::OpenFile, error))?;
    let before_stat = fstat(&fd)
        .map_err(|error| UnixFailure::errno(RepositoryIoOperationV1::StatDescriptor, error))?;
    let kind = node_kind(before_stat.st_mode);
    if kind != RepositoryNodeKindV1::RegularFile {
        return Err(UnixFailure::boundary(ToolFailure::WrongFileType {
            expected: RepositoryExpectedNodeKindV1::RegularFile,
            observed: kind,
        }));
    }
    let before = identity(before_stat);
    let mut file = std::fs::File::from(fd);
    let mut bytes = bounded_buffer(limit, RepositoryIoOperationV1::ReadFile)?;
    (&mut file)
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| UnixFailure::std_io(RepositoryIoOperationV1::ReadFile, &error))?;
    let after = fstat(&file)
        .map(identity)
        .map_err(|error| UnixFailure::errno(RepositoryIoOperationV1::StatDescriptor, error))?;
    if before != after {
        return Err(UnixFailure::boundary(
            ToolFailure::NodeChangedDuringObservation { before, after },
        ));
    }
    Ok((bytes, before))
}

fn directory_names(
    directory: &OwnedFd,
    entries_scanned: &mut u64,
    name_bytes_scanned: &mut u64,
    bounds: &RepositoryToolBoundsV1,
) -> Result<Vec<Vec<u8>>, UnixFailure> {
    let mut stream = Dir::read_from(directory)
        .map_err(|error| UnixFailure::errno(RepositoryIoOperationV1::ReadDirectory, error))?;
    let mut names = Vec::new();
    while let Some(entry) = stream.read() {
        let entry = entry
            .map_err(|error| UnixFailure::errno(RepositoryIoOperationV1::ReadDirectory, error))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        *entries_scanned = entries_scanned.saturating_add(1);
        if *entries_scanned > u64::from(bounds.max_directory_entries_scanned) {
            return Err(UnixFailure::boundary(ToolFailure::LimitExceeded {
                limit: RepositoryLimitKindV1::DirectoryEntriesScanned,
                requested: *entries_scanned,
                maximum: u64::from(bounds.max_directory_entries_scanned),
            }));
        }
        if u64::try_from(name.len()).unwrap_or(u64::MAX) > bounds.max_component_bytes {
            return Err(UnixFailure::boundary(ToolFailure::LimitExceeded {
                limit: RepositoryLimitKindV1::ComponentBytes,
                requested: u64::try_from(name.len()).unwrap_or(u64::MAX),
                maximum: bounds.max_component_bytes,
            }));
        }
        *name_bytes_scanned = name_bytes_scanned
            .checked_add(u64::try_from(name.len()).unwrap_or(u64::MAX))
            .unwrap_or(u64::MAX);
        if *name_bytes_scanned > bounds.max_directory_name_bytes_scanned {
            return Err(UnixFailure::boundary(ToolFailure::LimitExceeded {
                limit: RepositoryLimitKindV1::DirectoryNameBytesScanned,
                requested: *name_bytes_scanned,
                maximum: bounds.max_directory_name_bytes_scanned,
            }));
        }
        names
            .try_reserve(1)
            .map_err(|_| UnixFailure::resource_exhausted(RepositoryIoOperationV1::ReadDirectory))?;
        let mut retained_name = Vec::new();
        retained_name
            .try_reserve_exact(name.len())
            .map_err(|_| UnixFailure::resource_exhausted(RepositoryIoOperationV1::ReadDirectory))?;
        retained_name.extend_from_slice(name);
        names.push(retained_name);
    }
    names.sort_unstable();
    Ok(names)
}

fn bounded_buffer(limit: u64, operation: RepositoryIoOperationV1) -> Result<Vec<u8>, UnixFailure> {
    let capacity = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| UnixFailure::resource_exhausted(operation))?;
    Ok(bytes)
}

fn ensure_discovered_path_bound(
    path: &RepositoryRelativePathV1,
    bounds: &RepositoryToolBoundsV1,
) -> Result<(), UnixFailure> {
    let component_count = u64::try_from(path.unix_components().len()).unwrap_or(u64::MAX);
    if component_count > u64::from(bounds.max_path_components) {
        return Err(UnixFailure::boundary(ToolFailure::LimitExceeded {
            limit: RepositoryLimitKindV1::PathComponents,
            requested: component_count,
            maximum: u64::from(bounds.max_path_components),
        }));
    }
    let path_bytes = path
        .unix_components()
        .iter()
        .fold(0_u64, |total, component| {
            total
                .checked_add(u64::try_from(component.len()).unwrap_or(u64::MAX))
                .and_then(|value| value.checked_add(1))
                .unwrap_or(u64::MAX)
        });
    if path_bytes > bounds.max_path_bytes {
        return Err(UnixFailure::boundary(ToolFailure::LimitExceeded {
            limit: RepositoryLimitKindV1::PathBytes,
            requested: path_bytes,
            maximum: bounds.max_path_bytes,
        }));
    }
    Ok(())
}

fn literal_prefix_table(pattern: &[u8]) -> Vec<usize> {
    let mut prefix = vec![0; pattern.len()];
    let mut matched = 0;
    for index in 1..pattern.len() {
        while matched > 0 && pattern[index] != pattern[matched] {
            matched = prefix[matched - 1];
        }
        if pattern[index] == pattern[matched] {
            matched += 1;
            prefix[index] = matched;
        }
    }
    prefix
}

#[cfg(test)]
fn literal_offsets(bytes: &[u8], pattern: &[u8], prefix: &[usize], maximum: usize) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut matched = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        while matched > 0 && byte != pattern[matched] {
            matched = prefix[matched - 1];
        }
        if byte == pattern[matched] {
            matched += 1;
        }
        if matched == pattern.len() {
            offsets.push(index + 1 - pattern.len());
            if offsets.len() >= maximum {
                break;
            }
            matched = prefix[matched - 1];
        }
    }
    offsets
}

fn identity(stat: rustix::fs::Stat) -> RepositoryFileIdentityV1 {
    RepositoryFileIdentityV1::Unix(RepositoryUnixFileIdentityV1 {
        device: u64::try_from(stat.st_dev).unwrap_or(u64::MAX),
        inode: stat.st_ino,
        byte_len: stat.st_size,
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec,
        changed_seconds: stat.st_ctime,
        changed_nanoseconds: stat.st_ctime_nsec,
    })
}

fn unix_identity(identity: RepositoryFileIdentityV1) -> RepositoryUnixFileIdentityV1 {
    match identity {
        RepositoryFileIdentityV1::Unix(identity) => identity,
    }
}

fn appended_path(path: &RepositoryRelativePathV1, component: Vec<u8>) -> RepositoryRelativePathV1 {
    let mut components = path.unix_components().to_vec();
    components.push(component);
    RepositoryRelativePathV1::Unix { components }
}

fn node_kind(mode: rustix::fs::RawMode) -> RepositoryNodeKindV1 {
    match FileType::from_raw_mode(mode) {
        FileType::RegularFile => RepositoryNodeKindV1::RegularFile,
        FileType::Directory => RepositoryNodeKindV1::Directory,
        FileType::Symlink => RepositoryNodeKindV1::Symlink,
        _ => RepositoryNodeKindV1::Other,
    }
}

fn map_error_kind(kind: std::io::ErrorKind) -> RepositoryIoFailureKindV1 {
    match kind {
        std::io::ErrorKind::NotFound => RepositoryIoFailureKindV1::NotFound,
        std::io::ErrorKind::PermissionDenied => RepositoryIoFailureKindV1::PermissionDenied,
        std::io::ErrorKind::Interrupted => RepositoryIoFailureKindV1::Interrupted,
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
            RepositoryIoFailureKindV1::InvalidInput
        }
        std::io::ErrorKind::OutOfMemory
        | std::io::ErrorKind::StorageFull
        | std::io::ErrorKind::QuotaExceeded => RepositoryIoFailureKindV1::ResourceExhausted,
        _ => RepositoryIoFailureKindV1::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::{literal_offsets, literal_prefix_table};

    #[test]
    fn literal_matcher_finds_overlapping_matches() {
        let pattern = b"aba";
        let prefix = literal_prefix_table(pattern);
        assert_eq!(literal_offsets(b"ababa", pattern, &prefix, 10), vec![0, 2]);
    }

    #[test]
    fn literal_matcher_obeys_bound() {
        let pattern = b"a";
        let prefix = literal_prefix_table(pattern);
        assert_eq!(literal_offsets(b"aaaa", pattern, &prefix, 2), vec![0, 1]);
    }
}
