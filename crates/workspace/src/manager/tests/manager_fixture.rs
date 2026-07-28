use super::*;

pub(super) struct FakeCommandBoundary {
    outcomes: Mutex<VecDeque<Result<RawCommandOutput, CommandBoundaryError>>>,
}

impl FakeCommandBoundary {
    pub(super) fn one(outcome: Result<RawCommandOutput, CommandBoundaryError>) -> Self {
        Self {
            outcomes: Mutex::new(VecDeque::from([outcome])),
        }
    }
}

impl CommandBoundary for FakeCommandBoundary {
    fn run(
        &self,
        _command: &PreparedMacOsCommand,
    ) -> Result<RawCommandOutput, CommandBoundaryError> {
        self.outcomes
            .lock()
            .expect("fake command lock")
            .pop_front()
            .expect("one fake command outcome")
    }
}

#[derive(Default)]
struct FakeClock {
    next: AtomicU64,
}

impl ClockBoundary for FakeClock {
    fn now(
        &self,
        runtime_instance_id: RuntimeInstanceId,
    ) -> Result<RuntimeClockReading, ClockBoundaryError> {
        Ok(RuntimeClockReading {
            runtime_instance_id,
            monotonic_nanos: self.next.fetch_add(1, Ordering::SeqCst),
            observed_at: Utc::now(),
        })
    }
}

pub(super) fn uuid(value: u128) -> Uuid {
    Uuid::from_u128(value)
}

pub(super) fn manager(
    command: Arc<dyn CommandBoundary>,
    artifacts: Arc<dyn ArtifactBoundary>,
) -> (tempfile::TempDir, tempfile::TempDir, WorkspaceManager) {
    let source = tempfile::tempdir().expect("source tempdir");
    let state = tempfile::tempdir().expect("state tempdir");
    std::fs::write(source.path().join("kod-日本語.rs"), b"fn main() {}\n").expect("fixture writes");
    let manager = WorkspaceManager::open_with_boundaries(
        WorkspaceManagerConfig::new(source.path(), state.path()),
        command,
        artifacts,
        Arc::new(FakeClock::default()),
    )
    .expect("manager opens");
    (source, state, manager)
}
