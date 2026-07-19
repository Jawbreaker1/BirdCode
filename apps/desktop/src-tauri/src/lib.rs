mod runtime;

pub use runtime::{RuntimeManager, RuntimeResetError};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Starts the native desktop shell.
///
/// # Panics
///
/// Panics when the generated `Tauri` context is invalid or the application
/// event loop cannot be started.
pub fn run() {
    tauri::Builder::default()
        .manage(runtime::RuntimeManager::default())
        .invoke_handler(tauri::generate_handler![
            runtime::runtime_health,
            runtime::runtime_reset,
            runtime::runtime_discover_models,
            runtime::runtime_start_plan,
            runtime::runtime_reconcile_plan_start,
            runtime::runtime_poll_plan,
            runtime::runtime_cancel_plan
        ])
        .run(tauri::generate_context!())
        .expect("failed to run BirdCode desktop application");
}
