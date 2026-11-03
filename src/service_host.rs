//! Run the collector itself in the Windows SCM process: no wrapper child or
//! second collector. A stop control follows the normal database flush path.
use std::{
    ffi::OsString,
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
    time::Duration,
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};
static STOP: AtomicBool = AtomicBool::new(false);
static STATUS: OnceLock<ServiceStatusHandle> = OnceLock::new();
define_windows_service!(ffi_main, service_main);
pub fn dispatch() -> windows_service::Result<()> {
    service_dispatcher::start(genyra_common::service::NAME, ffi_main)
}
pub fn stopping() -> bool {
    STOP.load(Ordering::Relaxed)
}
fn status(state: ServiceState, code: u32) -> windows_service::Result<()> {
    if let Some(handle) = STATUS.get() {
        handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: if matches!(
                state,
                ServiceState::StartPending | ServiceState::StopPending
            ) {
                1
            } else {
                0
            },
            wait_hint: if matches!(
                state,
                ServiceState::StartPending | ServiceState::StopPending
            ) {
                Duration::from_secs(20)
            } else {
                Duration::ZERO
            },
            process_id: None,
        })?;
    }
    Ok(())
}
pub fn started() -> windows_service::Result<()> {
    status(ServiceState::Running, 0)
}
fn service_main(_: Vec<OsString>) {
    let handle =
        service_control_handler::register(genyra_common::service::NAME, |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                STOP.store(true, Ordering::Relaxed);
                let _ = status(ServiceState::StopPending, 0);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        });
    let Ok(handle) = handle else {
        return;
    };
    let _ = STATUS.set(handle);
    let _ = status(ServiceState::StartPending, 0);
    let code = match crate::run() {
        Ok(()) => 0,
        Err(error) => {
            let message = format!("Genyra Snitch service failed: {error}\n");
            let _ = genyra_common::save_private(
                &crate::paths::data_dir(),
                "service-error.log",
                message.as_bytes(),
            );
            1
        }
    };
    let _ = status(ServiceState::Stopped, code);
}
