use std::ffi::c_void;

use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use kmr_common::consts::{KEYSTORE_GID, KEYSTORE_UID};
use log::{error, info, warn, LevelFilter};
use nix::unistd::Pid;

use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;

mod auto_targets;
pub mod config;
pub mod filter;
pub mod forward;
pub mod hook;
pub mod identify;
pub mod inject;
pub mod ipc;
pub mod legacy;
pub mod logging;
pub mod parcel;
mod soter_mark;
mod soter_watch;
pub mod sys;
pub mod tracker;
pub mod utils;

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

fn log_runtime_identity(role: &str) {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getgid() };
    let egid = unsafe { libc::getegid() };
    info!("runtime identity role={} uid={} euid={} gid={} egid={}", role, uid, euid, gid, egid);
}

const WEBUI_GET_TEE_STATUS: &str = "--webui-get-tee-status";

fn parse_webui_tee_status_args(args: &[String]) -> Option<Result<(), String>> {
    let command = args.first()?;
    if command != WEBUI_GET_TEE_STATUS {
        return None;
    }
    if args.len() != 1 {
        return Some(Err(format!("{WEBUI_GET_TEE_STATUS} does not accept arguments")));
    }
    Some(Ok(()))
}

fn enter_keystore_identity() -> anyhow::Result<()> {
    let effective_uid = unsafe { libc::geteuid() };
    let effective_gid = unsafe { libc::getegid() };
    if effective_uid == KEYSTORE_UID && effective_gid == KEYSTORE_GID {
        return Ok(());
    }
    if effective_uid != 0 {
        bail!(
            "TEE status probe requires root or keystore uid/gid; current euid={effective_uid} egid={effective_gid}"
        );
    }

    if unsafe { libc::setgid(KEYSTORE_GID) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to enter keystore gid for TEE status probe");
    }
    if unsafe { libc::setuid(KEYSTORE_UID) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to enter keystore uid for TEE status probe");
    }
    if unsafe { libc::geteuid() } != KEYSTORE_UID || unsafe { libc::getegid() } != KEYSTORE_GID {
        bail!("TEE status probe did not enter the keystore uid/gid");
    }
    Ok(())
}

fn probe_tee_status() -> anyhow::Result<()> {
    enter_keystore_identity()?;
    ipc::ensure_process_state();
    ipc::with_omk_once(|omk| {
        let _ = omk.r#getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)?;
        Ok(())
    })
    .context("failed to obtain the OMK TEE security level")
}

fn handle_webui_tee_status_command() -> Option<Result<&'static str, String>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match parse_webui_tee_status_args(&args)? {
        Ok(()) => Some(probe_tee_status().map(|()| "normal").map_err(|error| format!("{error:#}"))),
        Err(error) => Some(Err(error)),
    }
}

fn handle_webui_config_command() -> Option<Result<String, String>> {
    let mut args = std::env::args();
    let _program = args.next();
    let command = args.next()?;

    match command.as_str() {
        "--webui-engineer-selected" => {
            let uid = args.next().and_then(|value| value.parse::<u32>().ok());
            if unsafe { libc::geteuid() } != 0 || args.next().is_some() || uid.is_none() {
                return Some(Err("Engineer display selection requires root and one UID".into()));
            }
            Some(config::engineer_display_selected(uid.unwrap()).map(|value| value.to_string()))
        }
        "--webui-get-auto-targets" => {
            if args.next().is_some() {
                return Some(Err("--webui-get-auto-targets does not accept arguments".into()));
            }
            Some(
                auto_targets::status()
                    .and_then(|state| Ok(serde_json::to_string(&state)?))
                    .map_err(|error| format!("{error:#}")),
            )
        }
        "--webui-set-auto-targets" => {
            let enabled = match args.next().as_deref() {
                Some("0") => false,
                Some("1") => true,
                _ => return Some(Err("--webui-set-auto-targets requires 0 or 1".into())),
            };
            if args.next().is_some() {
                return Some(Err("--webui-set-auto-targets accepts one argument".into()));
            }
            Some(
                auto_targets::set_enabled(enabled)
                    .and_then(|state| Ok(serde_json::to_string(&state)?))
                    .map_err(|error| format!("{error:#}")),
            )
        }
        "--webui-update-scoop" => {
            let Some(encoded) = args.next() else {
                return Some(Err("--webui-update-scoop requires a base64 JSON delta".into()));
            };
            if args.next().is_some() || encoded.len() > 4 * 1024 * 1024 {
                return Some(Err("invalid scoop delta arguments".into()));
            }
            Some(
                BASE64_STANDARD
                    .decode(encoded)
                    .map_err(|error| error.to_string())
                    .and_then(|payload| {
                        serde_json::from_slice::<config::ScoopDelta>(&payload)
                            .map_err(|error| error.to_string())
                    })
                    .and_then(config::update_scoop_for_webui)
                    .and_then(|targets| {
                        serde_json::to_string(&targets).map_err(|error| error.to_string())
                    }),
            )
        }
        "--webui-get-scoop" => {
            if args.next().is_some() {
                return Some(Err("--webui-get-scoop does not accept arguments".to_string()));
            }
            Some(
                config::read_scoop_for_webui().and_then(|packages| {
                    serde_json::to_string(&packages).map_err(|e| e.to_string())
                }),
            )
        }
        "--webui-set-scoop" => {
            let Some(encoded) = args.next() else {
                return Some(Err(
                    "--webui-set-scoop requires a base64-encoded JSON array".to_string()
                ));
            };
            if args.next().is_some() {
                return Some(Err("--webui-set-scoop accepts one argument".to_string()));
            }
            let result = BASE64_STANDARD
                .decode(encoded)
                .map_err(|error| format!("invalid scoop payload encoding: {error}"))
                .and_then(|payload| {
                    serde_json::from_slice::<Vec<String>>(&payload)
                        .map_err(|error| format!("invalid scoop payload: {error}"))
                })
                .and_then(config::replace_scoop_for_webui)
                .map(|()| "ok".to_string());
            Some(result)
        }
        _ => None,
    }
}


/// Conceal this process from casual /proc inspection: rename the thread
/// command and overwrite the argv strings the kernel exposes in
/// `/proc/<pid>/cmdline`. Arguments are already parsed by the time this runs.
fn conceal_process(comm: &str) {
    let comm = std::ffi::CString::new(comm).unwrap_or_default();
    unsafe {
        libc::prctl(libc::PR_SET_NAME, comm.as_ptr() as libc::c_ulong, 0, 0, 0);
    }
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return;
    };
    let Some(close) = stat.rfind(')') else { return };
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    let (Some(start), Some(end)) = (fields.get(45), fields.get(46)) else {
        return;
    };
    let (Ok(start), Ok(end)) = (start.parse::<usize>(), end.parse::<usize>()) else {
        return;
    };
    if end <= start || end - start > 1024 * 1024 {
        return;
    }
    // Keep the terminating NUL: only the visible characters are blanked.
    unsafe {
        let name = b"keymaster";
        let span = end - start;
        let n = name.len().min(span.saturating_sub(1));
        std::ptr::copy_nonoverlapping(name.as_ptr(), start as *mut u8, n);
        std::ptr::write_bytes((start as *mut u8).add(n), b' ', span - n - 1);
    }
}


/// Keystore2 guard: injects into the current keystore2 process whenever the
/// payload state does not name it, and honours restart.injector. Replaces the
/// shell supervisor so no script process is visible in /proc.
fn guard_loop() -> ! {
    use std::time::Duration;

    let state = std::path::Path::new("/data/adb/omk/injector.payload");
    let restart = std::path::Path::new("/data/adb/omk/restart.injector");
    loop {
        let forced = restart.exists();
        if forced {
            let _ = std::fs::remove_file(restart);
        }
        if let Ok((pid, _)) = utils::find_process_by_name("keystore2") {
            let current = std::fs::read_to_string(state)
                .ok()
                .and_then(|text| text.split_whitespace().next().and_then(|p| p.parse::<i32>().ok()));
            if forced || current != Some(pid) {
                match inject::inject_library(nix::unistd::Pid::from_raw(pid)) {
                    Ok(()) => log::info!("keystore2 guard injected pid={pid}"),
                    Err(error) => log::warn!("keystore2 guard injection failed: {error:#}"),
                }
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}


/// Start the in-process KeyMint runtime when embedded mode is enabled.
///
/// The library is copied to /data/misc/keystore/omk at boot so keystore2 can
/// load it without touching the module directory.
fn start_embedded_keymint() {
    if !std::path::Path::new("/data/misc/keystore/omk/embedded").exists() {
        return;
    }
    let mut handle = std::ptr::null_mut();
    for candidate in ["/system/lib64/libomk_keymint.so", "/data/misc/keystore/omk/libomk_keymint.so"] {
        let Ok(path) = std::ffi::CString::new(candidate) else { continue };
        handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if !handle.is_null() {
            log::info!("embedded keymint library loaded from {candidate}");
            break;
        }
        let detail = unsafe {
            let error = libc::dlerror();
            if error.is_null() {
                "unknown".to_string()
            } else {
                std::ffi::CStr::from_ptr(error).to_string_lossy().into_owned()
            }
        };
        log::error!("embedded keymint dlopen {candidate} failed: {detail}");
    }
    if handle.is_null() {
        return;
    }
    let symbol = unsafe { libc::dlsym(handle, c"omk_keymint_serve".as_ptr()) };
    if symbol.is_null() {
        log::error!("embedded keymint entry missing");
        return;
    }
    let entry: unsafe extern "C" fn() -> i32 = unsafe { std::mem::transmute(symbol) };
    let _ = std::thread::Builder::new()
        .name("keymint-runtime".into())
        .spawn(move || {
            log::info!("embedded keymint runtime starting");
            let code = unsafe { entry() };
            log::error!("embedded keymint runtime exited with {code}");
        });
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--guard") {
        conceal_process("keymaster");
        logging::init_logger_fallback(LevelFilter::Info);
        guard_loop();
    }
    if std::env::args().nth(1).as_deref() == Some("--soter-watch") {
        if std::env::args().count() != 2 {
            std::process::exit(2);
        }
        conceal_process("keymaster");
        logging::init_logger_fallback(LevelFilter::Info);
        if let Err(error) = soter_watch::run() {
            error!("Local SOTER supervisor failed: {error:#}");
            std::process::exit(2);
        }
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("--auto-targets-watch") {
        if std::env::args().count() != 2 {
            eprintln!("--auto-targets-watch does not accept arguments");
            std::process::exit(2);
        }
        conceal_process("keymaster");
        logging::init_logger_fallback(LevelFilter::Warn);
        if let Err(error) = auto_targets::run_watcher() {
            eprintln!("automatic app selection watcher failed: {error:#}");
            std::process::exit(2);
        }
        return;
    }
    if let Some(result) = handle_webui_tee_status_command() {
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    if let Some(result) = handle_webui_config_command() {
        match result {
            Ok(output) => println!("{output}"),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        return;
    }

    conceal_process("keymaster");
    logging::init_logger_fallback(LevelFilter::Debug);
    let config = config::get();
    if config::parse_level_filter(&config.main.log_level).is_none() {
        warn!(
            "injector logging unknown log level '{}', keeping debug fallback",
            config.main.log_level
        );
    }
    log::set_max_level(config.main.log_level_filter());
    log_runtime_identity("Launcher");
    match utils::current_exe_identity() {
        Ok(identity) => {
            info!(
                "injector binary build_id={} build_target={} git_sha={} runtime_arch={} exe={} sha256={} elf={}",
                utils::build_id(),
                utils::build_target(),
                utils::build_git_sha(),
                std::env::consts::ARCH,
                identity.path.display(),
                identity.sha256,
                identity.elf,
            );
        }
        Err(error) => {
            error!("failed to describe current injector binary: {:#}", error);
        }
    }

    let (pid, target_path) = match utils::find_process_by_name("keystore2") {
        Ok(target) => target,
        Err(error) => {
            warn!("event=target_not_ready process=keystore2 error={error:#}; daemon will retry");
            std::process::exit(1);
        }
    };
    match utils::executable_identity(&target_path) {
        Ok(identity) => info!(
            "keystore2 target pid={} exe={} sha256={} elf={}",
            pid,
            identity.path.display(),
            identity.sha256,
            identity.elf,
        ),
        Err(error) => {
            error!("failed to describe keystore2 executable {}: {:#}", target_path.display(), error)
        }
    }
    let pid = Pid::from_raw(pid);
    match inject::inject_library(pid) {
        Ok(()) => info!("injection completed"),
        Err(e) => {
            error!("injection failed: {:#}", e);
            std::process::exit(1);
        }
    }
}

#[no_mangle]
#[allow(unused)]
pub extern "C" fn entry(handle: *const c_void) -> bool {
    // This runs inside the target process, so we must initialize logging again
    // for that process. On Android this enables both logcat and stdout logging.
    logging::init_logger_fallback(LevelFilter::Debug);
    let config = config::get();
    if config::parse_level_filter(&config.main.log_level).is_none() {
        warn!(
            "injector logging unknown log level '{}', keeping debug fallback",
            config.main.log_level
        );
    }
    log::set_max_level(config.main.log_level_filter());
    log_runtime_identity("Payload");
    log::info!(
        "Injected library entry called! Handle: {:?}, build_id={}, build_target={}, runtime_arch={}, current_exe={}",
        handle,
        utils::build_id(),
        utils::build_target(),
        std::env::consts::ARCH,
        utils::current_exe_path()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string()),
    );
    ipc::ensure_process_state();
    if let Err(error) = hook::init_hook() {
        error!("failed to initialize binder ioctl hook: {error:#}");
        return false;
    }
    soter_mark::install();
    start_embedded_keymint();
    true
}

/// # Safety
/// The root injector transfers two distinct owned connected socket descriptors.
#[no_mangle]
pub unsafe extern "C" fn soter_entry(_handle: *const c_void, auth: i32, calls: i32) -> bool {
    use std::os::{fd::FromRawFd, unix::net::UnixStream};
    logging::init_logger_fallback(LevelFilter::Info);
    let auth = UnixStream::from_raw_fd(auth);
    let calls = UnixStream::from_raw_fd(calls);
    match hook::soter::initialize(auth, calls) {
        Ok(()) => true,
        Err(error) => {
            error!("Local SOTER initialization failed: {error:#}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn tee_status_command_is_dispatched_without_arguments() {
        assert_eq!(parse_webui_tee_status_args(&args(&[WEBUI_GET_TEE_STATUS])), Some(Ok(())));
    }

    #[test]
    fn tee_status_command_rejects_extra_arguments() {
        assert_eq!(
            parse_webui_tee_status_args(&args(&[WEBUI_GET_TEE_STATUS, "extra"])),
            Some(Err(format!("{WEBUI_GET_TEE_STATUS} does not accept arguments")))
        );
    }

    #[test]
    fn tee_status_parser_leaves_other_commands_for_existing_dispatch() {
        assert_eq!(parse_webui_tee_status_args(&args(&["--webui-get-scoop"])), None);
        assert_eq!(parse_webui_tee_status_args(&[]), None);
    }
}
