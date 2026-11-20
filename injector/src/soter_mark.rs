//! Real biometric evidence for the local SOTER identity.
//!
//! The software TA signs only inside a fingerprint match, like the stock TA.
//! The match is observed where the platform posts it: keystore2 mirrors every
//! `addAuthToken` into the OMK keymint, and this module records the fingerprint
//! tokens so `soter_ta::platform` can answer with a per-boot mark.
//!
//! A mark packs a per-process boot tag in the high 31 bits and a capture counter
//! in the low 32, matching `soter_ta::platform`'s comparison rules.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use crate::android::hardware::security::keymint::HardwareAuthenticatorType::HardwareAuthenticatorType;

static START: OnceLock<Instant> = OnceLock::new();
static BOOT_TAG: OnceLock<u64> = OnceLock::new();
static FINGERPRINT_MARKS: AtomicU64 = AtomicU64::new(0);

fn start() -> &'static Instant {
    START.get_or_init(Instant::now)
}

/// Tag that changes with every injected process start. Sessions never outlive
/// the process that opened them, so a new tag invalidates older evidence.
fn tag() -> u64 {
    *BOOT_TAG.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() & 0x7fff_ffff)
            .unwrap_or(1)
    })
}

unsafe extern "C" fn boot_ms() -> i64 {
    start().elapsed().as_millis() as i64
}

unsafe extern "C" fn bio_mark() -> i64 {
    ((tag() << 32) | FINGERPRINT_MARKS.load(Ordering::Relaxed)) as i64
}

/// Record one accepted fingerprint capture.
pub fn mark_fingerprint() {
    FINGERPRINT_MARKS.fetch_add(1, Ordering::Relaxed);
}

/// Whether an auth token reports a fingerprint authenticator.
pub fn is_fingerprint(auth_type: HardwareAuthenticatorType) -> bool {
    const AUTH_TYPE_FINGERPRINT: i32 = 0x2;
    auth_type.0 & AUTH_TYPE_FINGERPRINT != 0
}

/// Publish the platform probes to the local SOTER identity.
pub fn install() {
    soter_ta::platform::install(Some(boot_ms), Some(bio_mark));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_bit_is_detected_but_other_authenticators_are_not() {
        assert!(is_fingerprint(HardwareAuthenticatorType(0x2)));
        assert!(is_fingerprint(HardwareAuthenticatorType(0x3)));
        assert!(!is_fingerprint(HardwareAuthenticatorType(0x1)));
        assert!(!is_fingerprint(HardwareAuthenticatorType(0)));
    }

    #[test]
    fn marks_advance_only_on_capture() {
        let before = unsafe { bio_mark() };
        mark_fingerprint();
        let after = unsafe { bio_mark() };
        assert!(after > before);
        assert_eq!(after >> 32, before >> 32);
    }
}
