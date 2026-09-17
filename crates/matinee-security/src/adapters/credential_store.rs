//! Private platform credential-store boundary.
//!
//! The adapter returns opaque handles only.  It deliberately has no operation
//! for exporting key material, and its errors contain no provider diagnostics or
//! identifiers that could disclose credential state.

use core::fmt;

/// A stable, non-secret selector supplied by the owning identity transition.
///
/// The adapter does not interpret this value.  In particular, it must not fall
/// back to another principal when the selected binding is absent or mismatched.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CredentialBinding([u8; 32]);

impl CredentialBinding {
    pub(crate) const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Derive a stable selector from the state-directory and daemon identities.
    /// The selector is non-secret and cannot be substituted with another principal.
    pub(crate) fn for_identities(state_directory: uuid::Uuid, daemon: uuid::Uuid) -> Self {
        let mut value = [0u8; 32];
        let state = state_directory.as_bytes();
        let daemon = daemon.as_bytes();
        for i in 0..16 {
            value[i] = state[i];
            value[16 + i] = daemon[i];
        }
        Self(value)
    }
}


impl fmt::Debug for CredentialBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialBinding(REDACTED)")
    }
}

/// Opaque custody returned by a platform credential store.
///
/// The bytes behind this handle never cross the adapter boundary.  A handle is
/// intentionally not serializable, displayable, or convertible to bytes.
#[derive(PartialEq, Eq)]
pub(crate) struct CredentialHandle {
    slot: u64,
}

impl CredentialHandle {
    pub(crate) const fn from_slot(slot: u64) -> Self {
        Self { slot }
    }

    pub(crate) const fn slot(&self) -> u64 {
        self.slot
    }
}

impl fmt::Debug for CredentialHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialHandle(REDACTED)")
    }
}

/// Closed, redacted credential lookup outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialStoreError {
    /// No credential is registered for the selected binding.
    Missing,
    /// A credential exists, but is bound to a different identity.
    Mismatch,
    /// More than one credential claims the selected binding.
    Duplicate,
    /// The platform service could not be queried.  Callers must fail closed.
    Unavailable,
}

/// The sole credential-store seam owned by this crate.
///
/// Implementations may retain private material in the platform service, but
/// they may return only an opaque [`CredentialHandle`].  No clock, persistence,
/// origin, or cryptographic-library trait is defined here.
pub(crate) trait CredentialStore {
    fn lookup(&self, binding: CredentialBinding) -> Result<CredentialHandle, CredentialStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_are_closed_and_handle_debug_is_redacted() {
        let handle = CredentialHandle::from_slot(42);
        assert_eq!(handle.slot(), 42);
        assert_eq!(format!("{handle:?}"), "CredentialHandle(REDACTED)");
        assert_eq!(
            format!("{:?}", CredentialBinding::new([7; 32])),
            "CredentialBinding(REDACTED)"
        );
        assert_ne!(
            CredentialStoreError::Missing,
            CredentialStoreError::Unavailable
        );
    }
}
