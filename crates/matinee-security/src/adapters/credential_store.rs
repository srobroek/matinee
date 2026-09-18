//! Private platform credential-store boundary.
//!
//! The adapter returns opaque handles only. It deliberately has no operation
//! for exporting key material, and its errors contain no provider diagnostics or
//! identifiers that could disclose credential state.

use core::fmt;

use ring::digest;

/// A derived, non-secret selector supplied by the owning identity transition.
///
/// The selector is a domain-separated SHA-256 digest, never a concatenation of
/// identity bytes. The owner tag lets a storage provider distinguish a record
/// whose selector is present but whose identity binding is wrong.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CredentialBinding {
    selector: [u8; 32],
    owner: [u8; 32],
}

impl CredentialBinding {
    /// Construct a deterministic opaque binding for adapter-level tests.
    pub(crate) const fn new(value: [u8; 32]) -> Self {
        Self { selector: value, owner: value }
    }

    /// Derive a stable selector from the state-directory and daemon identities.
    /// Both the selector and owner tag are one-way, domain-separated digests.
    pub(crate) fn for_identities(state_directory: uuid::Uuid, daemon: uuid::Uuid) -> Self {
        let state = state_directory.as_bytes();
        let daemon = daemon.as_bytes();
        Self {
            selector: derive(b"matinee credential selector v1", state, daemon),
            owner: derive(b"matinee credential owner v1", state, daemon),
        }
    }

    fn selector(self) -> [u8; 32] { self.selector }
    fn owner(self) -> [u8; 32] { self.owner }
}

fn derive(domain: &[u8], state: &[u8; 16], daemon: &[u8; 16]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..domain.len().min(32)].copy_from_slice(&domain[..domain.len().min(32)]);
    input[32..48].copy_from_slice(state);
    input[48..].copy_from_slice(daemon);
    let digest = digest::digest(&digest::SHA256, &input);
    let mut result = [0u8; 32];
    result.copy_from_slice(digest.as_ref());
    result
}

impl fmt::Debug for CredentialBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialBinding(REDACTED)")
    }
}

/// Opaque custody returned by a platform credential store.
///
/// The bytes behind this handle never cross the adapter boundary. A handle is
/// intentionally not serializable, displayable, or convertible to bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CredentialHandle {
    slot: u64,
}

impl CredentialHandle {
    pub(crate) const fn from_slot(slot: u64) -> Self { Self { slot } }
    pub(crate) const fn slot(&self) -> u64 { self.slot }
}

impl fmt::Debug for CredentialHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialHandle(REDACTED)")
    }
}

/// Closed, redacted credential lookup outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialStoreError {
    Missing,
    Mismatch,
    Duplicate,
    Unavailable,
}

/// The sole credential-store seam owned by this crate.
pub(crate) trait CredentialStore {
    fn lookup(&self, binding: CredentialBinding) -> Result<CredentialHandle, CredentialStoreError>;
}

/// Minimal real storage used by the bootstrap operation and contract tests.
///
/// Entries are selector-indexed records, not a test-only fake. Lookup is an
/// all-or-failure operation: unavailable, absent, mismatched, and duplicate
/// records never produce a handle. A platform adapter can implement the same
/// [`CredentialStore`] contract without exposing key bytes.
#[derive(Default)]
pub(crate) struct InMemoryCredentialStore {
    entries: Vec<CredentialRecord>,
    unavailable: bool,
}

#[derive(Clone, Copy)]
struct CredentialRecord {
    selector: [u8; 32],
    owner: [u8; 32],
    handle: CredentialHandle,
}

impl InMemoryCredentialStore {
    pub(crate) fn new() -> Self { Self::default() }

    pub(crate) fn register(&mut self, binding: CredentialBinding, slot: u64) {
        self.entries.push(CredentialRecord {
            selector: binding.selector(), owner: binding.owner(),
            handle: CredentialHandle::from_slot(slot),
        });
    }

    pub(crate) fn register_mismatched(&mut self, binding: CredentialBinding, slot: u64) {
        let mut owner = binding.owner();
        owner[0] ^= 0xff;
        self.entries.push(CredentialRecord {
            selector: binding.selector(), owner, handle: CredentialHandle::from_slot(slot),
        });
    }

    pub(crate) fn set_unavailable(&mut self, unavailable: bool) {
        self.unavailable = unavailable;
    }
}

impl CredentialStore for InMemoryCredentialStore {
    fn lookup(&self, binding: CredentialBinding) -> Result<CredentialHandle, CredentialStoreError> {
        if self.unavailable { return Err(CredentialStoreError::Unavailable); }
        let mut found = None;
        for record in self.entries.iter().filter(|record| record.selector == binding.selector()) {
            if found.is_some() { return Err(CredentialStoreError::Duplicate); }
            found = Some(record);
        }
        let record = found.ok_or(CredentialStoreError::Missing)?;
        if record.owner != binding.owner() { return Err(CredentialStoreError::Mismatch); }
        Ok(record.handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_is_derived_and_storage_outcomes_are_closed() {
        let first = CredentialBinding::for_identities(uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2));
        let other = CredentialBinding::for_identities(uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(3));
        assert_ne!(first, other);
        assert_eq!(format!("{first:?}"), "CredentialBinding(REDACTED)");
        let mut store = InMemoryCredentialStore::new();
        assert_eq!(store.lookup(first), Err(CredentialStoreError::Missing));
        store.register_mismatched(first, 7);
        assert_eq!(store.lookup(first), Err(CredentialStoreError::Mismatch));
        store.register(first, 8);
        assert_eq!(store.lookup(first), Err(CredentialStoreError::Duplicate));
        store.set_unavailable(true);
        assert_eq!(store.lookup(first), Err(CredentialStoreError::Unavailable));
    }
}
