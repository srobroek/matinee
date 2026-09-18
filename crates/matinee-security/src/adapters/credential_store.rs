//! Private platform credential-store boundary.
//!
//! The adapter returns opaque handles only. It deliberately has no operation
//! for exporting key material, and its errors contain no provider diagnostics or
//! identifiers that could disclose credential state.

use core::fmt;

use keyring::Entry;
use ring::digest;

const CREDENTIAL_SERVICE: &str = "matinee-security-credential-v1";
const OWNER_BYTES: usize = 32;
const MIN_PRIVATE_KEY_BYTES: usize = 32;

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
    #[cfg(test)]
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
    /// No credential is registered for the selected binding.
    Missing,
    /// A credential exists, but is bound to a different identity.
    Mismatch,
    /// More than one credential claims the selected binding.
    Duplicate,
    /// The platform service could not be queried. Callers must fail closed.
    Unavailable,
}

/// The sole credential-store seam owned by this crate.
pub(crate) trait CredentialStore {
    fn lookup(&self, binding: CredentialBinding) -> Result<CredentialHandle, CredentialStoreError>;
}

/// Production credential-store adapter backed by the selected native keyring.
///
/// The keyring entry name contains only the hex encoding of the derived selector.
/// A provisioned secret is an owner digest followed by at least one P-256 private
/// key (normally 32 bytes). The private bytes are hashed only to derive an opaque
/// handle and are zeroed before this lookup returns. Neither identity bytes nor
/// key bytes are returned from this adapter.
pub(crate) struct PlatformCredentialStore;

impl PlatformCredentialStore {
    pub(crate) const fn new() -> Self { Self }

    fn entry(binding: CredentialBinding) -> Result<Entry, CredentialStoreError> {
        let selector = selector_text(binding);
        Entry::new(CREDENTIAL_SERVICE, &selector).map_err(map_keyring_error)
    }
}

impl CredentialStore for PlatformCredentialStore {
    fn lookup(&self, binding: CredentialBinding) -> Result<CredentialHandle, CredentialStoreError> {
        let entry = Self::entry(binding)?;
        let mut record = entry.get_secret().map_err(map_keyring_error)?;
        let result = decode_record(binding, &record);
        record.fill(0);
        result
    }
}

fn selector_text(binding: CredentialBinding) -> String {
    let mut selector = String::with_capacity(3 + 64);
    selector.push_str("v1-");
    for byte in binding.selector() {
        use core::fmt::Write;
        let _ = write!(selector, "{byte:02x}");
    }
    selector
}

fn decode_record(
    binding: CredentialBinding,
    record: &[u8],
) -> Result<CredentialHandle, CredentialStoreError> {
    if record.len() < OWNER_BYTES + MIN_PRIVATE_KEY_BYTES
        || record[..OWNER_BYTES] != binding.owner()
    {
        return Err(CredentialStoreError::Mismatch);
    }
    let key_digest = digest::digest(&digest::SHA256, &record[OWNER_BYTES..]);
    let mut slot = [0u8; 8];
    slot.copy_from_slice(&key_digest.as_ref()[..8]);
    Ok(CredentialHandle::from_slot(u64::from_be_bytes(slot)))
}

fn map_keyring_error(error: keyring::Error) -> CredentialStoreError {
    match error {
        keyring::Error::NoEntry => CredentialStoreError::Missing,
        keyring::Error::Ambiguous(_) => CredentialStoreError::Duplicate,
        keyring::Error::NoStorageAccess(_) | keyring::Error::PlatformFailure(_) => {
            CredentialStoreError::Unavailable
        }
        keyring::Error::BadEncoding(_)
        | keyring::Error::TooLong(_, _)
        | keyring::Error::Invalid(_, _) => CredentialStoreError::Mismatch,
        _ => CredentialStoreError::Unavailable,
    }
}

/// Minimal deterministic storage used by the bootstrap operation's injectable
/// test seam. Production code uses [`PlatformCredentialStore`] instead.
///
/// Entries are selector-indexed records, not a plaintext fallback. Lookup is an
/// all-or-failure operation: unavailable, absent, mismatched, and duplicate
/// records never produce a handle.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct InMemoryCredentialStore {
    entries: Vec<CredentialRecord>,
    unavailable: bool,
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct CredentialRecord {
    selector: [u8; 32],
    owner: [u8; 32],
    handle: CredentialHandle,
}

#[cfg(test)]
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

#[cfg(test)]
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
        let selector = selector_text(first);
        assert!(selector.starts_with("v1-"));
        assert!(!selector.contains('1') || selector.len() > 3);
        let mut store = InMemoryCredentialStore::new();
        assert_eq!(store.lookup(first), Err(CredentialStoreError::Missing));
        store.register_mismatched(first, 7);
        assert_eq!(store.lookup(first), Err(CredentialStoreError::Mismatch));
        store.register(first, 8);
        assert_eq!(store.lookup(first), Err(CredentialStoreError::Duplicate));
        store.set_unavailable(true);
        assert_eq!(store.lookup(first), Err(CredentialStoreError::Unavailable));
    }

    #[test]
    fn platform_record_returns_only_a_redacted_handle() {
        let binding = CredentialBinding::new([0x55; 32]);
        let mut record = Vec::from(binding.owner());
        record.extend_from_slice(&[0x42; MIN_PRIVATE_KEY_BYTES]);
        let handle = decode_record(binding, &record).expect("valid platform record");
        assert_eq!(format!("{handle:?}"), "CredentialHandle(REDACTED)");
        assert_eq!(decode_record(binding, &[0; OWNER_BYTES + MIN_PRIVATE_KEY_BYTES]), Err(CredentialStoreError::Mismatch));
        assert_eq!(decode_record(binding, &[0; OWNER_BYTES]), Err(CredentialStoreError::Mismatch));
    }
}
