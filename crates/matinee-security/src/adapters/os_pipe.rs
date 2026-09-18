//! Private inherited operating-system pipe boundary.
//!
//! Bootstrap uses an anonymous inherited handle only. Envelope parsing and
//! validation belong to the bootstrap implementation; this seam exposes no
//! plaintext or platform error details.

use core::fmt;
use core::cell::Cell;

#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};

#[cfg(unix)]
enum OwnedPlatformHandle {
    Unix(OwnedFd),
    #[cfg(test)]
    Test,
}
#[cfg(windows)]
enum OwnedPlatformHandle {
    Windows(OwnedHandle),
    #[cfg(test)]
    Test,
}
#[cfg(not(any(unix, windows)))]
enum OwnedPlatformHandle {
    #[cfg(test)]
    Test,
}

/// Opaque inherited handle owned by the bootstrap transition.
///
/// Unix acquisition performs `fcntl(F_GETFD)` to validate the descriptor and
/// `fcntl(F_SETFD, FD_CLOEXEC)` before wrapping it in `OwnedFd`; Windows
/// acquisition performs `GetHandleInformation` and clears `HANDLE_FLAG_INHERIT`
/// with `SetHandleInformation`. `close` is idempotent and is used on every
/// success and error path; dropping a still-open value closes it as a final
/// guard through the owned-handle type.
pub(crate) struct InheritedPipe {
    handle: Option<OwnedPlatformHandle>,
    close_on_exec: bool,
    closed: bool,
}
impl PartialEq for InheritedPipe {
    fn eq(&self, other: &Self) -> bool {
        self.closed == other.closed
            && self.close_on_exec == other.close_on_exec
            && self.is_present() == other.is_present()
    }
}

impl Eq for InheritedPipe {}

impl InheritedPipe {
    /// Test-only/raw adapter construction. Production acquisition uses the
    /// explicit inherited constructor below and therefore performs OS effects.
    #[cfg(test)]
    pub(crate) fn from_handle(handle: u64) -> Self {
        Self {
            handle: (handle != 0).then_some(OwnedPlatformHandle::Test),
            close_on_exec: false,
            closed: false,
        }
    }

    pub(crate) fn from_inherited_handle(handle: u64) -> Result<Self, OsPipeError> {
        if handle == 0 { return Err(OsPipeError::Missing); }

        #[cfg(unix)]
        {
            if handle > RawFd::MAX as u64 { return Err(OsPipeError::Missing); }
            let raw = handle as RawFd;
            // F_GETFD validates that ownership can be transferred without
            // manufacturing an OwnedFd for an invalid descriptor.
            let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
            if flags == -1 { return Err(OsPipeError::Missing); }
            if unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
                return Err(OsPipeError::Unavailable);
            }
            // SAFETY: F_GETFD succeeded, and this constructor takes ownership
            // of the descriptor exactly once.
            let owned = unsafe { OwnedFd::from_raw_fd(raw) };
            return Ok(Self {
                handle: Some(OwnedPlatformHandle::Unix(owned)),
                close_on_exec: true,
                closed: false,
            });
        }

        #[cfg(windows)]
        {
            if handle == u64::MAX { return Err(OsPipeError::Missing); }
            let raw = handle as usize as RawHandle;
            let mut flags = 0u32;
            if unsafe { GetHandleInformation(raw, &mut flags) } == 0 {
                return Err(OsPipeError::Missing);
            }
            // Windows' equivalent of close-on-exec for an inherited handle is
            // removing HANDLE_FLAG_INHERIT before the next child is spawned.
            if unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT, 0) } == 0 {
                return Err(OsPipeError::Unavailable);
            }
            // SAFETY: GetHandleInformation succeeded, and this constructor
            // takes ownership of the handle exactly once.
            let owned = unsafe { OwnedHandle::from_raw_handle(raw) };
            return Ok(Self {
                handle: Some(OwnedPlatformHandle::Windows(owned)),
                close_on_exec: true,
                closed: false,
            });
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = handle;
            Err(OsPipeError::Unavailable)
        }
    }

    pub(crate) const fn is_present(&self) -> bool {
        self.handle.is_some() && !self.closed
    }

    pub(crate) const fn close_on_exec(&self) -> bool { self.close_on_exec }
    pub(crate) const fn is_closed(&self) -> bool { self.closed }

    /// Close the inherited handle. The operation is safe to repeat.
    pub(crate) fn close(&mut self) {
        // Taking the owned value delegates the one actual close to OwnedFd or
        // OwnedHandle. A second close observes None and cannot double-close a
        // descriptor that may already have been reused by the caller.
        let _ = self.handle.take();
        self.closed = true;
    }

    /// Explicit error-path close, kept separate at call sites for auditability.
    pub(crate) fn close_on_error(&mut self) { self.close(); }
}

impl fmt::Debug for InheritedPipe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InheritedPipe(REDACTED)")
    }
}

impl Drop for InheritedPipe {
    fn drop(&mut self) { self.close(); }
}

/// Production inherited-pipe source. The caller supplies the raw inherited
/// descriptor/handle exactly once; [`InheritedPipe`] then owns and closes it.
pub(crate) struct PlatformOsPipe {
    handle: Cell<Option<u64>>,
}
impl PlatformOsPipe {
    pub(crate) const fn new(handle: u64) -> Self { Self { handle: Cell::new(Some(handle)) } }
}

impl OsPipe for PlatformOsPipe {
    fn acquire(&self) -> Result<InheritedPipe, OsPipeError> {
        let handle = self.handle.take().ok_or(OsPipeError::Missing)?;
        InheritedPipe::from_inherited_handle(handle)
}
}

/// Closed, fail-closed outcomes from inherited-pipe acquisition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OsPipeError {
    Missing,
    Mismatch,
    Duplicate,
    Unavailable,
    Malformed,
    Oversized,
}

/// The sole inherited-pipe seam owned by this crate.
pub(crate) trait OsPipe {
    fn acquire(&self) -> Result<InheritedPipe, OsPipeError>;
}

/// The bounded identity envelope carried over an inherited pipe. Private key
/// bytes have no field in this type and therefore cannot cross the boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BootstrapEnvelope {
    pub(crate) nonce: [u8; 32],
    pub(crate) state_directory: uuid::Uuid,
    pub(crate) daemon: uuid::Uuid,
    pub(crate) bootstrap: uuid::Uuid,
    pub(crate) public_key: [u8; 65],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnvelopeError {
    Eof,
    Oversized,
    Malformed,
    Duplicate,
    Unknown,
    InvalidUtf8,
    InvalidType,
    Trailing,
}

const ENVELOPE_VERSION: u8 = 1;
const MAX_ENVELOPE_BYTES: usize = 512;
const MAX_ENDPOINT_BYTES: usize = 256;

impl BootstrapEnvelope {
    pub(crate) fn new(
        nonce: [u8; 32], state_directory: uuid::Uuid, daemon: uuid::Uuid,
        bootstrap: uuid::Uuid, public_key: [u8; 65],
    ) -> Result<Self, EnvelopeError> {
        if p256::PublicKey::from_sec1_bytes(&public_key).is_err() {
            return Err(EnvelopeError::Malformed);
        }
        Ok(Self { nonce, state_directory, daemon, bootstrap, public_key })
    }

    /// Canonical fixed-field encoding: version, five length-prefixed fields, and no
    /// extension bytes. Lengths are big-endian u16 and every field occurs once.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 2 + 32 + 2 + 16 * 3 + 2 + 65);
        out.push(ENVELOPE_VERSION);
        for field in [
            self.nonce.as_slice(), self.state_directory.as_bytes().as_slice(),
            self.daemon.as_bytes().as_slice(), self.bootstrap.as_bytes().as_slice(),
            self.public_key.as_slice(),
        ] {
            out.extend_from_slice(&(field.len() as u16).to_be_bytes());
            out.extend_from_slice(field);
        }
        out
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() > MAX_ENVELOPE_BYTES { return Err(EnvelopeError::Oversized); }
        let mut cursor = 0usize;
        let version = take(bytes, &mut cursor, 1)?[0];
        if version != ENVELOPE_VERSION { return Err(EnvelopeError::Unknown); }
        let nonce = take_field(bytes, &mut cursor, 32)?;
        let state = take_field(bytes, &mut cursor, 16)?;
        let daemon = take_field(bytes, &mut cursor, 16)?;
        let bootstrap = take_field(bytes, &mut cursor, 16)?;
        let key = take_field(bytes, &mut cursor, 65)?;
        if cursor != bytes.len() { return Err(EnvelopeError::Trailing); }
        let mut n = [0; 32]; n.copy_from_slice(nonce);
        let mut p = [0; 65]; p.copy_from_slice(key);
        Self::new(
            n,
            uuid::Uuid::from_slice(state).map_err(|_| EnvelopeError::InvalidType)?,
            uuid::Uuid::from_slice(daemon).map_err(|_| EnvelopeError::InvalidType)?,
            uuid::Uuid::from_slice(bootstrap).map_err(|_| EnvelopeError::InvalidType)?,
            p,
        )
    }

    /// Decode and bound the endpoint supplied by the owning transport.
    pub(crate) fn parse_endpoint(bytes: &[u8]) -> Result<&str, EnvelopeError> {
        if bytes.is_empty() || bytes.len() > MAX_ENDPOINT_BYTES {
            return Err(EnvelopeError::InvalidType);
        }
        let endpoint = core::str::from_utf8(bytes).map_err(|_| EnvelopeError::InvalidUtf8)?;
        if endpoint.chars().any(char::is_control) { return Err(EnvelopeError::InvalidType); }
        Ok(endpoint)
    }
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, count: usize) -> Result<&'a [u8], EnvelopeError> {
    let end = cursor.checked_add(count).ok_or(EnvelopeError::Eof)?;
    if end > bytes.len() { return Err(EnvelopeError::Eof); }
    let value = &bytes[*cursor..end]; *cursor = end; Ok(value)
}

fn take_field<'a>(bytes: &'a [u8], cursor: &mut usize, expected: usize) -> Result<&'a [u8], EnvelopeError> {
    let len = u16::from_be_bytes(take(bytes, cursor, 2)?.try_into().unwrap()) as usize;
    if len != expected { return Err(if len > expected { EnvelopeError::Oversized } else { EnvelopeError::Malformed }); }
    take(bytes, cursor, len)
}

/// A nonce ledger used by one bootstrap invocation. Consumption is atomic from
/// the caller's perspective: a nonce is either newly inserted or rejected.
#[derive(Default)]
pub(crate) struct NonceLedger(std::collections::HashSet<[u8; 32]>);
impl NonceLedger {
    pub(crate) fn consume(&mut self, nonce: [u8; 32]) -> Result<(), EnvelopeError> {
        if self.0.insert(nonce) { Ok(()) } else { Err(EnvelopeError::Duplicate) }
    }
    pub(crate) fn release(&mut self, nonce: &[u8; 32]) { self.0.remove(nonce); }
}

#[cfg(windows)]
const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetHandleInformation(handle: RawHandle, flags: *mut u32) -> i32;
    fn SetHandleInformation(handle: RawHandle, mask: u32, flags: u32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_P256_POINT: [u8; 65] = [
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
        0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
        0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
        0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
        0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
    ];

    #[test]
    fn handle_is_opaque_and_empty_handle_is_not_present() {
        assert!(!InheritedPipe::from_handle(0).is_present());
        assert!(InheritedPipe::from_handle(9).is_present());
        assert_eq!(format!("{:?}", InheritedPipe::from_handle(9)), "InheritedPipe(REDACTED)");
    }

    #[test]
    fn acquisition_outcomes_are_closed() {
        let outcomes = [
            OsPipeError::Missing, OsPipeError::Mismatch, OsPipeError::Duplicate,
            OsPipeError::Unavailable, OsPipeError::Malformed, OsPipeError::Oversized,
        ];
        assert_eq!(outcomes.len(), 6);
        assert!(outcomes.contains(&OsPipeError::Unavailable));
    }

    #[test]
    fn canonical_envelope_round_trip_and_closed_malformed_outcomes() {
        let envelope = BootstrapEnvelope::new(
            [7; 32], uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2),
            uuid::Uuid::from_u128(3), VALID_P256_POINT,
        ).unwrap();
        assert_eq!(BootstrapEnvelope::parse(&envelope.encode()), Ok(envelope.clone()));
        let mut truncated = envelope.encode(); truncated.pop();
        assert_eq!(BootstrapEnvelope::parse(&truncated), Err(EnvelopeError::Eof));
        let mut trailing = envelope.encode(); trailing.push(0);
        assert_eq!(BootstrapEnvelope::parse(&trailing), Err(EnvelopeError::Trailing));
        let mut wrong = envelope.encode(); wrong[0] = 9;
        assert_eq!(BootstrapEnvelope::parse(&wrong), Err(EnvelopeError::Unknown));
    }

    #[test]
    fn nonce_ledger_consumes_once_and_allows_explicit_rollback() {
        let mut ledger = NonceLedger::default();
        assert!(ledger.consume([1; 32]).is_ok());
        assert_eq!(ledger.consume([1; 32]), Err(EnvelopeError::Duplicate));
        ledger.release(&[1; 32]);
        assert!(ledger.consume([1; 32]).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn owned_fd_sets_cloexec_and_drop_closes_with_ebadf() {
        use std::os::fd::IntoRawFd;
        let (left, _right) = std::os::unix::net::UnixStream::pair().unwrap();
        let raw = left.into_raw_fd();
        let pipe = InheritedPipe::from_inherited_handle(raw as u64).unwrap();
        assert!(pipe.close_on_exec());
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        assert_ne!(flags, -1);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        drop(pipe);
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_error_close_closes_owned_fd_exactly_once() {
        use std::os::fd::IntoRawFd;
        let (left, _right) = std::os::unix::net::UnixStream::pair().unwrap();
        let raw = left.into_raw_fd();
        let mut pipe = InheritedPipe::from_inherited_handle(raw as u64).unwrap();
        pipe.close_on_error();
        pipe.close();
        assert!(pipe.is_closed());
        assert!(!pipe.is_present());
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }
}
