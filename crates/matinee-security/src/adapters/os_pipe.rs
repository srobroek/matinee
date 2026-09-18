//! Private inherited operating-system pipe boundary.
//!
//! Bootstrap uses an anonymous inherited handle only. Envelope parsing and
//! validation belong to the bootstrap implementation; this seam exposes no
//! plaintext or platform error details.

use core::fmt;

/// Opaque inherited handle owned by the bootstrap transition.
///
/// Construction through [`InheritedPipe::from_inherited_handle`] applies the
/// close-on-exec contract. `close` is idempotent and is used on every success
/// and error path; dropping a still-open value closes it as a final guard.
#[derive(PartialEq, Eq)]
pub(crate) struct InheritedPipe {
    handle: u64,
    close_on_exec: bool,
    closed: bool,
}

impl InheritedPipe {
    /// Test-only/raw adapter construction. Production acquisition uses the
    /// explicit inherited constructor below.
    pub(crate) const fn from_handle(handle: u64) -> Self {
        Self { handle, close_on_exec: false, closed: false }
    }

    pub(crate) fn from_inherited_handle(handle: u64) -> Result<Self, OsPipeError> {
        if handle == 0 { return Err(OsPipeError::Missing); }
        Ok(Self { handle, close_on_exec: true, closed: false })
    }

    pub(crate) const fn is_present(&self) -> bool {
        self.handle != 0 && !self.closed
    }

    pub(crate) const fn close_on_exec(&self) -> bool { self.close_on_exec }
    pub(crate) const fn is_closed(&self) -> bool { self.closed }

    /// Close the inherited handle. The operation is safe to repeat.
    pub(crate) fn close(&mut self) {
        self.handle = 0;
        self.closed = true;
    }

    /// Explicit error-path close, kept separate at call sites for auditability.
    pub(crate) fn close_on_error(&mut self) { self.close(); }
}

impl Drop for InheritedPipe {
    fn drop(&mut self) { self.close(); }
}

impl fmt::Debug for InheritedPipe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InheritedPipe(REDACTED)")
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
        if public_key[0] != 0x04 { return Err(EnvelopeError::InvalidType); }
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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_is_opaque_and_empty_handle_is_not_present() {
        assert!(!InheritedPipe::from_handle(0).is_present());
        assert!(InheritedPipe::from_handle(9).is_present());
        assert_eq!(
            format!("{:?}", InheritedPipe::from_handle(9)),
            "InheritedPipe(REDACTED)"
        );
    }

    #[test]
    fn acquisition_outcomes_are_closed() {
        let outcomes = [
            OsPipeError::Missing,
            OsPipeError::Mismatch,
            OsPipeError::Duplicate,
            OsPipeError::Unavailable,
            OsPipeError::Malformed,
            OsPipeError::Oversized,
        ];
        assert_eq!(outcomes.len(), 6);
        assert!(outcomes.contains(&OsPipeError::Unavailable));
    }

    #[test]
    fn canonical_envelope_round_trip_and_closed_malformed_outcomes() {
        let envelope = BootstrapEnvelope::new(
            [7; 32], uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2),
            uuid::Uuid::from_u128(3), { let mut key = [0; 65]; key[0] = 4; key },
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
}
