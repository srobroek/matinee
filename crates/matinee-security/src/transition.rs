//! Bootstrap transition boundary: validation, required-event gating, and atomic state.
use crate::adapters::credential_store::{CredentialBinding, CredentialStore, CredentialStoreError};
use crate::adapters::os_pipe::{BootstrapEnvelope, EnvelopeError, NonceLedger};
use crate::events::{emit_required, EventBoundary, EventOutcome, EventTime, EndpointClass, MetadataEntry, SafeNextAction, SecurityCode, SecurityEvent, SecurityEventSink, SecurityEventSinkResult};
use crate::identity::{CredentialReference, DaemonIdentity, Fingerprint, IdentityId, PublicKey, TransitionId, TransitionOutcome};
use ring::digest;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CrashPoint { BeforeEvent, AfterEvent, AfterCommit }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapError {
    Envelope(EnvelopeError), Credential(CredentialStoreError), EventUnavailable,
    IdentityMismatch, AlreadyUsed, Crash(CrashPoint), InvalidKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BootstrapRecord { pub(crate) state: IdentityId, pub(crate) daemon: IdentityId, pub(crate) bootstrap: uuid::Uuid, pub(crate) fingerprint: Fingerprint }

#[derive(Default)]
pub(crate) struct BootstrapState {
    active: Option<BootstrapRecord>,
    staged: Option<BootstrapRecord>,
    ledger: NonceLedger,
}
impl BootstrapState {
    pub(crate) fn active(&self) -> Option<&BootstrapRecord> { self.active.as_ref() }
    pub(crate) fn staged(&self) -> Option<&BootstrapRecord> { self.staged.as_ref() }
    pub(crate) fn recover(&mut self) { if self.active.is_none() { self.staged = None; } else { self.staged = None; } }

    pub(crate) fn apply<S: SecurityEventSink, C: CredentialStore>(
        &mut self, envelope: &BootstrapEnvelope, credential: &C, sink: Option<&mut S>,
        crash: Option<CrashPoint>, endpoint: &str,
    ) -> Result<TransitionOutcome, BootstrapError> {
        if let Some(active) = &self.active {
            if active.bootstrap == envelope.bootstrap && active.fingerprint.as_str() == fingerprint(envelope.public_key).map_err(|_| BootstrapError::InvalidKey)?.as_str() {
                return Ok(TransitionOutcome::AlreadyCommitted);
            }
            return Err(BootstrapError::IdentityMismatch);
        }
        self.ledger.consume(envelope.nonce).map_err(|_| BootstrapError::AlreadyUsed)?;
        let binding = CredentialBinding::for_identities(envelope.state_directory, envelope.daemon);
        if let Err(error) = credential.lookup(binding) {
            self.ledger.release(&envelope.nonce);
            return Err(BootstrapError::Credential(error));
        }
        if matches!(crash, Some(CrashPoint::BeforeEvent)) { self.ledger.release(&envelope.nonce); return Err(BootstrapError::Crash(CrashPoint::BeforeEvent)); }
        let fp = fingerprint(envelope.public_key).map_err(|_| BootstrapError::InvalidKey)?;
        let event = SecurityEvent::new(
            envelope.bootstrap, EventBoundary::Bootstrap, SecurityCode::EnrollmentAccepted,
            EventOutcome::Committed, SafeNextAction::Continue, None, None, EndpointClass::Native,
            EventTime(0), envelope.state_directory,
            vec![MetadataEntry { key: "operation".into(), value: "bootstrap".into() }],
        ).map_err(|_| { self.ledger.release(&envelope.nonce); BootstrapError::EventUnavailable })?;
        emit_required(sink, event).map_err(|_| { self.ledger.release(&envelope.nonce); BootstrapError::EventUnavailable })?;
        if matches!(crash, Some(CrashPoint::AfterEvent)) { self.ledger.release(&envelope.nonce); return Err(BootstrapError::Crash(CrashPoint::AfterEvent)); }
        let record = BootstrapRecord { state: IdentityId::new(envelope.state_directory), daemon: IdentityId::new(envelope.daemon), bootstrap: envelope.bootstrap, fingerprint: fp };
        self.staged = Some(record.clone());
        self.active = self.staged.take();
        if matches!(crash, Some(CrashPoint::AfterCommit)) { return Err(BootstrapError::Crash(CrashPoint::AfterCommit)); }
        let _ = endpoint;
        Ok(TransitionOutcome::Committed)
    }
}

fn fingerprint(bytes: [u8; 65]) -> Result<Fingerprint, &'static str> {
    if bytes[0] != 0x04 { return Err("invalid public key"); }
    let digest = digest::digest(&digest::SHA256, &bytes);
    let mut text = String::with_capacity(64);
    for b in digest.as_ref() { use core::fmt::Write; write!(&mut text, "{b:02x}").unwrap(); }
    Fingerprint::new(text)
}

#[allow(dead_code)]
fn _keep_types(_: CredentialReference, _: DaemonIdentity, _: PublicKey, _: TransitionId) {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn fingerprint_is_lowercase_sha256() {
        let fp = fingerprint([0x04; 65]).unwrap();
        assert_eq!(fp.as_str().len(), 64); assert!(fp.as_str().bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }
}
