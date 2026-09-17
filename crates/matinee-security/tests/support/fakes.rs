use crate::adapters::{credential_store, os_pipe};
use crate::events::{self, SecurityEvent};

#[derive(Clone, Copy)]
enum CredentialOutcome {
    Handle(u64),
    Missing,
    Mismatch,
    Duplicate,
    Unavailable,
}

pub(crate) struct FakeCredentialStore {
    entries: Vec<(credential_store::CredentialBinding, CredentialOutcome)>,
}
impl FakeCredentialStore {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
    pub(crate) fn registered(
        mut self,
        binding: credential_store::CredentialBinding,
        slot: u64,
    ) -> Self {
        self.entries
            .push((binding, CredentialOutcome::Handle(slot)));
        self
    }
    pub(crate) fn with_error(
        mut self,
        binding: credential_store::CredentialBinding,
        error: credential_store::CredentialStoreError,
    ) -> Self {
        let outcome = match error {
            credential_store::CredentialStoreError::Missing => CredentialOutcome::Missing,
            credential_store::CredentialStoreError::Mismatch => CredentialOutcome::Mismatch,
            credential_store::CredentialStoreError::Duplicate => CredentialOutcome::Duplicate,
            credential_store::CredentialStoreError::Unavailable => CredentialOutcome::Unavailable,
        };
        self.entries.push((binding, outcome));
        self
    }
}
impl credential_store::CredentialStore for FakeCredentialStore {
    fn lookup(
        &self,
        binding: credential_store::CredentialBinding,
    ) -> Result<credential_store::CredentialHandle, credential_store::CredentialStoreError> {
        match self
            .entries
            .iter()
            .find(|(candidate, _)| *candidate == binding)
            .map(|(_, outcome)| *outcome)
        {
            Some(CredentialOutcome::Handle(slot)) => {
                Ok(credential_store::CredentialHandle::from_slot(slot))
            }
            Some(CredentialOutcome::Missing) | None => {
                Err(credential_store::CredentialStoreError::Missing)
            }
            Some(CredentialOutcome::Mismatch) => {
                Err(credential_store::CredentialStoreError::Mismatch)
            }
            Some(CredentialOutcome::Duplicate) => {
                Err(credential_store::CredentialStoreError::Duplicate)
            }
            Some(CredentialOutcome::Unavailable) => {
                Err(credential_store::CredentialStoreError::Unavailable)
            }
        }
    }
}

enum PipeOutcome {
    Present(u64),
    Missing,
    Mismatch,
    Unavailable,
}
pub(crate) struct FakeOsPipe {
    outcome: PipeOutcome,
}
impl FakeOsPipe {
    pub(crate) fn present(handle: u64) -> Self {
        Self {
            outcome: PipeOutcome::Present(handle),
        }
    }
    pub(crate) fn error(error: os_pipe::OsPipeError) -> Self {
        let outcome = match error {
            os_pipe::OsPipeError::Missing => PipeOutcome::Missing,
            os_pipe::OsPipeError::Mismatch => PipeOutcome::Mismatch,
            os_pipe::OsPipeError::Unavailable => PipeOutcome::Unavailable,
            _ => PipeOutcome::Unavailable,
        };
        Self { outcome }
    }
}
impl os_pipe::OsPipe for FakeOsPipe {
    fn acquire(&self) -> Result<os_pipe::InheritedPipe, os_pipe::OsPipeError> {
        match self.outcome {
            PipeOutcome::Present(handle) => Ok(os_pipe::InheritedPipe::from_handle(handle)),
            PipeOutcome::Missing => Err(os_pipe::OsPipeError::Missing),
            PipeOutcome::Mismatch => Err(os_pipe::OsPipeError::Mismatch),
            PipeOutcome::Unavailable => Err(os_pipe::OsPipeError::Unavailable),
        }
    }
}

pub(crate) struct FakeEventSink {
    result: events::SecurityEventSinkResult,
    received: Vec<SecurityEvent>,
}
impl FakeEventSink {
    pub(crate) fn new(result: events::SecurityEventSinkResult) -> Self {
        Self {
            result,
            received: Vec::new(),
        }
    }
    pub(crate) fn accepted() -> Self {
        Self::new(events::SecurityEventSinkResult::Accepted)
    }
    pub(crate) fn aggregated() -> Self {
        Self::new(events::SecurityEventSinkResult::Aggregated)
    }
    pub(crate) fn unavailable() -> Self {
        Self::new(events::SecurityEventSinkResult::Unavailable)
    }
    pub(crate) fn received(&self) -> &[SecurityEvent] {
        &self.received
    }
}
impl events::SecurityEventSink for FakeEventSink {
    fn emit(&mut self, event: SecurityEvent) -> events::SecurityEventSinkResult {
        self.received.push(event);
        self.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::credential_store::CredentialStore;
    use crate::adapters::os_pipe::OsPipe;
    use crate::events::SecurityEventSink;
    use crate::events::{
        EndpointClass, EventBoundary, EventOutcome, EventTime, SafeNextAction, SecurityCode,
    };
    use uuid::Uuid;
    fn event() -> SecurityEvent {
        SecurityEvent::new(
            Uuid::nil(),
            EventBoundary::Input,
            SecurityCode::MalformedInput,
            EventOutcome::Rejected,
            SafeNextAction::FailClosed,
            None,
            None,
            EndpointClass::Unknown,
            EventTime(0),
            Uuid::nil(),
            Vec::new(),
        )
        .unwrap()
    }
    #[test]
    fn fakes_cover_valid_and_closed_paths() {
        let binding = credential_store::CredentialBinding::new([1; 32]);
        assert!(
            FakeCredentialStore::new()
                .registered(binding, 7)
                .lookup(binding)
                .is_ok()
        );
        assert_eq!(
            FakeCredentialStore::new()
                .with_error(binding, credential_store::CredentialStoreError::Mismatch)
                .lookup(binding),
            Err(credential_store::CredentialStoreError::Mismatch)
        );
        assert!(FakeOsPipe::present(3).acquire().unwrap().is_present());
        assert_eq!(
            FakeOsPipe::error(os_pipe::OsPipeError::Missing).acquire(),
            Err(os_pipe::OsPipeError::Missing)
        );
        let mut sink = FakeEventSink::accepted();
        assert_eq!(
            sink.emit(event()),
            events::SecurityEventSinkResult::Accepted
        );
        let mut aggregated = FakeEventSink::aggregated();
        assert_eq!(
            aggregated.emit(event()),
            events::SecurityEventSinkResult::Aggregated
        );
        assert_eq!(sink.received().len(), 1);
        let mut unavailable = FakeEventSink::unavailable();
        assert_eq!(
            events::emit_required(Some(&mut unavailable), event()),
            Err(events::RequiredEventError::Unavailable)
        );
    }
    #[test]
    fn opaque_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", credential_store::CredentialBinding::new([9; 32])),
            "CredentialBinding(REDACTED)"
        );
        assert_eq!(
            format!("{:?}", credential_store::CredentialHandle::from_slot(9)),
            "CredentialHandle(REDACTED)"
        );
        assert_eq!(
            format!("{:?}", os_pipe::InheritedPipe::from_handle(9)),
            "InheritedPipe(REDACTED)"
        );
    }
}
