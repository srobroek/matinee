use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use uuid::Uuid;

use crate::{
    Capability, CapabilityAction, ChannelSession, ChannelSigner, ChannelSigningError,
    ClientHandshake, ClientHandshakeConfig, ConnectionId, CredentialReference, Fingerprint,
    IdentityId, ObjectOwner, PayloadKind, Principal, PrincipalKind, ProjectionClass, PublicKey,
    SecurityEvent, SecurityEventSink, SecurityEventSinkResult, ServerHandshake,
    ServerHandshakeConfig, SessionInput, SessionProjection,
};

pub(crate) const ENDPOINT: &str = "127.0.0.1:7777";
pub(crate) const PRINCIPAL: u128 = 2;
pub(crate) const DAEMON: u128 = 3;
pub(crate) const CONNECTION: u128 = 0xabcdefabcdefabcdefabcdefabcd;
pub(crate) const STATE_DIRECTORY: u128 = 0x5d;
/// Every fixture principal owns its objects through the daemon identity that registered it.
pub(crate) const OWNER: u128 = DAEMON;
/// The scope fixture sessions request. It sits under the fixture ceiling `matinee`.
pub(crate) const SCOPE: &str = "matinee/status";

pub(crate) struct RingSigner {
    key: EcdsaKeyPair,
    public: PublicKey,
}

impl RingSigner {
    pub(crate) fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("fixture key generation");
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .expect("fixture key import");
        let public = PublicKey::from_uncompressed(
            key.public_key()
                .as_ref()
                .try_into()
                .expect("P-256 public key length"),
        )
        .expect("valid fixture public key");
        Self { key, public }
    }
}

impl ChannelSigner for RingSigner {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign_p1363(&self, transcript: &[u8]) -> Result<[u8; 64], ChannelSigningError> {
        let signature = self
            .key
            .sign(&SystemRandom::new(), transcript)
            .map_err(|_| ChannelSigningError)?;
        signature
            .as_ref()
            .try_into()
            .map_err(|_| ChannelSigningError)
    }
}

#[derive(Default)]
pub(crate) struct RecordingSink {
    pub(crate) events: Vec<SecurityEvent>,
    pub(crate) unavailable: bool,
}

impl SecurityEventSink for RecordingSink {
    fn emit(&mut self, event: SecurityEvent) -> SecurityEventSinkResult {
        if self.unavailable {
            SecurityEventSinkResult::Unavailable
        } else {
            self.events.push(event);
            SecurityEventSinkResult::Accepted
        }
    }
}

pub(crate) fn id(value: u128) -> IdentityId {
    IdentityId::new(Uuid::from_u128(value))
}

pub(crate) fn capability(action: CapabilityAction, scope: &str) -> Capability {
    Capability::new(action, scope).expect("bounded capability scope")
}

/// A registered principal at exactly `epoch`.
///
/// The authentication epoch is not settable: it only advances through a completed rotation,
/// so the fixture rotates the principal until it carries the epoch a session needs. That is
/// the same path production takes, which is why a session can trust the epoch it reads.
pub(crate) fn registered_principal(
    id_value: u128,
    kind: PrincipalKind,
    key: PublicKey,
    ceiling: Vec<Capability>,
    epoch: u64,
) -> Principal {
    let owner = id(OWNER);
    let mut principal = Principal::new(
        id(id_value),
        kind,
        key,
        Fingerprint::new("a".repeat(64)).expect("64 lowercase hex digits"),
        owner,
        ceiling,
        CredentialReference::new("fixture-store", "principal-key", owner, id(STATE_DIRECTORY))
            .expect("bounded credential reference"),
    )
    .expect("valid principal binding");
    principal.activate().expect("pending principal");
    for index in 0..epoch {
        principal.begin_rotation().expect("active principal");
        principal
            .complete_rotation(
                Fingerprint::new(format!("{index:064x}")).expect("64 lowercase hex digits"),
                CredentialReference::new(
                    "fixture-store",
                    "principal-key",
                    owner,
                    id(STATE_DIRECTORY),
                )
                .expect("bounded credential reference"),
            )
            .expect("rotating principal");
    }
    assert_eq!(principal.epoch(), epoch);
    principal
}

/// The MCP-client principal fixture sessions authenticate, with a `matinee` read ceiling.
pub(crate) fn fixture_principal(key: PublicKey, epoch: u64) -> Principal {
    registered_principal(
        PRINCIPAL,
        PrincipalKind::McpClient,
        key,
        vec![capability(CapabilityAction::Read, "matinee")],
        epoch,
    )
}

/// The operation a fixture daemon session authorizes: an owned object read at `SCOPE`.
pub(crate) fn owned_operation(kind: PayloadKind) -> SessionInput<'static> {
    SessionInput::new(
        capability(CapabilityAction::Read, SCOPE),
        kind,
        ObjectOwner::Owned(id(OWNER)),
        None,
    )
}

/// The projection a fixture daemon session discloses: an owned object at `SCOPE`.
pub(crate) fn owned_projection(class: ProjectionClass, payload: &[u8]) -> SessionProjection<'_> {
    SessionProjection::new(
        class,
        capability(CapabilityAction::Read, SCOPE),
        ObjectOwner::Owned(id(OWNER)),
        None,
        payload,
    )
}

pub(crate) fn establish_pair(epoch: u64) -> (ChannelSession, ChannelSession) {
    establish_pair_with_ranges(epoch, (1, 3), (2, 4)).expect("production handshake fixture")
}

pub(crate) fn establish_pair_with_ranges(
    epoch: u64,
    client_range: (u16, u16),
    server_range: (u16, u16),
) -> Result<(ChannelSession, ChannelSession), crate::SecurityFailure> {
    establish_pair_at_epochs(epoch, epoch, client_range, server_range)
}

/// Establish a pair where the client believes it authenticates at `client_epoch` while the
/// registry holds the principal at `principal_epoch`.
pub(crate) fn establish_pair_at_epochs(
    client_epoch: u64,
    principal_epoch: u64,
    client_range: (u16, u16),
    server_range: (u16, u16),
) -> Result<(ChannelSession, ChannelSession), crate::SecurityFailure> {
    let client_signer = RingSigner::generate();
    let server_signer = RingSigner::generate();
    let client = ClientHandshakeConfig::new(
        ENDPOINT,
        id(PRINCIPAL),
        client_signer.public.clone(),
        id(DAEMON),
        server_signer.public.clone(),
        client_epoch,
        client_range.0,
        client_range.1,
    )?;
    let server = ServerHandshakeConfig::new(
        ENDPOINT,
        fixture_principal(client_signer.public.clone(), principal_epoch),
        id(DAEMON),
        server_signer.public.clone(),
        server_range.0,
        server_range.1,
        ConnectionId::new(Uuid::from_u128(CONNECTION)),
    )?;
    let mut sink = RecordingSink::default();
    let (client_pending, hello) = ClientHandshake::start(client)?;
    let (server_pending, proof) =
        ServerHandshake::accept(server, &hello, &server_signer, &mut sink)?;
    let (client_session, client_proof) =
        client_pending.finish(&proof, &client_signer, &mut sink)?;
    let server_session = server_pending.finish(&client_proof, &mut sink)?;
    Ok((client_session, server_session))
}
