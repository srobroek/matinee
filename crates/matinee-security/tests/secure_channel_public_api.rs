use matinee_security::{
    AuthorizedOutput, Capability, CapabilityAction, ChannelSigner, ChannelSigningError,
    ClientHandshake, ClientHandshakeConfig, ConnectionId, CredentialReference, FailureCode,
    Fingerprint, IdentityId, ObjectOwner, PayloadKind, Principal, PrincipalKind, ProjectionClass,
    PublicKey, SecurityEvent, SecurityEventSink, SecurityEventSinkResult, ServerHandshake,
    ServerHandshakeConfig, SessionInput, SessionProjection,
};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use uuid::Uuid;

const ENDPOINT: &str = "127.0.0.1:7777";
const EPOCH: u64 = 2;

struct Signer {
    key: EcdsaKeyPair,
    public: PublicKey,
}

impl Signer {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let public =
            PublicKey::from_uncompressed(key.public_key().as_ref().try_into().unwrap()).unwrap();
        Self { key, public }
    }
}

impl ChannelSigner for Signer {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign_p1363(&self, transcript: &[u8]) -> Result<[u8; 64], ChannelSigningError> {
        self.key
            .sign(&SystemRandom::new(), transcript)
            .map_err(|_| ChannelSigningError)?
            .as_ref()
            .try_into()
            .map_err(|_| ChannelSigningError)
    }
}

#[derive(Default)]
struct Sink(Vec<SecurityEvent>);

impl SecurityEventSink for Sink {
    fn emit(&mut self, event: SecurityEvent) -> SecurityEventSinkResult {
        self.0.push(event);
        SecurityEventSinkResult::Accepted
    }
}

fn id(value: u128) -> IdentityId {
    IdentityId::new(Uuid::from_u128(value))
}

fn capability(action: CapabilityAction, scope: &str) -> Capability {
    Capability::new(action, scope).unwrap()
}

/// An external consumer registers a principal exactly the way the crate boundary requires:
/// an activated snapshot whose epoch it advanced through real rotations. Each epoch before
/// the last is held by its own key, and `key` is installed by the final rotation, so the
/// signer presented at the handshake is the only credential the principal still names.
fn registered_principal(key: PublicKey, owner: IdentityId, epoch: u64) -> Principal {
    let initial = if epoch == 0 {
        key.clone()
    } else {
        Signer::generate().public
    };
    let mut principal = Principal::new(
        id(1),
        PrincipalKind::McpClient,
        initial,
        Fingerprint::new("a".repeat(64)).unwrap(),
        owner,
        vec![capability(CapabilityAction::Read, "matinee")],
        CredentialReference::new("consumer-store", "principal-key-0", owner, id(9)).unwrap(),
    )
    .unwrap();
    principal.activate().unwrap();
    for index in 0..epoch {
        let replacement = if index + 1 == epoch {
            key.clone()
        } else {
            Signer::generate().public
        };
        principal.begin_rotation().unwrap();
        principal
            .complete_rotation(
                replacement,
                Fingerprint::new(format!("{:064x}", index + 1)).unwrap(),
                CredentialReference::new(
                    "consumer-store",
                    &format!("principal-key-{}", index + 1),
                    owner,
                    id(9),
                )
                .unwrap(),
            )
            .unwrap();
    }
    assert_eq!(principal.public_key(), &key);
    principal
}

struct Pair {
    client: matinee_security::ChannelSession,
    daemon: matinee_security::ChannelSession,
    connection: ConnectionId,
    owner: IdentityId,
}

fn establish() -> Pair {
    let client_signer = Signer::generate();
    let daemon_signer = Signer::generate();
    let owner = id(2);
    let connection = ConnectionId::new(Uuid::from_u128(3));
    let client_config = ClientHandshakeConfig::new(
        ENDPOINT,
        id(1),
        client_signer.public.clone(),
        owner,
        daemon_signer.public.clone(),
        EPOCH,
        1,
        3,
    )
    .unwrap();
    let server_config = ServerHandshakeConfig::new(
        ENDPOINT,
        registered_principal(client_signer.public.clone(), owner, EPOCH),
        owner,
        daemon_signer.public.clone(),
        2,
        4,
        connection,
    )
    .unwrap();
    let mut sink = Sink::default();
    let (client_pending, hello) = ClientHandshake::start(client_config).unwrap();
    let (server_pending, proof) =
        ServerHandshake::accept(server_config, &hello, &daemon_signer, &mut sink).unwrap();
    let (client, client_proof) = client_pending
        .finish(&proof, &client_signer, &mut sink)
        .unwrap();
    let daemon = server_pending.finish(&client_proof, &mut sink).unwrap();
    Pair {
        client,
        daemon,
        connection,
        owner,
    }
}

#[test]
fn external_consumer_establishes_and_uses_only_the_typed_boundary() {
    let mut pair = establish();
    let mut sink = Sink::default();
    assert_eq!(pair.daemon.connection_id(), pair.connection);
    assert_eq!(pair.daemon.epoch(), EPOCH);
    assert_eq!(pair.client.epoch(), EPOCH);

    let output = AuthorizedOutput::filtered(PayloadKind::Command, b"status".to_vec()).unwrap();
    let frame = pair.client.send(&output, &mut sink).unwrap();
    let operation = SessionInput::new(
        capability(CapabilityAction::Read, "matinee/status"),
        PayloadKind::Command,
        ObjectOwner::Owned(pair.owner),
        None,
    );
    let input = pair.daemon.receive(&frame, &operation, &mut sink).unwrap();
    assert_eq!(input.payload(), b"status");
    assert_eq!(input.granted().resource_scope(), "matinee/status");

    let projection = SessionProjection::new(
        ProjectionClass::Status,
        capability(CapabilityAction::Read, "matinee/status"),
        ObjectOwner::Owned(pair.owner),
        None,
        b"ready",
    );
    let response = pair.daemon.send_projection(&projection, &mut sink).unwrap();
    let filtered = pair
        .client
        .receive_filtered(&response, PayloadKind::Response, &mut sink)
        .unwrap();
    assert_eq!(filtered.payload(), b"ready");
    assert!(pair.client.is_open() && pair.daemon.is_open());
}

#[test]
fn an_external_consumer_cannot_reach_an_unauthorized_path_on_either_side() {
    let mut pair = establish();
    let mut sink = Sink::default();
    let operation = SessionInput::new(
        capability(CapabilityAction::Read, "matinee/status"),
        PayloadKind::Command,
        ObjectOwner::Owned(pair.owner),
        None,
    );
    let output = AuthorizedOutput::filtered(PayloadKind::Command, b"status".to_vec()).unwrap();
    let frame = pair.client.send(&output, &mut sink).unwrap();

    // The daemon holds the principal, so it cannot consume a frame without authorizing it.
    let failure = pair
        .daemon
        .receive_filtered(&frame, PayloadKind::Command, &mut sink)
        .expect_err("a daemon must authorize what it accepts");
    assert_eq!(failure.code(), FailureCode::AuthorizationDenied);
    assert!(!pair.daemon.is_open());

    // The client holds no principal, so it cannot authorize anything.
    let mut pair = establish();
    let failure = pair
        .client
        .receive(&frame, &operation, &mut sink)
        .expect_err("a client cannot authorize");
    assert_eq!(failure.code(), FailureCode::AuthorizationDenied);
    assert!(!pair.client.is_open());

    let mut pair = establish();
    let projection = SessionProjection::new(
        ProjectionClass::Event,
        capability(CapabilityAction::Read, "matinee/status"),
        ObjectOwner::Owned(pair.owner),
        None,
        b"event",
    );
    let failure = pair
        .client
        .send_projection(&projection, &mut sink)
        .expect_err("a client cannot disclose an authorized projection");
    assert_eq!(failure.code(), FailureCode::AuthorizationDenied);
    assert!(!pair.client.is_open());
}

#[test]
fn a_pending_or_revoked_principal_never_reaches_a_traffic_key() {
    let client_signer = Signer::generate();
    let daemon_signer = Signer::generate();
    let owner = id(2);
    let pending = Principal::new(
        id(1),
        PrincipalKind::McpClient,
        client_signer.public.clone(),
        Fingerprint::new("a".repeat(64)).unwrap(),
        owner,
        vec![capability(CapabilityAction::Read, "matinee")],
        CredentialReference::new("consumer-store", "principal-key", owner, id(9)).unwrap(),
    )
    .unwrap();
    let mut revoked = pending.clone();
    revoked.activate().unwrap();
    revoked.revoke();
    for principal in [pending, revoked] {
        let failure = ServerHandshakeConfig::new(
            ENDPOINT,
            principal,
            owner,
            daemon_signer.public.clone(),
            2,
            4,
            ConnectionId::new(Uuid::from_u128(3)),
        )
        .expect_err("only an active principal establishes a channel");
        assert_eq!(failure.code(), FailureCode::AuthenticationFailed);
    }
}
