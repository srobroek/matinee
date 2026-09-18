//! Authenticated P-256 handshake and private v1 framing state.

use core::fmt;

use ring::rand::SecureRandom;
use ring::signature;
use ring::{aead, agreement, digest, hkdf, rand};
use uuid::Uuid;

use crate::ChannelSession;
use crate::authorization::AuthorizationContext;
use crate::events::{
    self, EndpointClass, EventBoundary, EventOutcome, EventTime, SafeNextAction, SecurityCode,
    SecurityEvent, SecurityEventSink,
};
use crate::failures::{FailureCode, SecurityFailure};
use crate::identity::{ConnectionId, IdentityId, Principal, PrincipalLifecycle, PublicKey};

pub const SECURE_CHANNEL_CONTEXT: &str = "matinee.secure-channel.v1";
const CONTEXT: &[u8] = SECURE_CHANNEL_CONTEXT.as_bytes();
const FRAME_VERSION: u8 = 1;
const LENGTH_LEN: usize = 4;
const HEADER_LEN: usize = 25;
const TAG_LEN: usize = 16;
const MAX_FRAME: usize = 1_048_576;
const MAX_PLAINTEXT: usize = 1_048_535;
const MAX_HANDSHAKE: usize = 4_096;
const NONCE_LEN: usize = 32;
const PUBLIC_KEY_LEN: usize = 65;
const SIGNATURE_LEN: usize = 64;
const CLIENT_TO_DAEMON: &str = "client-to-daemon";
const DAEMON_TO_CLIENT: &str = "daemon-to-client";

/// A long-term identity signer. Implementations retain custody of the private key.
/// The channel verifies every returned signature against the configured bound public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelSigningError;

pub trait ChannelSigner {
    fn public_key(&self) -> &PublicKey;
    fn sign_p1363(&self, transcript: &[u8]) -> Result<[u8; SIGNATURE_LEN], ChannelSigningError>;
}

/// The client-side values bound into one handshake.
#[derive(Clone, Debug)]
pub struct ClientHandshakeConfig {
    endpoint: String,
    principal: IdentityId,
    principal_key: PublicKey,
    daemon: IdentityId,
    daemon_key: PublicKey,
    epoch: u64,
    contract_min: u16,
    contract_max: u16,
}

impl ClientHandshakeConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: impl Into<String>,
        principal: IdentityId,
        principal_key: PublicKey,
        daemon: IdentityId,
        daemon_key: PublicKey,
        epoch: u64,
        contract_min: u16,
        contract_max: u16,
    ) -> Result<Self, SecurityFailure> {
        let endpoint = endpoint.into();
        validate_config(&endpoint, contract_min, contract_max)?;
        Ok(Self {
            endpoint,
            principal,
            principal_key,
            daemon,
            daemon_key,
            epoch,
            contract_min,
            contract_max,
        })
    }
}

/// The daemon-side values bound into one handshake.
///
/// The daemon accepts the registered principal itself rather than a raw identity and public
/// key: the identity, the bound public key, the capability ceiling, the authentication
/// epoch, and the owning state directory are all read off that one snapshot. A caller
/// therefore cannot present a key, an epoch, or a state directory the registry does not hold
/// for that principal, and the session that results carries the snapshot for life.
#[derive(Clone, Debug)]
pub struct ServerHandshakeConfig {
    endpoint: String,
    principal: Principal,
    daemon: IdentityId,
    daemon_key: PublicKey,
    contract_min: u16,
    contract_max: u16,
    connection: ConnectionId,
}

impl ServerHandshakeConfig {
    pub fn new(
        endpoint: impl Into<String>,
        principal: Principal,
        daemon: IdentityId,
        daemon_key: PublicKey,
        contract_min: u16,
        contract_max: u16,
        connection: ConnectionId,
    ) -> Result<Self, SecurityFailure> {
        let endpoint = endpoint.into();
        validate_config(&endpoint, contract_min, contract_max)?;
        if principal.lifecycle() != PrincipalLifecycle::Active {
            // A pending, rotating, or revoked principal never reaches a traffic key.
            return Err(SecurityFailure::new(FailureCode::AuthenticationFailed));
        }
        Ok(Self {
            endpoint,
            principal,
            daemon,
            daemon_key,
            contract_min,
            contract_max,
            connection,
        })
    }

    /// The authentication epoch this handshake is bound to, as the principal carries it.
    fn epoch(&self) -> u64 {
        self.principal.epoch()
    }
}

fn validate_config(endpoint: &str, minimum: u16, maximum: u16) -> Result<(), SecurityFailure> {
    if endpoint.is_empty() || endpoint.len() > 256 {
        return Err(SecurityFailure::new(FailureCode::EndpointRejected));
    }
    if minimum == 0 || minimum > maximum {
        return Err(SecurityFailure::new(FailureCode::DowngradeRejected));
    }
    Ok(())
}

/// Client handshake state. Product payload APIs do not exist until `finish` succeeds.
pub struct ClientHandshake {
    config: ClientHandshakeConfig,
    hello: Vec<u8>,
    ephemeral: agreement::EphemeralPrivateKey,
}

impl fmt::Debug for ClientHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientHandshake(REDACTED)")
    }
}

impl ClientHandshake {
    pub fn start(config: ClientHandshakeConfig) -> Result<(Self, Vec<u8>), SecurityFailure> {
        let rng = rand::SystemRandom::new();
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill(&mut nonce)
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
        let ephemeral = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
        let public = ephemeral
            .compute_public_key()
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
        let hello = client_hello(&config, &nonce, public.as_ref());
        Ok((
            Self {
                config,
                hello: hello.clone(),
                ephemeral,
            },
            hello,
        ))
    }

    /// Verify the daemon proof before signing or deriving any traffic key.
    pub fn finish(
        self,
        server_proof: &[u8],
        signer: &dyn ChannelSigner,
        sink: &mut dyn SecurityEventSink,
    ) -> Result<(ChannelSession, [u8; SIGNATURE_LEN]), SecurityFailure> {
        let principal = self.config.principal;
        let epoch = self.config.epoch;
        match self.finish_inner(server_proof, signer) {
            Ok(value) => Ok(value),
            Err(failure) => Err(emit_handshake_failure(
                sink, failure, principal, None, epoch,
            )),
        }
    }

    fn finish_inner(
        self,
        server_proof: &[u8],
        signer: &dyn ChannelSigner,
    ) -> Result<(ChannelSession, [u8; SIGNATURE_LEN]), SecurityFailure> {
        if signer.public_key() != &self.config.principal_key {
            return Err(SecurityFailure::new(FailureCode::AuthenticationFailed));
        }
        let fields = parse_server_proof(server_proof, &self.hello)?;
        let expected_contract = negotiate(
            self.config.contract_min,
            self.config.contract_max,
            fields.server_min,
            fields.server_max,
        )?;
        if fields.selected != expected_contract
            || fields.daemon != self.config.daemon
            || fields.daemon_key != self.config.daemon_key
        {
            return Err(SecurityFailure::new(FailureCode::DowngradeRejected));
        }
        verify_signature(
            &self.config.daemon_key,
            fields.proof_input,
            &fields.server_signature,
        )?;
        let client_proof = client_proof_input(fields.proof_input, &fields.server_signature);
        let client_signature = signer
            .sign_p1363(&client_proof)
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
        verify_signature(&self.config.principal_key, &client_proof, &client_signature)?;
        let salt = traffic_salt(&client_proof, &client_signature);
        let keys = agree_and_derive(
            self.ephemeral,
            &fields.server_ephemeral,
            &salt,
            fields.selected,
        )?;
        let session = ChannelSession::client(
            fields.connection,
            self.config.principal,
            self.config.daemon,
            self.config.epoch,
            fields.selected,
            self.config.endpoint,
            keys,
        )?;
        Ok((session, client_signature))
    }
}

/// Pending daemon handshake state. It can establish a session only once.
pub struct ServerHandshake {
    config: ServerHandshakeConfig,
    selected: u16,
    client_ephemeral: [u8; PUBLIC_KEY_LEN],
    ephemeral: agreement::EphemeralPrivateKey,
    proof_input: Vec<u8>,
    server_signature: [u8; SIGNATURE_LEN],
}

impl fmt::Debug for ServerHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServerHandshake(REDACTED)")
    }
}

impl ServerHandshake {
    /// Parse and negotiate the client hello, then sign the complete server transcript.
    pub fn accept(
        config: ServerHandshakeConfig,
        client_hello_bytes: &[u8],
        signer: &dyn ChannelSigner,
        sink: &mut dyn SecurityEventSink,
    ) -> Result<(Self, Vec<u8>), SecurityFailure> {
        let principal = config.principal.id();
        let connection = config.connection;
        let epoch = config.epoch();
        match Self::accept_inner(config, client_hello_bytes, signer) {
            Ok(value) => Ok(value),
            Err(failure) => Err(emit_handshake_failure(
                sink,
                failure,
                principal,
                Some(connection),
                epoch,
            )),
        }
    }

    fn accept_inner(
        config: ServerHandshakeConfig,
        client_hello_bytes: &[u8],
        signer: &dyn ChannelSigner,
    ) -> Result<(Self, Vec<u8>), SecurityFailure> {
        if signer.public_key() != &config.daemon_key {
            return Err(SecurityFailure::new(FailureCode::AuthenticationFailed));
        }
        let hello = parse_client_hello(client_hello_bytes)?;
        let expected_selector = principal_selector(config.principal.id());
        if hello.endpoint != config.endpoint.as_bytes()
            || hello.principal_selector != expected_selector.as_bytes()
            || hello.principal_key != *config.principal.public_key()
        {
            return Err(SecurityFailure::new(FailureCode::AuthenticationFailed));
        }
        if hello.epoch != config.epoch() {
            // The client authenticated at an epoch the registry has already moved past.
            return Err(SecurityFailure::new(FailureCode::StaleEpoch));
        }
        let selected = negotiate(
            hello.contract_min,
            hello.contract_max,
            config.contract_min,
            config.contract_max,
        )?;
        let rng = rand::SystemRandom::new();
        let mut server_nonce = [0u8; NONCE_LEN];
        rng.fill(&mut server_nonce)
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
        let ephemeral = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
        let public = ephemeral
            .compute_public_key()
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
        let server_ephemeral: [u8; PUBLIC_KEY_LEN] = public
            .as_ref()
            .try_into()
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
        let proof_input = server_proof_input(
            client_hello_bytes,
            selected,
            config.contract_min,
            config.contract_max,
            config.daemon,
            &config.daemon_key,
            &server_nonce,
            &server_ephemeral,
            config.connection,
        );
        let server_signature = signer
            .sign_p1363(&proof_input)
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
        verify_signature(&config.daemon_key, &proof_input, &server_signature)?;
        let mut proof = Vec::with_capacity(proof_input.len() + LENGTH_LEN + SIGNATURE_LEN);
        proof.extend_from_slice(&proof_input);
        lp(&mut proof, &server_signature);
        Ok((
            Self {
                config,
                selected,
                client_ephemeral: hello.client_ephemeral,
                ephemeral,
                proof_input,
                server_signature,
            },
            proof,
        ))
    }

    /// Verify the registered principal proof before deriving traffic keys.
    pub fn finish(
        self,
        client_signature: &[u8],
        sink: &mut dyn SecurityEventSink,
    ) -> Result<ChannelSession, SecurityFailure> {
        let principal = self.config.principal.id();
        let connection = self.config.connection;
        let epoch = self.config.epoch();
        match self.finish_inner(client_signature) {
            Ok(session) => Ok(session),
            Err(failure) => Err(emit_handshake_failure(
                sink,
                failure,
                principal,
                Some(connection),
                epoch,
            )),
        }
    }

    fn finish_inner(self, client_signature: &[u8]) -> Result<ChannelSession, SecurityFailure> {
        if client_signature.len() != SIGNATURE_LEN {
            return Err(SecurityFailure::new(FailureCode::MalformedInput));
        }
        let client_proof = client_proof_input(&self.proof_input, &self.server_signature);
        verify_signature(
            self.config.principal.public_key(),
            &client_proof,
            client_signature,
        )?;
        let salt = traffic_salt(&client_proof, client_signature);
        let keys = agree_and_derive(self.ephemeral, &self.client_ephemeral, &salt, self.selected)?;
        // The session owns the principal snapshot from here: the ceiling, the epoch, and the
        // state directory every later decision reads are fixed at this point.
        let context = AuthorizationContext::new(
            self.config.principal,
            self.selected,
            self.config.contract_min,
            self.config.contract_max,
        );
        ChannelSession::daemon(self.config.connection, context, self.config.endpoint, keys)
    }
}

struct ParsedClientHello<'a> {
    endpoint: &'a [u8],
    principal_selector: &'a [u8],
    principal_key: PublicKey,
    epoch: u64,
    contract_min: u16,
    contract_max: u16,
    client_ephemeral: [u8; PUBLIC_KEY_LEN],
}

struct ParsedServerProof<'a> {
    selected: u16,
    server_min: u16,
    server_max: u16,
    daemon: IdentityId,
    daemon_key: PublicKey,
    server_ephemeral: [u8; PUBLIC_KEY_LEN],
    connection: ConnectionId,
    proof_input: &'a [u8],
    server_signature: [u8; SIGNATURE_LEN],
}

fn client_hello(
    config: &ClientHandshakeConfig,
    nonce: &[u8; NONCE_LEN],
    ephemeral: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    lp(&mut out, CONTEXT);
    lp(&mut out, b"client-hello");
    lp(&mut out, config.endpoint.as_bytes());
    lp(&mut out, principal_selector(config.principal).as_bytes());
    out.extend_from_slice(&config.epoch.to_be_bytes());
    lp_contract(&mut out, config.contract_min);
    lp_contract(&mut out, config.contract_max);
    lp(&mut out, nonce);
    lp(&mut out, ephemeral);
    lp(&mut out, config.principal_key.as_bytes());
    out
}

#[allow(clippy::too_many_arguments)]
fn server_proof_input(
    client_hello: &[u8],
    selected: u16,
    server_min: u16,
    server_max: u16,
    daemon: IdentityId,
    daemon_key: &PublicKey,
    server_nonce: &[u8; NONCE_LEN],
    server_ephemeral: &[u8; PUBLIC_KEY_LEN],
    connection: ConnectionId,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(client_hello.len() + 256);
    lp(&mut out, b"server-proof");
    out.extend_from_slice(client_hello);
    lp_contract(&mut out, selected);
    lp_contract(&mut out, server_min);
    lp_contract(&mut out, server_max);
    lp(&mut out, daemon.get().as_bytes());
    lp(&mut out, daemon_key.as_bytes());
    lp(&mut out, server_nonce);
    lp(&mut out, server_ephemeral);
    lp(&mut out, connection.get().as_bytes());
    out
}

fn client_proof_input(server_proof_input: &[u8], server_signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 12 + 32 + 4 + SIGNATURE_LEN);
    lp(&mut out, b"client-proof");
    out.extend_from_slice(digest::digest(&digest::SHA256, server_proof_input).as_ref());
    lp(&mut out, server_signature);
    out
}

fn parse_client_hello(input: &[u8]) -> Result<ParsedClientHello<'_>, SecurityFailure> {
    if input.len() > MAX_HANDSHAKE {
        return Err(SecurityFailure::new(FailureCode::ResourceLimit));
    }
    let mut reader = Reader::new(input);
    reader.expect_lp(CONTEXT, CONTEXT.len())?;
    reader.expect_lp(b"client-hello", 12)?;
    let endpoint = reader.lp(256)?;
    core::str::from_utf8(endpoint)
        .map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))?;
    let principal_selector = reader.lp(128)?;
    core::str::from_utf8(principal_selector)
        .map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))?;
    let epoch = reader.u64()?;
    let contract_min = parse_contract(reader.lp(5)?)?;
    let contract_max = parse_contract(reader.lp(5)?)?;
    reader.exact_lp::<NONCE_LEN>()?;
    let client_ephemeral = reader.valid_public_key()?;
    let principal_key = PublicKey::from_uncompressed(reader.valid_public_key()?)
        .map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))?;
    reader.finish()?;
    Ok(ParsedClientHello {
        endpoint,
        principal_selector,
        principal_key,
        epoch,
        contract_min,
        contract_max,
        client_ephemeral,
    })
}

fn parse_server_proof<'a>(
    input: &'a [u8],
    expected_hello: &[u8],
) -> Result<ParsedServerProof<'a>, SecurityFailure> {
    if input.len() > MAX_HANDSHAKE {
        return Err(SecurityFailure::new(FailureCode::ResourceLimit));
    }
    let mut reader = Reader::new(input);
    reader.expect_lp(b"server-proof", 12)?;
    reader.expect_raw(expected_hello)?;
    let selected = parse_contract(reader.lp(5)?)?;
    let server_min = parse_contract(reader.lp(5)?)?;
    let server_max = parse_contract(reader.lp(5)?)?;
    let daemon = IdentityId::new(Uuid::from_bytes(reader.exact_lp::<16>()?));
    let daemon_key = PublicKey::from_uncompressed(reader.valid_public_key()?)
        .map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))?;
    let _server_nonce = reader.exact_lp::<NONCE_LEN>()?;
    let server_ephemeral = reader.valid_public_key()?;
    let connection = ConnectionId::new(Uuid::from_bytes(reader.exact_lp::<16>()?));
    let proof_input_end = reader.position();
    let server_signature = reader.exact_lp::<SIGNATURE_LEN>()?;
    reader.finish()?;
    Ok(ParsedServerProof {
        selected,
        server_min,
        server_max,
        daemon,
        daemon_key,
        server_ephemeral,
        connection,
        proof_input: &input[..proof_input_end],
        server_signature,
    })
}

fn principal_selector(principal: IdentityId) -> String {
    format!("id:{}", principal.get())
}

fn negotiate(
    client_min: u16,
    client_max: u16,
    server_min: u16,
    server_max: u16,
) -> Result<u16, SecurityFailure> {
    if client_min == 0 || server_min == 0 || client_min > client_max || server_min > server_max {
        return Err(SecurityFailure::new(FailureCode::DowngradeRejected));
    }
    let minimum = client_min.max(server_min);
    let maximum = client_max.min(server_max);
    if minimum > maximum {
        return Err(SecurityFailure::new(FailureCode::CompatibilityUnsupported));
    }
    Ok(maximum)
}

fn verify_signature(
    key: &PublicKey,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), SecurityFailure> {
    if signature_bytes.len() != SIGNATURE_LEN {
        return Err(SecurityFailure::new(FailureCode::MalformedInput));
    }
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, key.as_bytes())
        .verify(message, signature_bytes)
        .map_err(|_| SecurityFailure::new(FailureCode::AuthenticationFailed))
}

fn traffic_salt(client_proof: &[u8], client_signature: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(client_proof.len() + client_signature.len());
    input.extend_from_slice(client_proof);
    input.extend_from_slice(client_signature);
    digest::digest(&digest::SHA256, &input)
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes")
}

pub(crate) struct TrafficKeys {
    client_to_daemon: [u8; 32],
    daemon_to_client: [u8; 32],
}

fn agree_and_derive(
    private: agreement::EphemeralPrivateKey,
    peer_public: &[u8; PUBLIC_KEY_LEN],
    salt: &[u8; 32],
    contract: u16,
) -> Result<TrafficKeys, SecurityFailure> {
    let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public);
    agreement::agree_ephemeral(private, &peer, |shared| {
        derive_traffic_keys(shared, salt, contract)
    })
    .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?
}

fn derive_traffic_keys(
    shared_secret: &[u8],
    salt: &[u8; 32],
    contract: u16,
) -> Result<TrafficKeys, SecurityFailure> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(shared_secret);
    Ok(TrafficKeys {
        client_to_daemon: derive_key(&prk, contract, CLIENT_TO_DAEMON)?,
        daemon_to_client: derive_key(&prk, contract, DAEMON_TO_CLIENT)?,
    })
}

fn derive_key(
    prk: &hkdf::Prk,
    contract: u16,
    direction: &str,
) -> Result<[u8; 32], SecurityFailure> {
    let mut info = Vec::with_capacity(64);
    lp(&mut info, CONTEXT);
    lp_contract(&mut info, contract);
    lp(&mut info, direction.as_bytes());
    let info_parts = [&info[..]];
    let okm = prk
        .expand(&info_parts, AesKey)
        .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
    let mut key = [0u8; 32];
    okm.fill(&mut key)
        .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
    Ok(key)
}

struct AesKey;
impl hkdf::KeyType for AesKey {
    fn len(&self) -> usize {
        32
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Role {
    Client,
    Daemon,
}

impl Role {
    fn send_direction(self) -> Direction {
        match self {
            Self::Client => Direction::ClientToDaemon,
            Self::Daemon => Direction::DaemonToClient,
        }
    }

    fn receive_direction(self) -> Direction {
        match self {
            Self::Client => Direction::DaemonToClient,
            Self::Daemon => Direction::ClientToDaemon,
        }
    }
}

#[derive(Clone, Copy)]
enum Direction {
    ClientToDaemon,
    DaemonToClient,
}

impl Direction {
    fn number(self) -> u32 {
        match self {
            Self::ClientToDaemon => 0,
            Self::DaemonToClient => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ClientToDaemon => CLIENT_TO_DAEMON,
            Self::DaemonToClient => DAEMON_TO_CLIENT,
        }
    }
}

pub(crate) struct ChannelState {
    send: aead::LessSafeKey,
    receive: aead::LessSafeKey,
    send_direction: Direction,
    receive_direction: Direction,
    send_counter: u64,
    receive_counter: u64,
    send_exhausted: bool,
    receive_exhausted: bool,
}

impl fmt::Debug for ChannelState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChannelState")
            .field("send_counter", &self.send_counter)
            .field("receive_counter", &self.receive_counter)
            .field("send_exhausted", &self.send_exhausted)
            .field("receive_exhausted", &self.receive_exhausted)
            .finish()
    }
}

impl ChannelState {
    pub(crate) fn new(role: Role, keys: TrafficKeys) -> Result<Self, SecurityFailure> {
        let (send_bytes, receive_bytes) = match role {
            Role::Client => (keys.client_to_daemon, keys.daemon_to_client),
            Role::Daemon => (keys.daemon_to_client, keys.client_to_daemon),
        };
        Ok(Self {
            send: aead_key(&send_bytes)?,
            receive: aead_key(&receive_bytes)?,
            send_direction: role.send_direction(),
            receive_direction: role.receive_direction(),
            send_counter: 0,
            receive_counter: 0,
            send_exhausted: false,
            receive_exhausted: false,
        })
    }

    pub(crate) fn seal(
        &mut self,
        id: ConnectionId,
        epoch: u64,
        contract: u16,
        kind: crate::PayloadKind,
        payload: &[u8],
    ) -> Result<Vec<u8>, SecurityFailure> {
        if payload.len() >= MAX_PLAINTEXT {
            return Err(SecurityFailure::new(FailureCode::ResourceLimit));
        }
        if self.send_exhausted {
            return Err(SecurityFailure::new(FailureCode::CounterMismatch));
        }
        let counter = self.send_counter;
        let header = header(id, counter);
        let aad = aad(&header, contract, epoch, self.send_direction);
        let nonce = nonce(self.send_direction, counter);
        let frame_len = HEADER_LEN + 1 + payload.len() + TAG_LEN;
        let mut body = Vec::with_capacity(1 + payload.len() + TAG_LEN);
        body.push(kind.wire_code());
        body.extend_from_slice(payload);
        self.send
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad.as_slice()),
                &mut body,
            )
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
        let mut framed = Vec::with_capacity(LENGTH_LEN + frame_len);
        framed.extend_from_slice(&(frame_len as u32).to_be_bytes());
        framed.extend_from_slice(&header);
        framed.extend_from_slice(&body);
        advance(&mut self.send_counter, &mut self.send_exhausted);
        Ok(framed)
    }

    pub(crate) fn open(
        &mut self,
        framed: &[u8],
        id: ConnectionId,
        epoch: u64,
        contract: u16,
    ) -> Result<(Vec<u8>, u64), SecurityFailure> {
        if framed.len() < LENGTH_LEN {
            return Err(SecurityFailure::new(FailureCode::MalformedInput));
        }
        let declared = u32::from_be_bytes(
            framed[..LENGTH_LEN]
                .try_into()
                .map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))?,
        ) as usize;
        if declared > MAX_FRAME {
            return Err(SecurityFailure::new(FailureCode::ResourceLimit));
        }
        if declared < HEADER_LEN + TAG_LEN || framed.len() != LENGTH_LEN + declared {
            return Err(SecurityFailure::new(FailureCode::MalformedInput));
        }
        let frame = &framed[LENGTH_LEN..];
        let header = &frame[..HEADER_LEN];
        if header[0] != FRAME_VERSION || header[1..17] != *id.get().as_bytes() {
            return Err(SecurityFailure::new(FailureCode::MalformedInput));
        }
        let counter = u64::from_be_bytes(
            header[17..25]
                .try_into()
                .map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))?,
        );
        if self.receive_exhausted || counter != self.receive_counter {
            let code = if counter < self.receive_counter {
                FailureCode::ReplayDetected
            } else {
                FailureCode::CounterMismatch
            };
            return Err(SecurityFailure::new(code));
        }
        let mut body = frame[HEADER_LEN..].to_vec();
        let aad = aad(header, contract, epoch, self.receive_direction);
        let plaintext_len = self
            .receive
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce(self.receive_direction, counter)),
                aead::Aad::from(aad.as_slice()),
                &mut body,
            )
            .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?
            .len();
        if plaintext_len > MAX_PLAINTEXT {
            return Err(SecurityFailure::new(FailureCode::ResourceLimit));
        }
        body.truncate(plaintext_len);
        Ok((body, counter))
    }

    pub(crate) fn commit_receive(&mut self, counter: u64) {
        debug_assert_eq!(self.receive_counter, counter);
        debug_assert!(!self.receive_exhausted);
        advance(&mut self.receive_counter, &mut self.receive_exhausted);
    }

    #[cfg(test)]
    pub(crate) fn set_counters(&mut self, send: u64, receive: u64) {
        self.send_counter = send;
        self.receive_counter = receive;
        self.send_exhausted = false;
        self.receive_exhausted = false;
    }

    #[cfg(test)]
    pub(crate) fn receive_counter(&self) -> u64 {
        self.receive_counter
    }

    #[cfg(test)]
    pub(crate) fn send_counter(&self) -> u64 {
        self.send_counter
    }
}

fn aead_key(bytes: &[u8; 32]) -> Result<aead::LessSafeKey, SecurityFailure> {
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, bytes)
        .map_err(|_| SecurityFailure::new(FailureCode::CryptographicFailure))?;
    Ok(aead::LessSafeKey::new(unbound))
}

fn advance(counter: &mut u64, exhausted: &mut bool) {
    if *counter == u64::MAX {
        *exhausted = true;
    } else {
        *counter += 1;
    }
}

fn header(id: ConnectionId, counter: u64) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0] = FRAME_VERSION;
    out[1..17].copy_from_slice(id.get().as_bytes());
    out[17..].copy_from_slice(&counter.to_be_bytes());
    out
}

fn nonce(direction: Direction, counter: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..4].copy_from_slice(&direction.number().to_be_bytes());
    out[4..].copy_from_slice(&counter.to_be_bytes());
    out
}

fn aad(header: &[u8], contract: u16, epoch: u64, direction: Direction) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(header);
    lp(&mut out, CONTEXT);
    lp_contract(&mut out, contract);
    out.extend_from_slice(&epoch.to_be_bytes());
    lp(&mut out, direction.label().as_bytes());
    out
}

fn lp_contract(out: &mut Vec<u8>, contract: u16) {
    lp(out, contract.to_string().as_bytes());
}

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn parse_contract(input: &[u8]) -> Result<u16, SecurityFailure> {
    let text = core::str::from_utf8(input)
        .map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))?;
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(SecurityFailure::new(FailureCode::MalformedInput));
    }
    text.parse()
        .map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn raw(&mut self, length: usize) -> Result<&'a [u8], SecurityFailure> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SecurityFailure::new(FailureCode::MalformedInput))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(SecurityFailure::new(FailureCode::MalformedInput))?;
        self.offset = end;
        Ok(value)
    }

    fn u64(&mut self) -> Result<u64, SecurityFailure> {
        Ok(u64::from_be_bytes(self.raw(8)?.try_into().map_err(
            |_| SecurityFailure::new(FailureCode::MalformedInput),
        )?))
    }

    fn lp(&mut self, maximum: usize) -> Result<&'a [u8], SecurityFailure> {
        let declared = u32::from_be_bytes(
            self.raw(LENGTH_LEN)?
                .try_into()
                .map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))?,
        ) as usize;
        if declared > maximum {
            return Err(SecurityFailure::new(FailureCode::ResourceLimit));
        }
        self.raw(declared)
    }

    fn exact_lp<const N: usize>(&mut self) -> Result<[u8; N], SecurityFailure> {
        self.lp(N)?
            .try_into()
            .map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))
    }

    fn valid_public_key(&mut self) -> Result<[u8; PUBLIC_KEY_LEN], SecurityFailure> {
        let key = self.exact_lp::<PUBLIC_KEY_LEN>()?;
        PublicKey::from_uncompressed(key)
            .map_err(|_| SecurityFailure::new(FailureCode::MalformedInput))?;
        Ok(key)
    }

    fn expect_lp(&mut self, expected: &[u8], maximum: usize) -> Result<(), SecurityFailure> {
        if self.lp(maximum)? != expected {
            return Err(SecurityFailure::new(FailureCode::AuthenticationFailed));
        }
        Ok(())
    }

    fn expect_raw(&mut self, expected: &[u8]) -> Result<(), SecurityFailure> {
        if self.raw(expected.len())? != expected {
            return Err(SecurityFailure::new(FailureCode::AuthenticationFailed));
        }
        Ok(())
    }

    fn finish(self) -> Result<(), SecurityFailure> {
        if self.offset != self.input.len() {
            return Err(SecurityFailure::new(FailureCode::MalformedInput));
        }
        Ok(())
    }
}

fn emit_handshake_failure(
    sink: &mut dyn SecurityEventSink,
    failure: SecurityFailure,
    principal: IdentityId,
    connection: Option<ConnectionId>,
    epoch: u64,
) -> SecurityFailure {
    let code = event_code(failure.code());
    let event = SecurityEvent::new(
        Uuid::now_v7(),
        EventBoundary::Channel,
        code,
        EventOutcome::Rejected,
        SafeNextAction::FailClosed,
        Some(principal.get()),
        connection.map(ConnectionId::get),
        EndpointClass::Loopback,
        EventTime(epoch),
        Uuid::nil(),
        vec![],
    );
    match event.and_then(|event| {
        events::emit_required(Some(sink), event).map_err(|_| events::EventBuildError::EventTooLarge)
    }) {
        Ok(_) => failure,
        Err(_) => SecurityFailure::new(FailureCode::EventSinkUnavailable),
    }
}

pub(crate) fn emit_session_failure(
    sink: &mut dyn SecurityEventSink,
    failure: SecurityFailure,
    principal: IdentityId,
    connection: ConnectionId,
    epoch: u64,
) -> SecurityFailure {
    emit_handshake_failure(sink, failure, principal, Some(connection), epoch)
}

fn event_code(code: FailureCode) -> SecurityCode {
    match code {
        FailureCode::ReplayDetected => SecurityCode::ReplayDetected,
        FailureCode::CounterMismatch => SecurityCode::CounterRejected,
        FailureCode::DowngradeRejected | FailureCode::CompatibilityUnsupported => {
            SecurityCode::Downgrade
        }
        FailureCode::MalformedInput => SecurityCode::MalformedInput,
        FailureCode::ResourceLimit => SecurityCode::ResourceLimit,
        FailureCode::CryptographicFailure => SecurityCode::CryptographicFailure,
        _ => SecurityCode::AuthenticationFailed,
    }
}

#[cfg(test)]
pub(crate) fn vector_material(
    shared_secret: &[u8],
    salt: &[u8; 32],
    contract: u16,
) -> Result<([u8; 32], [u8; 32]), SecurityFailure> {
    let keys = derive_traffic_keys(shared_secret, salt, contract)?;
    Ok((keys.client_to_daemon, keys.daemon_to_client))
}

#[cfg(test)]
pub(crate) struct VectorTranscriptInput<'a> {
    pub(crate) client_hello: &'a [u8],
    pub(crate) selected: u16,
    pub(crate) server_min: u16,
    pub(crate) server_max: u16,
    pub(crate) daemon: IdentityId,
    pub(crate) daemon_key: &'a PublicKey,
    pub(crate) server_nonce: &'a [u8; NONCE_LEN],
    pub(crate) server_ephemeral: &'a [u8; PUBLIC_KEY_LEN],
    pub(crate) connection: ConnectionId,
    pub(crate) server_signature: &'a [u8; SIGNATURE_LEN],
    pub(crate) client_signature: &'a [u8; SIGNATURE_LEN],
}

#[cfg(test)]
pub(crate) fn vector_transcripts(input: VectorTranscriptInput<'_>) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let server = server_proof_input(
        input.client_hello,
        input.selected,
        input.server_min,
        input.server_max,
        input.daemon,
        input.daemon_key,
        input.server_nonce,
        input.server_ephemeral,
        input.connection,
    );
    let client = client_proof_input(&server, input.server_signature);
    let salt = traffic_salt(&client, input.client_signature);
    (server, client, salt)
}

#[cfg(test)]
pub(crate) fn vector_verify_signature(
    key: &PublicKey,
    transcript: &[u8],
    signature: &[u8],
) -> Result<(), SecurityFailure> {
    verify_signature(key, transcript, signature)
}

/// A daemon session assembled straight from vector traffic keys, so a fixed vector can be
/// replayed through the same public receive path a handshake would have produced.
#[cfg(test)]
pub(crate) fn vector_daemon_session(
    connection: ConnectionId,
    principal: Principal,
    contract: u16,
    client_to_daemon: [u8; 32],
    daemon_to_client: [u8; 32],
) -> Result<ChannelSession, SecurityFailure> {
    ChannelSession::daemon(
        connection,
        AuthorizationContext::new(principal, contract, contract, contract),
        "127.0.0.1:7777".to_owned(),
        TrafficKeys {
            client_to_daemon,
            daemon_to_client,
        },
    )
}
