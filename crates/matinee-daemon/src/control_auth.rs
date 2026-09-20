//! MVP control-channel identity bootstrap and credential handoff.
//!
//! The daemon owns the private key material for its signing identity and publishes
//! only the two local-principal credential records needed by its native clients.
//! The secure-channel handshake remains the authority: this module only constructs
//! the registered snapshots and signers used by that handshake.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use matinee_security::{
    Capability, CapabilityAction, ChannelSigner, ChannelSigningError, ConnectionId,
    CredentialReference, Fingerprint, IdentityId, Principal, PrincipalKind, PublicKey,
    SECURE_CHANNEL_CONTEXT, SecurityEventSink, SecurityEventSinkResult, ServerHandshake,
    ServerHandshakeConfig,
};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::registry::{PairingRecord, PrincipalRecord, Registry};

pub const CONTROL_CONTRACT_MIN: u16 = 1;
pub const CONTROL_CONTRACT_MAX: u16 = 1;
pub const CREDENTIAL_FILE_NAME: &str = "daemon.control.credentials.json";
const MAX_HANDSHAKE: usize = 4_096;

/// A signing key retained by one process. Its PKCS#8 bytes are included only in
/// the local handoff file and never in a registry record.
pub struct RingSigner {
    key: EcdsaKeyPair,
    public: PublicKey,
    pkcs8: Vec<u8>,
}

impl RingSigner {
    fn generate() -> io::Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "control key generation failed"))?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    pub fn from_pkcs8(bytes: &[u8]) -> io::Result<Self> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, bytes, &rng).map_err(
            |_| io::Error::new(io::ErrorKind::InvalidData, "control credential is invalid"),
        )?;
        let public_bytes: [u8; 65] =
            key.public_key().as_ref().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "control key is not P-256")
            })?;
        let public = PublicKey::from_uncompressed(public_bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "control public key is invalid")
        })?;
        Ok(Self {
            key,
            public,
            pkcs8: bytes.to_vec(),
        })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
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

/// The local credentials a client can use to authenticate on the control channel.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialMaterial {
    pub identity_id: IdentityId,
    pub epoch: u64,
    pub public_key: PublicKey,
    pub private_key_pkcs8: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Handoff {
    version: u8,
    context: String,
    daemon_identity_id: IdentityId,
    daemon_public_key: PublicKey,
    mcp: CredentialMaterial,
    native: CredentialMaterial,
}

/// The registered control principals and daemon signing identity for one run.
pub struct ControlAuth {
    pub daemon_identity: IdentityId,
    pub daemon_public_key: PublicKey,
    pub daemon_signer: RingSigner,
    pub native: Principal,
    pub mcp: Principal,
    native_signer: RingSigner,
    mcp_signer: RingSigner,
    handoff_path: PathBuf,
    pub extension_public_key: Option<Vec<u8>>,
}

impl ControlAuth {
    /// Generates process-local identities and publishes the local credential handoff.
    pub fn create(
        endpoint: &str,
        state_dir: &Path,
        extension_public_key: Option<Vec<u8>>,
    ) -> io::Result<Self> {
        let daemon_identity = IdentityId::new(Uuid::now_v7());
        let state_identity = IdentityId::new(Uuid::now_v7());
        let daemon_signer = RingSigner::generate()?;
        let daemon_public_key = daemon_signer.public_key().clone();
        let native_signer = RingSigner::generate()?;
        let mcp_signer = RingSigner::generate()?;
        let native_id = IdentityId::new(Uuid::now_v7());
        let mcp_id = IdentityId::new(Uuid::now_v7());
        let native = make_principal(
            native_id,
            PrincipalKind::NativeAdmin,
            &native_signer,
            daemon_identity,
            state_identity,
            "native-admin",
            Principal::native_admin_ceiling(),
        )?;
        let mcp = make_principal(
            mcp_id,
            PrincipalKind::McpClient,
            &mcp_signer,
            daemon_identity,
            state_identity,
            "mcp-client",
            vec![Capability::new(CapabilityAction::Read, "matinee").map_err(invalid_data)?],
        )?;
        let handoff_path = state_dir.join(CREDENTIAL_FILE_NAME);
        let auth = Self {
            daemon_identity,
            daemon_public_key,
            daemon_signer,
            native,
            mcp,
            native_signer,
            mcp_signer,
            handoff_path,
            extension_public_key,
        };
        auth.write_handoff(endpoint)?;
        Ok(auth)
    }

    /// Inserts the two MVP principals and the development pairing into the process registry.
    pub fn register(&self, registry: &Registry) -> io::Result<()> {
        for (principal, kind, locator) in [
            (&self.native, "native_admin", "native-admin"),
            (&self.mcp, "mcp_client", "mcp-client"),
        ] {
            registry
                .insert_principal(PrincipalRecord {
                    identity_id: principal.id().get(),
                    kind: kind.to_owned(),
                    credential_reference: locator.to_owned(),
                    epoch: i64::try_from(principal.epoch()).map_err(invalid_data)?,
                    status: "active".to_owned(),
                    created_at: now_ms(),
                })
                .map_err(|error| invalid_data(error.detail()))?;
        }
        if let Some(key) = &self.extension_public_key {
            let extension_identity_id = Uuid::now_v7();
            let fingerprint = hex_digest(key);
            registry
                .insert_pairing(PairingRecord {
                    pairing_id: Uuid::now_v7(),
                    extension_identity_id,
                    origin: crate::server::EXTENSION_ORIGIN.to_owned(),
                    public_key: key.clone(),
                    fingerprint,
                    development_allowance: true,
                    status: "active".to_owned(),
                    created_at: now_ms(),
                    rotated_at: None,
                })
                .map_err(|error| invalid_data(error.detail()))?;
        }
        Ok(())
    }

    pub fn handoff_path(&self) -> &Path {
        &self.handoff_path
    }

    pub fn remove_handoff(&self) -> io::Result<()> {
        match fs::remove_file(&self.handoff_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Returns the daemon signer and the registered principal snapshot for a hello.
    /// The security crate then verifies the full transcript, epoch and signature.
    pub fn accept(
        &self,
        endpoint: &str,
        hello: &[u8],
        connection: ConnectionId,
        registry: &Registry,
    ) -> Result<(ServerHandshake, Vec<u8>, IdentityId), ControlAuthError> {
        let principal_id = hello_principal_id(hello).ok_or(ControlAuthError::Denied)?;
        let record = registry
            .principal(principal_id.get())
            .map_err(|_| ControlAuthError::Denied)?
            .ok_or(ControlAuthError::Denied)?;
        let principal = if principal_id == self.native.id() {
            &self.native
        } else if principal_id == self.mcp.id() {
            &self.mcp
        } else {
            return Err(ControlAuthError::Denied);
        };
        if record.status != "active"
            || record.epoch
                != i64::try_from(principal.epoch()).map_err(|_| ControlAuthError::Denied)?
        {
            return Err(ControlAuthError::Denied);
        }
        let config = ServerHandshakeConfig::new(
            endpoint,
            principal.clone(),
            self.daemon_identity,
            self.daemon_public_key.clone(),
            CONTROL_CONTRACT_MIN,
            CONTROL_CONTRACT_MAX,
            connection,
        )
        .map_err(|_| ControlAuthError::Denied)?;
        let mut sink = NullSink;
        let (pending, proof) =
            ServerHandshake::accept(config, hello, &self.daemon_signer, &mut sink)
                .map_err(|_| ControlAuthError::Denied)?;
        Ok((pending, proof, principal_id))
    }

    pub fn client_material(
        path: &Path,
        native: bool,
    ) -> io::Result<(
        IdentityId,
        u64,
        PublicKey,
        PublicKey,
        IdentityId,
        RingSigner,
    )> {
        let handoff: Handoff = serde_json::from_slice(&fs::read(path)?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if handoff.version != 1 || handoff.context != SECURE_CHANNEL_CONTEXT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported control credential",
            ));
        }
        let material = if native { handoff.native } else { handoff.mcp };
        let signer = RingSigner::from_pkcs8(&material.private_key_pkcs8)?;
        if signer.public_key() != &material.public_key {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "control credential key mismatch",
            ));
        }
        Ok((
            material.identity_id,
            material.epoch,
            material.public_key,
            handoff.daemon_public_key,
            handoff.daemon_identity_id,
            signer,
        ))
    }

    fn write_handoff(&self, _endpoint: &str) -> io::Result<()> {
        let handoff = Handoff {
            version: 1,
            context: SECURE_CHANNEL_CONTEXT.to_owned(),
            daemon_identity_id: self.daemon_identity,
            daemon_public_key: self.daemon_public_key.clone(),
            mcp: material(&self.mcp, &self.mcp_signer),
            native: material(&self.native, &self.native_signer),
        };
        let mut path = self.handoff_path.clone();
        path.set_extension(format!("json.{}.tmp", Uuid::now_v7()));
        let encoded = serde_json::to_vec(&handoff)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        #[cfg(unix)]
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&path)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        fs::rename(path, &self.handoff_path)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlAuthError {
    Denied,
}

impl std::fmt::Display for ControlAuthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("authorization.denied")
    }
}

impl std::error::Error for ControlAuthError {}

fn make_principal(
    id: IdentityId,
    kind: PrincipalKind,
    signer: &RingSigner,
    daemon: IdentityId,
    state: IdentityId,
    locator: &str,
    ceiling: Vec<Capability>,
) -> io::Result<Principal> {
    let reference = CredentialReference::new("state-directory", locator, daemon, state)
        .map_err(invalid_data)?;
    let mut principal = Principal::new(
        id,
        kind,
        signer.public_key().clone(),
        Fingerprint::from_public_key(signer.public_key()),
        daemon,
        ceiling,
        reference,
    )
    .map_err(invalid_data)?;
    principal.activate().map_err(invalid_data)?;
    Ok(principal)
}

fn material(principal: &Principal, signer: &RingSigner) -> CredentialMaterial {
    CredentialMaterial {
        identity_id: principal.id(),
        epoch: principal.epoch(),
        public_key: signer.public_key().clone(),
        private_key_pkcs8: signer.pkcs8().to_vec(),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digest = digest::digest(&digest::SHA256, bytes);
    let mut encoded = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        encoded.push(DIGITS[usize::from(byte >> 4)] as char);
        encoded.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn hello_principal_id(hello: &[u8]) -> Option<IdentityId> {
    let mut reader = Reader {
        bytes: hello,
        offset: 0,
    };
    reader.lp()?;
    if reader.lp()? != b"client-hello" {
        return None;
    }
    reader.lp()?;
    let selector = reader.lp()?;
    let selector = std::str::from_utf8(selector).ok()?.strip_prefix("id:")?;
    Some(IdentityId::new(Uuid::parse_str(selector).ok()?))
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn lp(&mut self) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(4)?;
        let len = u32::from_be_bytes(self.bytes.get(self.offset..end)?.try_into().ok()?) as usize;
        self.offset = end;
        let end = self.offset.checked_add(len)?;
        let value = self.bytes.get(self.offset..end)?;
        self.offset = end;
        (self.offset <= MAX_HANDSHAKE).then_some(value)
    }
}

struct NullSink;
impl SecurityEventSink for NullSink {
    fn emit(&mut self, _event: matinee_security::SecurityEvent) -> SecurityEventSinkResult {
        SecurityEventSinkResult::Accepted
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
