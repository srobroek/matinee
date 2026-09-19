use std::borrow::Borrow;
use std::path::Path;
use std::sync::OnceLock;

pub(crate) mod config;
pub(crate) mod enrollment;
pub(crate) mod environment;
pub(crate) mod error;
pub(crate) mod platform;

pub(crate) mod path_identity;
pub use enrollment::{
    ChromeReconnectOutcome, ConnectionId, DevelopmentIdentityAllowance, EnrollmentBinding,
    EnrollmentConsumeError, EnrollmentCreateError, EnrollmentCreation, EnrollmentCustodyError,
    EnrollmentExpiry, EnrollmentFailure, EnrollmentHost, EnrollmentProof, ExpiryResult,
    Fingerprint, IdentityId, PairedPrincipal, PairingCompletion, PairingSession, PairingTicket,
    PublicKey, SealedOneTimeKey, TransitionId, UNCOMPRESSED_KEY_BYTES, enrollment_host,
};
pub use environment::{ConfigurationSource, EnvironmentInput, EnvironmentResult, Provenance};
pub use error::{ConfigurationFailure, ConfigurationFailureCode};

#[cfg(test)]
extern crate self as matinee_runtime;

#[cfg(all(test, feature = "test-support"))]
#[path = "enrollment_boundary_tests.rs"]
mod enrollment_boundary_tests;
#[cfg(all(test, feature = "test-support"))]
#[path = "enrollment_host_budget_tests.rs"]
mod enrollment_host_budget_tests;

static PRODUCTION_REGISTRY: OnceLock<config::DescriptorRegistry> = OnceLock::new();

fn production_registry() -> &'static config::DescriptorRegistry {
    PRODUCTION_REGISTRY.get_or_init(config::DescriptorRegistry::production)
}

/// The complete immutable result of one successful environment resolution.
///
/// The internal resolver owns all validation and classification. This wrapper
/// keeps its crate-private carriers behind a stable public projection.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedEnvironment {
    resolved: environment::ResolvedEnvironment<'static>,
    lock_identity: LockIdentity,
}

/// The exact lock identity for a resolved state root.
///
/// This wraps the complete internal identity without hashing, truncating, or
/// converting it to a lossy string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockIdentity(environment::LockIdentity);

/// One winning setting from a resolved environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSetting {
    key: String,
    value: String,
    source: ConfigurationSource,
    provenance: Provenance,
}

impl ResolvedSetting {
    fn from_internal(setting: &config::ResolvedSetting<'_>) -> Self {
        Self {
            key: setting.key().to_owned(),
            value: setting
                .value()
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| setting.value().to_string()),
            source: setting.source(),
            provenance: setting.provenance().clone(),
        }
    }

    /// Returns the accepted key name.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Returns the winning normalized value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Returns the source that supplied the winning value.
    pub fn source(&self) -> ConfigurationSource {
        self.source
    }

    /// Returns the redaction-safe successful provenance projection.
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }
}

impl ResolvedEnvironment {
    /// Returns the selected project root.
    pub fn project_root(&self) -> &Path {
        self.resolved.project_root()
    }

    /// Returns the user configuration path only when that file was loaded.
    pub fn user_config(&self) -> Option<&Path> {
        self.resolved.user_config()
    }

    /// Returns the project configuration path only when that file was loaded.
    pub fn project_config(&self) -> Option<&Path> {
        self.resolved.project_config()
    }

    /// Returns the resolved configuration-file directory path.
    pub fn config(&self) -> &Path {
        self.resolved.paths().config()
    }

    /// Returns the effective resolved state path.
    pub fn state(&self) -> &Path {
        self.resolved.paths().state()
    }

    /// Returns the resolved runtime path.
    pub fn runtime(&self) -> &Path {
        self.resolved.paths().runtime()
    }

    /// Returns the resolved cache path.
    pub fn cache(&self) -> &Path {
        self.resolved.paths().cache()
    }

    /// Returns the resolved log path.
    pub fn log(&self) -> &Path {
        self.resolved.paths().logs()
    }

    /// Returns a winning setting by its accepted key name.
    pub fn get(&self, key: &str) -> Option<ResolvedSetting> {
        self.resolved
            .configuration()
            .get(key)
            .map(ResolvedSetting::from_internal)
    }

    /// Iterates over the complete set of winning settings.
    pub fn settings(&self) -> impl Iterator<Item = ResolvedSetting> + '_ {
        self.resolved
            .configuration()
            .settings()
            .map(ResolvedSetting::from_internal)
    }

    /// Returns the exact identity used for state locking.
    pub fn lock_identity(&self) -> &LockIdentity {
        &self.lock_identity
    }
}

/// Resolve one environment through the host platform and production registry.
///
/// Resolution is all-or-failure: the internal resolver assembles the complete
/// product only after every observation, validation, and merge succeeds.
pub fn resolve_environment(
    input: impl Borrow<EnvironmentInput>,
) -> EnvironmentResult<ResolvedEnvironment> {
    let platform = platform::HostPlatform::new()?;
    let resolved = environment::resolve_environment(&platform, input, production_registry())?;
    let lock_identity = LockIdentity(resolved.lock_identity().clone());
    Ok(ResolvedEnvironment {
        resolved,
        lock_identity,
    })
}

#[cfg(test)]
fn resolve_with_platform<P: platform::Platform>(
    platform: &P,
    input: impl Borrow<EnvironmentInput>,
) -> EnvironmentResult<ResolvedEnvironment> {
    let resolved = environment::resolve_environment(platform, input, production_registry())?;
    let lock_identity = LockIdentity(resolved.lock_identity().clone());
    Ok(ResolvedEnvironment {
        resolved,
        lock_identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        FileIdentity, FileSnapshot, FixturePlatform, Platform, PlatformKind, native_fixture_kind,
        native_fixture_path,
    };
    use std::path::PathBuf;

    fn fixture_platform() -> FixturePlatform {
        let kind = native_fixture_kind();
        let fixture = FixturePlatform::new(kind);
        let bases = fixture.base_directories().expect("fixture bases");
        let state_anchor = match kind {
            PlatformKind::Linux => bases.state.expect("Linux fixture state base"),
            PlatformKind::Windows => bases.data,
            PlatformKind::MacOs => unreachable!("native fixture kind excludes macOS"),
        };
        let project = native_fixture_path(["project"]);
        let root = FileIdentity::full(1, 10);
        fixture
            .with_snapshot(project.clone(), FileSnapshot::directory(root, Some(1)))
            .with_followed_file_identity(project.clone(), root)
            .with_snapshot(
                state_anchor,
                FileSnapshot::directory(FileIdentity::full(1, 11), Some(1)),
            )
            .with_anchored_missing(project)
    }

    #[test]
    fn success_exposes_complete_environment_and_effective_state() {
        let platform = fixture_platform();
        let expected_paths = platform.matinee_paths().expect("fixture paths");
        let project = native_fixture_path(["project"]);
        let custom_state = project.join("custom-state");
        let environment = resolve_with_platform(
            &platform,
            EnvironmentInput::new(project.clone()).with_state_dir(custom_state.clone()),
        )
        .expect("fixture environment resolves");

        assert_eq!(environment.project_root(), project.as_path());
        assert!(environment.user_config().is_none());
        assert!(environment.project_config().is_none());
        assert_eq!(environment.config(), expected_paths.config());
        assert_eq!(environment.state(), custom_state.as_path());
        assert_eq!(environment.runtime(), expected_paths.runtime());
        assert_eq!(environment.cache(), expected_paths.cache());
        assert_eq!(environment.log(), expected_paths.logs());

        let setting = environment
            .get("state_dir")
            .expect("state_dir setting is present");
        assert_eq!(setting.key(), "state_dir");
        assert_eq!(
            setting.value(),
            custom_state.to_str().expect("fixture state is UTF-8")
        );
        assert_eq!(setting.source(), ConfigurationSource::CommandLine);
        assert_eq!(
            setting.provenance().source(),
            ConfigurationSource::CommandLine
        );
        assert_eq!(setting.provenance().key(), Some("state_dir"));
        assert!(
            !format!("{:?}", environment.lock_identity()).contains(
                native_fixture_path(std::iter::empty::<&str>())
                    .to_str()
                    .expect("fixture root is UTF-8")
            )
        );
    }

    #[test]
    fn configuration_paths_report_only_files_that_were_loaded() {
        let project = native_fixture_path(["project"]);
        let project_config = project.join("matinee.toml");
        let home = FixturePlatform::new(native_fixture_kind())
            .base_directories()
            .expect("fixture bases")
            .home;
        let explicit_path = home.join("explicit.toml");
        let with_project = fixture_platform().with_anchored_file(
            project.clone(),
            FileIdentity::full(1, 20),
            b"",
            Some(2),
        );
        let environment =
            resolve_with_platform(&with_project, EnvironmentInput::new(project.clone()))
                .expect("implicit project configuration resolves");
        assert!(environment.user_config().is_none());
        assert_eq!(environment.project_config(), Some(project_config.as_path()),);

        let explicit = fixture_platform()
            .with_file(
                project_config,
                FileIdentity::full(1, 21),
                b"not valid = [",
                Some(2),
            )
            .with_file(
                explicit_path.clone(),
                FileIdentity::full(1, 22),
                b"",
                Some(2),
            );
        let environment = resolve_with_platform(
            &explicit,
            EnvironmentInput::new(project).with_config_path(explicit_path.clone()),
        )
        .expect("explicit configuration suppresses implicit project file");
        assert_eq!(environment.user_config(), Some(explicit_path.as_path()),);
        assert!(environment.project_config().is_none());
    }

    #[test]
    fn failure_is_closed_and_redacted() {
        let project = native_fixture_path(["project"]);
        let raw_path = native_fixture_path(["linux", "outside", "private.toml"]);
        let failure = resolve_with_platform(
            &fixture_platform(),
            EnvironmentInput::new(project).with_config_path(raw_path.clone()),
        )
        .expect_err("configuration outside the user home is rejected");

        assert_eq!(failure.code(), ConfigurationFailureCode::PathUnavailable);
        let raw_path = raw_path.to_str().expect("fixture path is UTF-8");
        assert!(!format!("{:?}", failure).contains(raw_path));
        assert!(!failure.summary().contains(raw_path));
        assert!(!failure.next_action().contains(raw_path));
        assert!(!failure.to_string().contains(raw_path));
    }

    #[test]
    fn lock_identity_is_exact_and_compares_canonical_roots() {
        let project = native_fixture_path(["project"]);
        let state = project.join("state");
        let equivalent_state = project.join("./state/../state");
        let other_state = project.join("other");
        let equivalent_a = resolve_with_platform(
            &fixture_platform(),
            EnvironmentInput::new(project.clone()).with_state_dir(state),
        )
        .expect("first equivalent state root resolves");
        let equivalent_b = resolve_with_platform(
            &fixture_platform(),
            EnvironmentInput::new(project.clone()).with_state_dir(equivalent_state),
        )
        .expect("second equivalent state root resolves");
        let distinct = resolve_with_platform(
            &fixture_platform(),
            EnvironmentInput::new(project).with_state_dir(other_state),
        )
        .expect("distinct state root resolves");

        assert_eq!(equivalent_a.lock_identity(), equivalent_b.lock_identity());
        assert_ne!(equivalent_a.lock_identity(), distinct.lock_identity());
    }

    #[test]
    fn repeated_resolution_has_identical_observable_outcome() {
        let project = native_fixture_path(["project"]);
        let state = project.join("state");
        let outside = native_fixture_path(["linux", "outside.toml"]);
        let platform = fixture_platform();
        let input = EnvironmentInput::new(project.clone()).with_state_dir(state);
        let first = resolve_with_platform(&platform, input.clone()).expect("first resolution");
        let second = resolve_with_platform(&platform, input).expect("second resolution");

        assert_eq!(first.project_root(), second.project_root());
        assert_eq!(first.state(), second.state());
        assert_eq!(first.lock_identity(), second.lock_identity());
        assert_eq!(first.get("state_dir"), second.get("state_dir"));

        let failure_input = EnvironmentInput::new(project).with_config_path(outside);
        let first_failure = resolve_with_platform(&platform, failure_input.clone())
            .expect_err("first invalid resolution fails");
        let second_failure = resolve_with_platform(&platform, failure_input)
            .expect_err("second invalid resolution fails");
        assert_eq!(first_failure, second_failure);
    }

    #[test]
    fn public_entry_point_does_not_create_observed_paths() {
        let missing = PathBuf::from("/tmp/matinee-runtime-t037-no-create-9d6fb2");
        assert!(!missing.exists());

        let result = resolve_environment(EnvironmentInput::new(&missing));
        assert!(result.is_err());
        assert!(!missing.exists());
    }

    #[cfg(target_os = "windows")]
    fn windows_fixture_platform() -> FixturePlatform {
        let project = Path::new(r"C:\fixture\project");
        let project_identity = FileIdentity::full(7, 70);
        let state = Path::new(r"C:\Users\fixture\AppData\Local\Matinee\state");
        let state_identity = FileIdentity::full(7, 71);
        FixturePlatform::new(PlatformKind::Windows)
            .with_snapshot(project, FileSnapshot::directory(project_identity, Some(1)))
            .with_followed_file_identity(project, project_identity)
            .with_snapshot(state, FileSnapshot::directory(state_identity, Some(1)))
            .with_followed_file_identity(state, state_identity)
            .with_snapshot(
                r"C:\fixture\project\user-state",
                FileSnapshot::directory(FileIdentity::full(7, 73), Some(1)),
            )
            .with_followed_file_identity(
                r"C:\fixture\project\user-state",
                FileIdentity::full(7, 73),
            )
            .with_snapshot(
                r"C:\fixture\project\command-line-state",
                FileSnapshot::directory(FileIdentity::full(7, 74), Some(1)),
            )
            .with_followed_file_identity(
                r"C:\fixture\project\command-line-state",
                FileIdentity::full(7, 74),
            )
            .with_anchored_missing(project)
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_fixture_uses_exact_known_folder_defaults_without_profile_access() {
        let environment = resolve_with_platform(
            &windows_fixture_platform(),
            EnvironmentInput::new(r"C:\fixture\project"),
        )
        .expect("Windows fixture environment resolves");

        assert_eq!(
            environment.config(),
            Path::new(r"C:\Users\fixture\AppData\Roaming\Matinee")
        );
        assert_eq!(
            environment.state(),
            Path::new(r"C:\Users\fixture\AppData\Local\Matinee\state")
        );
        assert_eq!(
            environment.runtime(),
            Path::new(r"C:\Users\fixture\AppData\Local\Matinee\state\run")
        );
        assert_eq!(
            environment.cache(),
            Path::new(r"C:\Users\fixture\AppData\Local\Matinee\cache")
        );
        assert_eq!(
            environment.log(),
            Path::new(r"C:\Users\fixture\AppData\Local\Matinee\state\logs")
        );
        assert!(environment.user_config().is_none());
        assert!(environment.get("state_dir").is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_fixture_user_bytes_win_only_by_command_line_and_redacts_provenance() {
        let user_path = Path::new(r"C:\Users\fixture\AppData\Roaming\Matinee\config.toml");
        let user_bytes = b"state_dir = 'C:\\fixture\\project\\user-state'\n".to_vec();
        let platform = windows_fixture_platform().with_file(
            user_path,
            FileIdentity::full(7, 72),
            user_bytes,
            Some(2),
        );
        let environment = resolve_with_platform(
            &platform,
            EnvironmentInput::new(r"C:\fixture\project")
                .with_state_dir(r"C:\fixture\project\command-line-state"),
        )
        .expect("Windows user and command-line configuration resolves");

        assert_eq!(
            environment.user_config(),
            Some(user_path),
            "the fixture must load the exact supplied user-config bytes"
        );
        let setting = environment
            .get("state_dir")
            .expect("state_dir is supplied by configuration");
        assert_eq!(setting.source(), ConfigurationSource::CommandLine);
        assert_eq!(
            setting.provenance().source(),
            ConfigurationSource::CommandLine
        );
        assert_eq!(setting.provenance().key(), Some("state_dir"));
        assert_eq!(setting.value(), r"C:\fixture\project\command-line-state");
        assert_eq!(
            environment.state(),
            Path::new(r"C:\fixture\project\command-line-state")
        );

        let user_only =
            resolve_with_platform(&platform, EnvironmentInput::new(r"C:\fixture\project"))
                .expect("Windows user configuration resolves");
        let user_setting = user_only
            .get("state_dir")
            .expect("user state_dir is present");
        assert_eq!(user_setting.source(), ConfigurationSource::UserFile);
        assert_eq!(
            user_setting.provenance().source(),
            ConfigurationSource::UserFile
        );
        assert_eq!(
            user_setting.provenance().relative_path(),
            Some(Path::new(r"AppData\Roaming\Matinee\config.toml"))
        );
        let debug = format!("{:?}", user_setting.provenance());
        assert!(!debug.contains(r"C:\Users\fixture"));
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_fixture_mixed_case_registered_alias_is_source_forbidden() {
        let platform = windows_fixture_platform().with_environment(
            "MaTiNeE_StAtE_DiR",
            r"C:\fixture\project\environment-secret",
        );
        let failure =
            resolve_with_platform(&platform, EnvironmentInput::new(r"C:\fixture\project"))
                .expect_err("a mixed-case protected environment alias must be rejected");

        assert_eq!(failure.code(), ConfigurationFailureCode::SourceForbidden);
        let rendered = format!("{failure:?} {failure}");
        assert!(rendered.contains("environment"));
        assert!(!rendered.contains(r"C:\fixture\project"));
        assert!(!rendered.contains(r"C:\Users\fixture"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_fixture_mixed_case_unknown_alias_is_redacted() {
        let alias = "MaTiNeE_UnReGiStErEd";
        let value = "windows-alias-secret";
        let failure = resolve_with_platform(
            &windows_fixture_platform().with_environment(alias, value),
            EnvironmentInput::new(r"C:\fixture\project"),
        )
        .expect_err("a mixed-case unknown environment alias must be rejected");

        assert_eq!(failure.code(), ConfigurationFailureCode::KeyUnknown);
        let rendered = format!("{failure:?} {failure}");
        assert!(rendered.contains("environment"));
        assert!(!rendered.contains(alias));
        assert!(!rendered.contains(value));
        assert!(!rendered.contains(r"C:\fixture\project"));
        assert!(!rendered.contains(r"C:\Users\fixture"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_fixture_rejects_protected_sources_and_malformed_user_value() {
        let project_platform = windows_fixture_platform().with_anchored_file(
            r"C:\fixture\project",
            FileIdentity::full(7, 75),
            b"state_dir = 'project-state'\n".to_vec(),
            Some(2),
        );
        let project_failure = resolve_with_platform(
            &project_platform,
            EnvironmentInput::new(r"C:\fixture\project"),
        )
        .expect_err("project state_dir must remain protected");
        assert_eq!(
            project_failure.code(),
            ConfigurationFailureCode::SourceForbidden
        );

        let environment_failure = resolve_with_platform(
            &windows_fixture_platform()
                .with_environment("MATINEE_STATE_DIR", r"C:\fixture\project\environment-state"),
            EnvironmentInput::new(r"C:\fixture\project"),
        )
        .expect_err("environment state_dir must remain protected");
        assert_eq!(
            environment_failure.code(),
            ConfigurationFailureCode::SourceForbidden
        );

        let user_file = r"C:\Users\fixture\AppData\Roaming\Matinee\config.toml";
        let user_failure = resolve_with_platform(
            &windows_fixture_platform().with_file(
                user_file,
                FileIdentity::full(7, 76),
                b"state_dir = true\n".to_vec(),
                Some(2),
            ),
            EnvironmentInput::new(r"C:\fixture\project"),
        )
        .expect_err("malformed user state_dir must be rejected");
        assert_eq!(user_failure.code(), ConfigurationFailureCode::ValueInvalid);
        let rendered = format!("{user_failure:?} {user_failure}");
        assert!(!rendered.contains("true"));
        assert!(!rendered.contains(r"C:\fixture\project"));
        assert!(!rendered.contains(r"C:\Users\fixture"));
    }
}
