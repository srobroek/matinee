use std::borrow::Borrow;
use std::path::Path;
use std::sync::OnceLock;

pub(crate) mod config;
pub(crate) mod environment;
pub(crate) mod error;
pub(crate) mod platform;

pub(crate) mod path_identity;
pub use environment::{ConfigurationSource, EnvironmentInput, EnvironmentResult, Provenance};
pub use error::{ConfigurationFailure, ConfigurationFailureCode};

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
    use crate::platform::{FileIdentity, FileSnapshot, FixturePlatform, PlatformKind};
    use std::path::PathBuf;

    fn fixture_platform() -> FixturePlatform {
        let root = FileIdentity::full(1, 10);
        FixturePlatform::new(PlatformKind::Linux)
            .with_snapshot("/fixture/project", FileSnapshot::directory(root, Some(1)))
            .with_followed_file_identity("/fixture/project", root)
            .with_snapshot(
                "/fixture/linux/home/.local/state",
                FileSnapshot::directory(FileIdentity::full(1, 11), Some(1)),
            )
    }

    #[test]
    fn success_exposes_complete_environment_and_effective_state() {
        let environment = resolve_with_platform(
            &fixture_platform(),
            EnvironmentInput::new("/fixture/project")
                .with_state_dir("/fixture/project/custom-state"),
        )
        .expect("fixture environment resolves");

        assert_eq!(environment.project_root(), Path::new("/fixture/project"));
        assert!(environment.user_config().is_none());
        assert!(environment.project_config().is_none());
        assert_eq!(
            environment.config(),
            Path::new("/fixture/linux/home/.config/matinee")
        );
        assert_eq!(
            environment.state(),
            Path::new("/fixture/project/custom-state")
        );
        assert_eq!(
            environment.runtime(),
            Path::new("/fixture/linux/runtime/matinee")
        );
        assert_eq!(
            environment.cache(),
            Path::new("/fixture/linux/home/.cache/matinee")
        );
        assert_eq!(
            environment.log(),
            Path::new("/fixture/linux/home/.local/state/matinee/logs")
        );

        let setting = environment
            .get("state_dir")
            .expect("state_dir setting is present");
        assert_eq!(setting.key(), "state_dir");
        assert_eq!(setting.value(), "/fixture/project/custom-state");
        assert_eq!(setting.source(), ConfigurationSource::CommandLine);
        assert_eq!(
            setting.provenance().source(),
            ConfigurationSource::CommandLine
        );
        assert_eq!(setting.provenance().key(), Some("state_dir"));
        assert!(!format!("{:?}", environment.lock_identity()).contains("/fixture"));
    }

    #[test]
    fn configuration_paths_report_only_files_that_were_loaded() {
        let with_project = fixture_platform().with_file(
            "/fixture/project/matinee.toml",
            FileIdentity::full(1, 20),
            b"",
            Some(2),
        );
        let environment =
            resolve_with_platform(&with_project, EnvironmentInput::new("/fixture/project"))
                .expect("implicit project configuration resolves");
        assert!(environment.user_config().is_none());
        assert_eq!(
            environment.project_config(),
            Some(Path::new("/fixture/project/matinee.toml")),
        );

        let explicit = fixture_platform()
            .with_file(
                "/fixture/project/matinee.toml",
                FileIdentity::full(1, 21),
                b"not valid = [",
                Some(2),
            )
            .with_file(
                "/fixture/linux/home/explicit.toml",
                FileIdentity::full(1, 22),
                b"",
                Some(2),
            );
        let environment = resolve_with_platform(
            &explicit,
            EnvironmentInput::new("/fixture/project")
                .with_config_path("/fixture/linux/home/explicit.toml"),
        )
        .expect("explicit configuration suppresses implicit project file");
        assert_eq!(
            environment.user_config(),
            Some(Path::new("/fixture/linux/home/explicit.toml")),
        );
        assert!(environment.project_config().is_none());
    }

    #[test]
    fn failure_is_closed_and_redacted() {
        let raw_path = "/fixture/linux/outside/private.toml";
        let failure = resolve_with_platform(
            &fixture_platform(),
            EnvironmentInput::new("/fixture/project").with_config_path(raw_path),
        )
        .expect_err("configuration outside the user home is rejected");

        assert_eq!(failure.code(), ConfigurationFailureCode::PathUnavailable);
        assert!(!format!("{:?}", failure).contains(raw_path));
        assert!(!failure.summary().contains(raw_path));
        assert!(!failure.next_action().contains(raw_path));
        assert!(!failure.to_string().contains(raw_path));
    }

    #[test]
    fn lock_identity_is_exact_and_compares_canonical_roots() {
        let equivalent_a = resolve_with_platform(
            &fixture_platform(),
            EnvironmentInput::new("/fixture/project").with_state_dir("/fixture/project/state"),
        )
        .expect("first equivalent state root resolves");
        let equivalent_b = resolve_with_platform(
            &fixture_platform(),
            EnvironmentInput::new("/fixture/project")
                .with_state_dir("/fixture/project/./state/../state"),
        )
        .expect("second equivalent state root resolves");
        let distinct = resolve_with_platform(
            &fixture_platform(),
            EnvironmentInput::new("/fixture/project").with_state_dir("/fixture/project/other"),
        )
        .expect("distinct state root resolves");

        assert_eq!(equivalent_a.lock_identity(), equivalent_b.lock_identity());
        assert_ne!(equivalent_a.lock_identity(), distinct.lock_identity());
    }

    #[test]
    fn repeated_resolution_has_identical_observable_outcome() {
        let platform = fixture_platform();
        let input =
            EnvironmentInput::new("/fixture/project").with_state_dir("/fixture/project/state");
        let first = resolve_with_platform(&platform, input.clone()).expect("first resolution");
        let second = resolve_with_platform(&platform, input).expect("second resolution");

        assert_eq!(first.project_root(), second.project_root());
        assert_eq!(first.state(), second.state());
        assert_eq!(first.lock_identity(), second.lock_identity());
        assert_eq!(first.get("state_dir"), second.get("state_dir"));

        let failure_input = EnvironmentInput::new("/fixture/project")
            .with_config_path("/fixture/linux/outside.toml");
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
            .with_snapshot(
                project,
                FileSnapshot::directory(project_identity, Some(1)),
            )
            .with_followed_file_identity(project, project_identity)
            .with_snapshot(
                state,
                FileSnapshot::directory(state_identity, Some(1)),
            )
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
        assert_eq!(
            setting.value(),
            r"C:\fixture\project\command-line-state"
        );
        assert_eq!(environment.state(), Path::new(r"C:\fixture\project\command-line-state"));

        let user_only = resolve_with_platform(
            &platform,
            EnvironmentInput::new(r"C:\fixture\project"),
        )
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
}