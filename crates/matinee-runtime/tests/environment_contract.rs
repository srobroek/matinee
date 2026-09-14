use matinee_runtime::{
    ConfigurationFailureCode, ConfigurationSource, EnvironmentInput, EnvironmentResult,
    ResolvedEnvironment, resolve_environment,
};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

static ENV_LOCK: Mutex<()> = Mutex::new(());
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct TempFixture {
    root: PathBuf,
    project_root: PathBuf,
}

impl TempFixture {
    fn new() -> Self {
        let root = loop {
            let counter = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            let candidate = std::env::temp_dir().join(format!(
                "matinee-runtime-contract-{}-{timestamp}-{counter}",
                std::process::id()
            ));
            if !candidate.exists() {
                fs::create_dir_all(&candidate).expect("create unique fixture root");
                break candidate;
            }
        };
        let project_root = root.join("project");
        fs::create_dir(&project_root).expect("create fixture project root");
        Self { root, project_root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn project_root(&self) -> &Path {
        &self.project_root
    }
}

impl Drop for TempFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct EnvironmentGuard {
    _lock: MutexGuard<'static, ()>,
    saved: Vec<(OsString, Option<OsString>)>,
}

impl EnvironmentGuard {
    fn acquire() -> Self {
        Self {
            _lock: ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            saved: Vec::new(),
        }
    }

    fn remember(&mut self, name: &OsStr) {
        if !self
            .saved
            .iter()
            .any(|(saved, _)| saved.as_os_str() == name)
        {
            self.saved.push((name.to_owned(), std::env::var_os(name)));
        }
    }

    fn set_path(&mut self, name: &str, value: &Path) {
        self.set_os(OsStr::new(name), value.as_os_str());
    }

    fn set_value(&mut self, name: &str, value: &str) {
        self.set_os(OsStr::new(name), OsStr::new(value));
    }

    fn set_os(&mut self, name: &OsStr, value: &OsStr) {
        self.remember(name);
        // Environment mutation is unsafe in edition 2024 because other threads may read it.
        unsafe {
            std::env::set_var(name, value);
        }
    }

    fn remove_os(&mut self, name: &OsStr) {
        self.remember(name);
        // Environment mutation is serialized by ENV_LOCK for this whole test body.
        unsafe {
            std::env::remove_var(name);
        }
    }

    fn clear_matinee_variables(&mut self) {
        let names = std::env::vars_os()
            .filter_map(|(name, _)| {
                if name
                    .to_str()
                    .is_some_and(|name| name.starts_with("MATINEE_"))
                {
                    Some(name)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for name in names {
            self.remove_os(&name);
        }
    }
}

impl Drop for EnvironmentGuard {
    fn drop(&mut self) {
        for (name, previous) in self.saved.iter().rev() {
            // Restore every touched variable before releasing ENV_LOCK.
            unsafe {
                match previous {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

fn configure_host_environment(fixture: &TempFixture, environment: &mut EnvironmentGuard) {
    environment.clear_matinee_variables();

    #[cfg(target_os = "macos")]
    {
        environment.set_path("HOME", &fixture.path("home"));
    }

    #[cfg(target_os = "linux")]
    {
        environment.set_path("HOME", &fixture.path("home"));
        environment.set_path("XDG_CONFIG_HOME", &fixture.path("xdg-config"));
        environment.set_path("XDG_DATA_HOME", &fixture.path("xdg-data"));
        environment.set_path("XDG_STATE_HOME", &fixture.path("xdg-state"));
        environment.set_path("XDG_RUNTIME_DIR", &fixture.path("xdg-runtime"));
        environment.set_path("XDG_CACHE_HOME", &fixture.path("xdg-cache"));
        environment.set_path("XDG_BIN_HOME", &fixture.path("xdg-bin"));
    }

    #[cfg(target_os = "windows")]
    {
        // These variables are restored for hygiene, but directories 6.0 obtains Windows bases
        // from SHGetKnownFolderPath, so they cannot force a fixture profile.
        environment.set_path("USERPROFILE", &fixture.path("profile"));
        environment.set_path("APPDATA", &fixture.path("roaming"));
        environment.set_path("LOCALAPPDATA", &fixture.path("local"));
    }
}

fn assert_distinct_absolute_paths(resolved: &ResolvedEnvironment) {
    let paths = [
        resolved.config(),
        resolved.state(),
        resolved.runtime(),
        resolved.cache(),
        resolved.log(),
    ];
    for path in paths {
        assert!(
            !path.as_os_str().is_empty(),
            "resolved path must not be empty"
        );
        assert!(
            path.is_absolute(),
            "resolved path must be absolute: {path:?}"
        );
    }
    for (index, left) in paths.iter().enumerate() {
        for right in paths.iter().skip(index + 1) {
            assert_ne!(left, right, "resolved path kinds must be distinct");
        }
    }
}

#[cfg(target_os = "windows")]
fn assert_component_suffix(path: &Path, suffix: &[&str]) {
    let components = path.components().collect::<Vec<_>>();
    assert!(
        components.len() >= suffix.len(),
        "path {path:?} is shorter than its expected suffix"
    );
    for (actual, expected) in components.iter().rev().zip(suffix.iter().rev()) {
        let expected = Path::new(expected)
            .components()
            .next()
            .expect("non-empty expected path component");
        assert_eq!(*actual, expected, "path suffix mismatch for {path:?}");
    }
}

#[test]
fn crate_root_exposes_environment_resolution_contract() {
    // This catches a regression that removes the public input, source, or wire-name contract.
    let input = EnvironmentInput::new("/workspace/project")
        .with_config_path("config.toml")
        .with_state_dir("state");
    assert_eq!(input.project_root(), Path::new("/workspace/project"));
    assert_eq!(input.config_path(), Some(Path::new("config.toml")));
    assert_eq!(input.state_dir(), Some(Path::new("state")));

    let source = ConfigurationSource::ProjectFile;
    assert_eq!(source.precedence(), 2);
    assert!(source.is_higher_than(ConfigurationSource::UserFile));
    assert_eq!(source.as_str(), "project_file");

    let result: EnvironmentResult<EnvironmentInput> = Ok(input.clone());
    assert_eq!(result.ok(), Some(input));
    assert_eq!(
        ConfigurationFailureCode::KeyUnknown.as_str(),
        "config.key_unknown"
    );
}

#[test]
fn host_base_directories_derive_exact_paths() {
    // This catches a regression that changes a platform's directory suffix or chooses the wrong base.
    let fixture = TempFixture::new();
    let mut environment = EnvironmentGuard::acquire();
    configure_host_environment(&fixture, &mut environment);

    #[cfg(target_os = "macos")]
    {
        let home = fixture.path("home");
        let application_support = home.join("Library/Application Support");
        let config = application_support.join("Matinee");
        let state = config.join("state");
        let resolved = resolve_environment(EnvironmentInput::new(fixture.project_root()))
            .expect("macOS host paths resolve");
        assert_eq!(resolved.config(), config);
        assert_eq!(resolved.state(), state);
        assert_eq!(resolved.runtime(), state.join("run"));
        assert_eq!(
            resolved.cache(),
            home.join("Library/Caches").join("Matinee")
        );
        assert_eq!(resolved.log(), home.join("Library/Logs").join("Matinee"));
    }

    #[cfg(target_os = "linux")]
    {
        let config = fixture.path("xdg-config").join("matinee");
        let state = fixture.path("xdg-state").join("matinee");
        let resolved = resolve_environment(EnvironmentInput::new(fixture.project_root()))
            .expect("Linux host paths resolve");
        assert_eq!(resolved.config(), config);
        assert_eq!(resolved.state(), state);
        assert_eq!(
            resolved.runtime(),
            fixture.path("xdg-runtime").join("matinee")
        );
        assert_eq!(resolved.cache(), fixture.path("xdg-cache").join("matinee"));
        assert_eq!(resolved.log(), state.join("logs"));
    }

    #[cfg(target_os = "windows")]
    {
        let resolved = resolve_environment(EnvironmentInput::new(fixture.project_root()))
            .expect("Windows host paths resolve");
        // SHGetKnownFolderPath ignores USERPROFILE/APPDATA/LOCALAPPDATA fixtures. Assert exact
        // derived suffix components and shared known-folder ancestry instead of a forced base.
        assert_distinct_absolute_paths(&resolved);
        assert_component_suffix(resolved.config(), &["Matinee"]);
        assert_component_suffix(resolved.state(), &["Matinee", "state"]);
        assert_component_suffix(resolved.runtime(), &["Matinee", "state", "run"]);
        assert_component_suffix(resolved.cache(), &["Matinee", "cache"]);
        assert_component_suffix(resolved.log(), &["Matinee", "state", "logs"]);
        let local_matinee = resolved
            .state()
            .parent()
            .expect("Windows Matinee state root");
        assert_eq!(resolved.cache().parent(), Some(local_matinee));
        assert_eq!(
            resolved.runtime().parent().and_then(Path::parent),
            Some(local_matinee)
        );
        assert_eq!(
            resolved.log().parent().and_then(Path::parent),
            Some(local_matinee)
        );
    }
}

#[test]
fn resolution_returns_one_distinct_absolute_path_per_kind() {
    // This catches a regression that aliases two required path kinds or returns relative paths.
    let fixture = TempFixture::new();
    let mut environment = EnvironmentGuard::acquire();
    configure_host_environment(&fixture, &mut environment);
    let resolved = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect("host environment resolves");
    assert_distinct_absolute_paths(&resolved);
}

#[test]
fn missing_required_base_returns_closed_path_failure() {
    // This catches a regression that accepts an invalid required base or returns a partial result.
    let fixture = TempFixture::new();
    let mut environment = EnvironmentGuard::acquire();
    environment.clear_matinee_variables();

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        // A blank Unix HOME falls back to passwd, so a relative HOME deterministically fails the
        // required-base check instead of depending on the developer's real home directory.
        environment.set_value("HOME", "relative-home");
        #[cfg(target_os = "linux")]
        for name in [
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR",
            "XDG_CACHE_HOME",
            "XDG_BIN_HOME",
        ] {
            environment.remove_os(OsStr::new(name));
        }
        let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
            .expect_err("invalid required base must fail");
        assert_eq!(failure.code(), ConfigurationFailureCode::PathUnavailable);
    }

    #[cfg(target_os = "windows")]
    {
        // Windows known folders cannot be blanked through profile variables; a missing project
        // root still proves the public resolver returns the same closed path failure.
        let failure = resolve_environment(EnvironmentInput::new(fixture.path("missing-project")))
            .expect_err("missing root must fail closed");
        assert_eq!(failure.code(), ConfigurationFailureCode::PathUnavailable);
    }
}

#[test]
fn resolution_creates_no_derived_directories() {
    // This catches a regression that eagerly creates one or more derived directories during resolution.
    let fixture = TempFixture::new();
    let mut environment = EnvironmentGuard::acquire();
    configure_host_environment(&fixture, &mut environment);
    #[cfg(not(target_os = "windows"))]
    let fixture_bases = [
        fixture.path("home"),
        fixture.path("xdg-config"),
        fixture.path("xdg-state"),
        fixture.path("xdg-runtime"),
        fixture.path("xdg-cache"),
    ];
    #[cfg(not(target_os = "windows"))]
    for base in fixture_bases {
        assert!(!base.exists(), "base fixture must start absent: {base:?}");
    }

    let resolved = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect("host environment resolves without creating directories");
    let derived = [
        resolved.config(),
        resolved.state(),
        resolved.runtime(),
        resolved.cache(),
        resolved.log(),
    ];
    let before = derived.iter().map(|path| path.exists()).collect::<Vec<_>>();
    #[cfg(not(target_os = "windows"))]
    assert!(
        before.iter().all(|exists| !exists),
        "derived fixtures start absent"
    );
    let after = derived.iter().map(|path| path.exists()).collect::<Vec<_>>();
    #[cfg(not(target_os = "windows"))]
    assert!(
        after.iter().all(|exists| !exists),
        "resolution must create no derived paths"
    );
    #[cfg(target_os = "windows")]
    assert_eq!(
        after, before,
        "Windows resolution must not create known-folder paths"
    );
}

#[test]
fn relative_state_path_resolves_against_project_root() {
    // This catches a regression that interprets relative environment paths against the process cwd.
    let fixture = TempFixture::new();
    let mut environment = EnvironmentGuard::acquire();
    configure_host_environment(&fixture, &mut environment);
    let resolved = resolve_environment(
        EnvironmentInput::new(fixture.project_root()).with_state_dir("state/../relative-state"),
    )
    .expect("relative state path resolves");

    assert_eq!(
        resolved.state(),
        fixture.project_root().join("relative-state")
    );
}

#[test]
fn absolute_state_path_preserves_its_root() {
    // This catches a regression that reinterprets an absolute override below the project root.
    let fixture = TempFixture::new();
    let mut environment = EnvironmentGuard::acquire();
    configure_host_environment(&fixture, &mut environment);
    let absolute = fixture.path("absolute-state");
    let resolved = resolve_environment(
        EnvironmentInput::new(fixture.project_root()).with_state_dir(&absolute),
    )
    .expect("absolute state path resolves");

    assert_eq!(resolved.state(), absolute);
}

#[test]
fn state_path_normalization_removes_dot_segments_without_filesystem_access() {
    // This catches a regression that leaves lexical dot segments in the resolved path.
    let fixture = TempFixture::new();
    let mut environment = EnvironmentGuard::acquire();
    configure_host_environment(&fixture, &mut environment);
    let input = fixture.path("nested/./child/../normalized/./state");
    let resolved =
        resolve_environment(EnvironmentInput::new(fixture.project_root()).with_state_dir(&input))
            .expect("normalized state path resolves");

    assert_eq!(resolved.state(), fixture.path("nested/normalized/state"));
}

#[test]
fn case_equivalent_state_paths_follow_anchor_filesystem_semantics() {
    // This catches a regression that applies one case policy to every target platform.
    let fixture = TempFixture::new();
    let mut environment = EnvironmentGuard::acquire();
    configure_host_environment(&fixture, &mut environment);

    let case_root = fixture.path("case-root");
    fs::create_dir(&case_root).expect("create case-semantics anchor");
    let uppercase_case_root = fixture.path("CASE-ROOT");
    let case_insensitive = uppercase_case_root.exists();
    let lower = case_root.join("state");
    let upper = uppercase_case_root.join("STATE");
    let lower_result =
        resolve_environment(EnvironmentInput::new(fixture.project_root()).with_state_dir(&lower))
            .expect("lower-case state path resolves");
    let upper_result =
        resolve_environment(EnvironmentInput::new(fixture.project_root()).with_state_dir(&upper))
            .expect("upper-case state path resolves");

    assert_eq!(
        lower_result.lock_identity() == upper_result.lock_identity(),
        case_insensitive,
        "case-equivalent paths must follow the anchor filesystem semantics"
    );
}

#[test]
fn supported_symbolic_link_project_root_converges_with_target_identity() {
    // This catches a regression that treats a supported project-root alias as a distinct state root.
    let fixture = TempFixture::new();
    let alias = fixture.path("project-alias");
    #[cfg(unix)]
    std::os::unix::fs::symlink(fixture.project_root(), &alias)
        .expect("create project-root symbolic link");
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(fixture.project_root(), &alias)
        .expect("create project-root symbolic link");

    let mut environment = EnvironmentGuard::acquire();
    configure_host_environment(&fixture, &mut environment);
    let target =
        resolve_environment(EnvironmentInput::new(fixture.project_root()).with_state_dir("state"))
            .expect("target project root resolves");
    let aliased = resolve_environment(EnvironmentInput::new(&alias).with_state_dir("state"))
        .expect("symbolic-link project root resolves");

    assert_eq!(target.lock_identity(), aliased.lock_identity());
}

#[test]
fn command_line_state_override_preserves_host_paths_and_lock_identity() {
    // This catches a regression that lets the state override replace other paths or collides lock identities.
    let fixture = TempFixture::new();
    let mut environment = EnvironmentGuard::acquire();
    configure_host_environment(&fixture, &mut environment);
    let baseline = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect("baseline host environment resolves");
    let first_state = fixture.path("state-first");
    let second_state = fixture.path("state-second");
    let first = resolve_environment(
        EnvironmentInput::new(fixture.project_root()).with_state_dir(&first_state),
    )
    .expect("first state override resolves");
    let same = resolve_environment(
        EnvironmentInput::new(fixture.project_root()).with_state_dir(&first_state),
    )
    .expect("repeat state override resolves");
    let different = resolve_environment(
        EnvironmentInput::new(fixture.project_root()).with_state_dir(&second_state),
    )
    .expect("different state override resolves");

    assert_eq!(first.state(), first_state);
    assert_eq!(first.config(), baseline.config());
    assert_eq!(first.runtime(), baseline.runtime());
    assert_eq!(first.cache(), baseline.cache());
    assert_eq!(first.log(), baseline.log());
    let setting = first.get("state_dir").expect("state override setting");
    assert_eq!(setting.source(), ConfigurationSource::CommandLine);
    assert_eq!(
        setting.value(),
        first_state.to_str().expect("UTF-8 fixture path")
    );
    assert_eq!(
        setting.provenance().source(),
        ConfigurationSource::CommandLine
    );
    assert_eq!(setting.provenance().relative_path(), None);
    assert_eq!(setting.provenance().key(), Some("state_dir"));
    assert_eq!(first.lock_identity(), same.lock_identity());
    assert_ne!(first.lock_identity(), different.lock_identity());
}

#[cfg(unix)]
#[test]
fn escaped_implicit_project_file_is_rejected_before_target_read() {
    // A malformed outside target distinguishes containment rejection from a read followed by
    // parsing: the resolver must return project_escape without observing target contents.
    let fixture = TempFixture::new();
    let outside = fixture.path("outside.toml");
    fs::write(&outside, b"this is not valid TOML = [").expect("write outside target");
    std::os::unix::fs::symlink(&outside, fixture.project_root().join("matinee.toml"))
        .expect("link implicit project file outside project root");

    let mut environment = EnvironmentGuard::acquire();
    configure_host_environment(&fixture, &mut environment);
    let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect_err("escaped implicit project file must fail closed");

    assert_eq!(failure.code(), ConfigurationFailureCode::ProjectEscape);
    assert_eq!(fs::read(&outside).expect("outside target remains readable"), b"this is not valid TOML = [");
}

#[cfg(unix)]
#[test]
fn linked_implicit_project_file_is_rejected_before_file_read() {
    // Even a link whose target is inside the project is not an ordinary project file. A malformed
    // target makes a syntax error observable if validation accidentally reads through the link.
    let fixture = TempFixture::new();
    let target = fixture.project_root().join("target.toml");
    fs::write(&target, b"this is not valid TOML = [").expect("write linked target");
    std::os::unix::fs::symlink(&target, fixture.project_root().join("matinee.toml"))
        .expect("link implicit project file");

    let mut environment = EnvironmentGuard::acquire();
    configure_host_environment(&fixture, &mut environment);
    let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect_err("linked implicit project file must fail closed");

    assert_eq!(failure.code(), ConfigurationFailureCode::ProjectEscape);
    assert_eq!(fs::read(&target).expect("linked target remains readable"), b"this is not valid TOML = [");
}
