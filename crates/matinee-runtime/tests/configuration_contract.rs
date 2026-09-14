use matinee_runtime::{
    ConfigurationFailureCode, ConfigurationSource, EnvironmentInput, resolve_environment,
};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

static ENV_LOCK: Mutex<()> = Mutex::new(());
static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

const ENVIRONMENT_NAMES: &[&str] = &[
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_STATE_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR",
    "APPDATA",
    "LOCALAPPDATA",
    "USERPROFILE",
    "MATINEE_STATE_DIR",
    "MATINEE_UNREGISTERED",
];

struct TestFixture {
    _lock: MutexGuard<'static, ()>,
    root: PathBuf,
    saved_environment: Vec<(OsString, Option<OsString>)>,
}

impl TestFixture {
    fn new() -> Self {
        let lock = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = unique_temp_root();
        fs::create_dir_all(root.join("project")).expect("create project fixture root");

        let mut names = ENVIRONMENT_NAMES
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("MATINEE_")
                && !names.iter().any(|saved| saved == &name)
            {
                names.push(name);
            }
        }
        let saved_environment = names
            .into_iter()
            .map(|name| {
                let previous = std::env::var_os(&name);
                unsafe { std::env::remove_var(&name) };
                (name, previous)
            })
            .collect::<Vec<_>>();

        let home = root.join("home");
        let config = home.join(".config");
        let state = home.join(".local").join("state");
        let data = home.join(".local").join("share");
        let cache = home.join(".cache");
        let runtime = root.join("runtime");
        let appdata = root.join("appdata");
        let localappdata = root.join("localappdata");
        for path in [
            &home,
            &config,
            &state,
            &data,
            &cache,
            &runtime,
            &appdata,
            &localappdata,
        ] {
            fs::create_dir_all(path).expect("create host base directory fixture");
        }
        for (name, value) in [
            ("HOME", &home),
            ("XDG_CONFIG_HOME", &config),
            ("XDG_STATE_HOME", &state),
            ("XDG_DATA_HOME", &data),
            ("XDG_CACHE_HOME", &cache),
            ("XDG_RUNTIME_DIR", &runtime),
            ("APPDATA", &appdata),
            ("LOCALAPPDATA", &localappdata),
            ("USERPROFILE", &home),
        ] {
            unsafe { std::env::set_var(name, value) };
        }

        Self {
            _lock: lock,
            root,
            saved_environment,
        }
    }

    fn project_root(&self) -> PathBuf {
        self.root.join("project")
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn user_config(&self) -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            self.home()
                .join("Library")
                .join("Application Support")
                .join("Matinee")
                .join("config.toml")
        }
        #[cfg(target_os = "linux")]
        {
            self.home()
                .join(".config")
                .join("matinee")
                .join("config.toml")
        }
        #[cfg(target_os = "windows")]
        {
            self.root
                .join("appdata")
                .join("Matinee")
                .join("config.toml")
        }
    }

    fn write_user_config(&self, contents: &str) {
        let path = self.user_config();
        fs::create_dir_all(path.parent().expect("user config has a parent"))
            .expect("create user config directory");
        fs::write(path, contents).expect("write user configuration");
    }

    fn write_project_config(&self, contents: &str) {
        fs::write(self.project_root().join("matinee.toml"), contents)
            .expect("write project configuration");
    }

    fn set_environment(&self, name: &str, value: &str) {
        unsafe { std::env::set_var(name, value) };
    }

    fn state_value(&self, name: &str) -> PathBuf {
        self.root.join("values").join(name)
    }

    fn default_state(&self) -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            self.home()
                .join("Library")
                .join("Application Support")
                .join("Matinee")
                .join("state")
        }
        #[cfg(target_os = "linux")]
        {
            self.home()
                .join(".local")
                .join("state")
                .join("matinee")
        }
        #[cfg(target_os = "windows")]
        {
            self.root.join("localappdata").join("Matinee").join("state")
        }
    }
}

impl Drop for TestFixture {
    fn drop(&mut self) {
        for (name, value) in &self.saved_environment {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn unique_temp_root() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "matinee-runtime-configuration-{}-{timestamp}-{id}",
        std::process::id()
    ))
}

fn assert_state_setting(
    environment: &matinee_runtime::ResolvedEnvironment,
    expected_source: ConfigurationSource,
    expected_value: &Path,
) {
    let setting = environment
        .get("state_dir")
        .expect("state_dir is present when supplied by a configuration source");
    assert_eq!(setting.source(), expected_source);
    let expected_value_string = expected_value.to_string_lossy();
    assert_eq!(setting.value(), expected_value_string.as_ref());
    assert_eq!(environment.state(), expected_value);
}

#[test]
fn precedence_enum_pins_the_complete_ladder() {
    // Catches a reordered precedence ladder that changes winners in future layers.
    let sources = [
        ConfigurationSource::Default,
        ConfigurationSource::UserFile,
        ConfigurationSource::ProjectFile,
        ConfigurationSource::Environment,
        ConfigurationSource::CommandLine,
    ];
    for (index, source) in sources.iter().enumerate() {
        assert_eq!(source.precedence(), index as u8);
        for (other_index, other) in sources.iter().enumerate() {
            assert_eq!(
                source.is_higher_than(*other),
                index > other_index,
                "unexpected ordering for {:?} over {:?}",
                source,
                other
            );
        }
    }
}

#[test]
fn user_file_beats_the_built_in_state_fallback() {
    // Catches a resolver that ignores a user-file state_dir and keeps the host default.
    let fixture = TestFixture::new();
    let user_value = fixture.state_value("user-over-default");
    fixture.write_user_config(&format!("state_dir = {:?}\n", user_value.to_string_lossy()));

    let environment = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect("user-file configuration resolves");
    assert_state_setting(&environment, ConfigurationSource::UserFile, &user_value);
}

#[test]
fn command_line_beats_the_built_in_state_fallback() {
    // Catches a resolver that fails to apply the explicit state-dir command-line override.
    let fixture = TestFixture::new();
    let command_line_value = fixture.state_value("command-line-over-default");

    let environment = resolve_environment(
        EnvironmentInput::new(fixture.project_root()).with_state_dir(&command_line_value),
    )
    .expect("command-line configuration resolves");
    assert_state_setting(
        &environment,
        ConfigurationSource::CommandLine,
        &command_line_value,
    );
}

#[test]
fn command_line_beats_the_user_file() {
    // Catches a merge that gives user-file values precedence over explicit command-line values.
    let fixture = TestFixture::new();
    let user_value = fixture.state_value("user-loses");
    let command_line_value = fixture.state_value("command-line-wins");
    fixture.write_user_config(&format!("state_dir = {:?}\n", user_value.to_string_lossy()));

    let environment = resolve_environment(
        EnvironmentInput::new(fixture.project_root()).with_state_dir(&command_line_value),
    )
    .expect("user-file and command-line configuration resolves");
    assert_state_setting(
        &environment,
        ConfigurationSource::CommandLine,
        &command_line_value,
    );
}

#[test]
fn project_file_state_dir_is_rejected_as_forbidden() {
    // Catches a protected state_dir accidentally becoming selectable from the project file.
    let fixture = TestFixture::new();
    fixture.write_project_config("state_dir = \"project-value\"\n");

    let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect_err("project-file state_dir must be rejected");
    assert_eq!(failure.code(), ConfigurationFailureCode::SourceForbidden);
}

#[test]
fn environment_state_dir_is_rejected_as_forbidden() {
    // Catches a protected state_dir accidentally becoming selectable from MATINEE_ variables.
    let fixture = TestFixture::new();
    fixture.set_environment("MATINEE_STATE_DIR", "environment-value");

    let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect_err("environment state_dir must be rejected");
    assert_eq!(failure.code(), ConfigurationFailureCode::SourceForbidden);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_case_alias_for_registered_environment_name_uses_native_comparison() {
    // Windows environment names are case-insensitive before they are mapped to keys.
    // A mixed-case alias must therefore reach the registered protected descriptor and
    // be rejected for the environment source, rather than being silently ignored.
    let fixture = TestFixture::new();
    fixture.set_environment("matinee_state_dir", "environment-value");

    let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect_err("a Windows case alias for state_dir must be rejected");
    assert_eq!(failure.code(), ConfigurationFailureCode::SourceForbidden);
}

#[cfg(target_os = "windows")]
#[test]
fn windows_case_alias_for_unknown_environment_name_maps_before_lookup() {
    // Case normalization must happen before descriptor lookup, so a mixed-case alias
    // remains an unknown key and cannot leak its spelling or value in the failure.
    let fixture = TestFixture::new();
    let alias = "MaTiNeE_UnReGiStErEd";
    let value = "windows-alias-secret";
    fixture.set_environment(alias, value);

    let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect_err("a Windows case alias for an unknown key must be rejected");
    assert_eq!(failure.code(), ConfigurationFailureCode::KeyUnknown);
    let rendered = format!("{failure:?} {failure}");
    assert!(rendered.contains("environment"));
    assert!(!rendered.contains(alias));
    assert!(!rendered.contains(value));
}

#[test]
fn unknown_keys_are_rejected_in_each_external_source() {
    // Catches a source-specific parser or merge path that silently accepts unknown keys.
    for source in ["user", "project", "environment"] {
        let fixture = TestFixture::new();
        let failure = match source {
            "user" => {
                fixture.write_user_config("unregistered = \"value\"\n");
                resolve_environment(EnvironmentInput::new(fixture.project_root()))
            }
            "project" => {
                fixture.write_project_config("unregistered = \"value\"\n");
                resolve_environment(EnvironmentInput::new(fixture.project_root()))
            }
            "environment" => {
                fixture.set_environment("MATINEE_UNREGISTERED", "value");
                resolve_environment(EnvironmentInput::new(fixture.project_root()))
            }
            _ => unreachable!("source list is closed"),
        }
        .expect_err("unknown key must be rejected");
        assert_eq!(
            failure.code(),
            ConfigurationFailureCode::KeyUnknown,
            "source: {source}"
        );
    }
}

#[test]
fn reserved_keys_are_unknown_until_their_descriptor_is_registered() {
    // Reserved names do not bypass descriptor lookup merely because a future
    // specification has marked them as protected.
    for source in ["user", "project", "environment"] {
        let fixture = TestFixture::new();
        let failure = match source {
            "user" => {
                fixture.write_user_config("daemon.endpoint = \"http://secret.example\"\n");
                resolve_environment(EnvironmentInput::new(fixture.project_root()))
            }
            "project" => {
                fixture.write_project_config("principal.native = \"native-secret\"\n");
                resolve_environment(EnvironmentInput::new(fixture.project_root()))
            }
            "environment" => {
                fixture.set_environment("MATINEE_EXTENSION__DEVELOPMENT_IDENTITY", "identity");
                resolve_environment(EnvironmentInput::new(fixture.project_root()))
            }
            _ => unreachable!("source list is closed"),
        }
        .expect_err("unregistered reserved keys must remain unknown");
        assert_eq!(
            failure.code(),
            ConfigurationFailureCode::KeyUnknown,
            "source: {source}"
        );
    }
}

#[test]
fn unknown_key_failure_is_redacted_and_does_not_return_partial_state() {
    let fixture = TestFixture::new();
    let rejected_key = "credentials.api_token";
    let secret_value = "raw-secret-that-must-not-leak";
    fixture.write_user_config(&format!(
        "state_dir = \"accepted-but-not-returned\"\n{rejected_key} = \"{secret_value}\"\n"
    ));

    let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect_err("an unknown key rejects the complete resolution");
    assert_eq!(failure.code(), ConfigurationFailureCode::KeyUnknown);
    let rendered = format!("{failure:?} {failure}");
    assert!(rendered.contains("user-file"));
    assert!(!rendered.contains(rejected_key));
    assert!(!rendered.contains(secret_value));
    let root_text = fixture.root.to_string_lossy();
    assert!(!rendered.contains(root_text.as_ref()));
}

#[test]
fn malformed_registered_value_is_rejected_after_source_authorization() {
    let fixture = TestFixture::new();
    fixture.write_user_config("state_dir = true\n");

    let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect_err("a registered state_dir with the wrong TOML type must fail");
    assert_eq!(failure.code(), ConfigurationFailureCode::ValueInvalid);
    let rendered = format!("{failure:?} {failure}");
    assert!(!rendered.contains("true"));
    let root_text = fixture.root.to_string_lossy();
    assert!(!rendered.contains(root_text.as_ref()));
}

#[test]
fn duplicate_project_key_is_rejected_before_merge() {
    let fixture = TestFixture::new();
    fixture.write_project_config("state_dir = \"first\"\nstate_dir = \"second\"\n");

    let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect_err("duplicate project assignments must be rejected");
    assert_eq!(failure.code(), ConfigurationFailureCode::KeyDuplicate);
}

#[test]
fn environment_names_that_normalize_to_one_key_are_rejected_as_duplicates() {
    let fixture = TestFixture::new();
    fixture.set_environment("MATINEE_DUPLICATE__KEY", "first");
    fixture.set_environment("MATINEE_DUPLICATE__key", "second");

    let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect_err("distinct environment spellings mapping to one key must fail");
    assert_eq!(failure.code(), ConfigurationFailureCode::KeyDuplicate);
}
#[test]
fn duplicate_user_key_is_rejected() {
    // Catches a parser that lets a duplicate assignment overwrite an earlier user value.
    let fixture = TestFixture::new();
    fixture.write_user_config("state_dir = \"first\"\nstate_dir = \"second\"\n");

    let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect_err("duplicate user key must be rejected");
    assert_eq!(failure.code(), ConfigurationFailureCode::KeyDuplicate);
}

#[test]
fn no_override_uses_the_host_derived_default_state_path() {
    // Catches a resolver that creates a setting from an unconfigured key or derives the wrong host path.
    let fixture = TestFixture::new();

    let environment = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect("default environment resolves");
    assert_eq!(environment.state(), fixture.default_state());
    assert!(environment.get("state_dir").is_none());
    assert!(
        !environment
            .settings()
            .any(|setting| setting.key() == "state_dir")
    );
}

#[test]
fn user_file_provenance_is_relative_and_redacted() {
    // Catches provenance that leaks an absolute temporary root or the configured HOME value.
    let fixture = TestFixture::new();
    let user_value = fixture.state_value("provenance-value");
    fixture.write_user_config(&format!("state_dir = {:?}\n", user_value.to_string_lossy()));

    let environment = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect("user-file configuration resolves");
    let setting = environment.get("state_dir").expect("state_dir is resolved");
    assert_eq!(setting.provenance().source(), ConfigurationSource::UserFile);
    let relative_path = setting
        .provenance()
        .relative_path()
        .expect("user-file provenance has a relative path");
    assert!(!relative_path.is_absolute());
    let debug = format!("{:?}", setting.provenance());
    let root_text = fixture.root.to_string_lossy();
    let home = fixture.home();
    let home_text = home.to_string_lossy();
    assert!(!debug.contains(root_text.as_ref()));
    assert!(!debug.contains(home_text.as_ref()));
}

fn assert_user_config_failure(
    contents: &str,
    expected: ConfigurationFailureCode,
) -> matinee_runtime::ConfigurationFailure {
    let fixture = TestFixture::new();
    fixture.write_user_config(contents);

    let failure = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect_err("the configuration boundary case must be rejected");
    assert_eq!(failure.code(), expected);
    failure
}

fn exact_byte_document(byte_length: usize) -> String {
    let prefix = "state_dir = \"boundary\"\n";
    assert!(byte_length >= prefix.len());
    let mut document = String::with_capacity(byte_length);
    document.push_str(prefix);
    document.push_str(&"#".repeat(byte_length - prefix.len()));
    document
}

#[test]
fn configuration_accepts_exact_file_byte_limit_and_rejects_one_over() {
    const FILE_BYTE_LIMIT: usize = 1_048_576;
    let fixture = TestFixture::new();
    fixture.write_user_config(&exact_byte_document(FILE_BYTE_LIMIT));
    let resolved = resolve_environment(EnvironmentInput::new(fixture.project_root()))
        .expect("a syntactically valid configuration at the byte limit resolves");
    assert_eq!(
        resolved
            .get("state_dir")
            .expect("state_dir is present")
            .value(),
        "boundary"
    );
    drop(fixture);

    let failure = assert_user_config_failure(
        &exact_byte_document(FILE_BYTE_LIMIT + 1),
        ConfigurationFailureCode::FileTooLarge,
    );
    let rendered = failure.to_string();
    assert!(rendered.contains("source: user-configuration-file"));
    assert!(!rendered.contains("source: built-in"));
}

#[test]
fn configuration_accepts_exact_assignment_limit_and_rejects_one_over() {
    const ASSIGNMENT_LIMIT: usize = 100;
    let mut exact = String::with_capacity(ASSIGNMENT_LIMIT * 24);
    for index in 0..ASSIGNMENT_LIMIT {
        writeln!(&mut exact, "unknown_{index} = \"value\"").expect("writing to String cannot fail");
    }
    assert_user_config_failure(&exact, ConfigurationFailureCode::KeyUnknown);

    let mut one_over = String::with_capacity((ASSIGNMENT_LIMIT + 1) * 24);
    for index in 0..=ASSIGNMENT_LIMIT {
        writeln!(&mut one_over, "unknown_{index} = \"value\"")
            .expect("writing to String cannot fail");
    }
    assert_user_config_failure(&one_over, ConfigurationFailureCode::LimitExceeded);
}

#[test]
fn configuration_accepts_exact_key_depth_and_rejects_one_over() {
    assert_user_config_failure(
        "one.two.three.four = \"value\"\n",
        ConfigurationFailureCode::KeyUnknown,
    );
    assert_user_config_failure(
        "one.two.three.four.five = \"value\"\n",
        ConfigurationFailureCode::LimitExceeded,
    );
}

#[test]
fn configuration_accepts_exact_text_length_and_rejects_one_over() {
    const TEXT_SCALAR_LIMIT: usize = 4_096;
    let exact = format!("unknown = \"{}\"\n", "x".repeat(TEXT_SCALAR_LIMIT));
    assert_user_config_failure(&exact, ConfigurationFailureCode::KeyUnknown);

    let one_over = format!("unknown = \"{}\"\n", "x".repeat(TEXT_SCALAR_LIMIT + 1));
    assert_user_config_failure(&one_over, ConfigurationFailureCode::LimitExceeded);
}

#[test]
fn pathological_exact_one_mib_toml_hits_preflight_before_size_gate() {
    const FILE_BYTE_LIMIT: usize = 1_048_576;
    const ASSIGNMENT_LIMIT: usize = 100;
    let mut assignments = String::with_capacity((ASSIGNMENT_LIMIT + 1) * 24);
    for index in 0..=ASSIGNMENT_LIMIT {
        writeln!(&mut assignments, "unknown_{index} = \"value\"")
            .expect("writing to String cannot fail");
    }
    let mut document = assignments;
    document.push_str(&"#".repeat(FILE_BYTE_LIMIT - document.len()));

    assert_eq!(document.len(), FILE_BYTE_LIMIT);
    let failure = assert_user_config_failure(&document, ConfigurationFailureCode::LimitExceeded);
    let rendered = failure.to_string();
    assert!(rendered.contains("config.limit_exceeded"));
    assert!(rendered.contains("source: user-configuration-file"));
    assert!(!rendered.contains("config.file_too_large"));
}
