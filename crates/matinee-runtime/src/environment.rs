//! Immutable inputs and redacted projections shared by environment resolution.
//!
//! The resolver is assembled by later runtime nodes. This module owns the
//! values that cross that boundary: source precedence, explicit path inputs,
//! successful provenance, and the closed failure result. Provenance
//! constructors accept only already-redacted relative paths or accepted key
//! names, so a raw absolute path cannot enter a successful diagnostic
//! projection through this API.

#![allow(dead_code)]

use crate::config::{ConfigurationLayer, DescriptorRegistry, ResolvedConfiguration};
use crate::error::{ConfigurationFailure, LayerClass};
use std::path::{Component, Path, PathBuf};

/// The configuration layers with an explicit, stable precedence rank.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationSource {
    Default,
    UserFile,
    ProjectFile,
    Environment,
    CommandLine,
}

impl ConfigurationSource {
    /// Returns the stable precedence rank from lowest to highest.
    pub const fn precedence(self) -> u8 {
        match self {
            Self::Default => 0,
            Self::UserFile => 1,
            Self::ProjectFile => 2,
            Self::Environment => 3,
            Self::CommandLine => 4,
        }
    }

    /// Returns whether this source is higher than the other source.
    pub const fn is_higher_than(self, other: Self) -> bool {
        self.precedence() > other.precedence()
    }

    /// Returns the contract spelling used in successful provenance.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::UserFile => "user_file",
            Self::ProjectFile => "project_file",
            Self::Environment => "environment",
            Self::CommandLine => "command_line",
        }
    }

    /// Converts a successful source into the closed failure-source layer.
    pub(crate) const fn layer_class(self) -> LayerClass {
        match self {
            Self::Default => LayerClass::BuiltIn,
            Self::UserFile => LayerClass::UserFile,
            Self::ProjectFile => LayerClass::ProjectFile,
            Self::Environment => LayerClass::Environment,
            Self::CommandLine => LayerClass::CommandLine,
        }
    }
}

/// An explicit, already-redacted path relative to a trusted root.
///
/// Absolute paths and parent traversal are rejected at construction. Keeping
/// the path opaque prevents callers from accidentally putting a raw user or
/// project root into [`Provenance`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RelativePath(PathBuf);

impl RelativePath {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Option<Self> {
        let path = path.into();
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
        {
            return None;
        }
        Some(Self(path))
    }

    pub(crate) fn as_path(&self) -> &Path {
        &self.0
    }
}

/// An opaque, redaction-safe key projection for provenance.
///
/// Descriptor lookup and acceptance belong to configuration resolution. This
/// boundary only prevents raw paths, values, and control syntax from entering
/// a successful provenance projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcceptedKey(String);

const MAX_ACCEPTED_KEY_LENGTH: usize = 255;

impl AcceptedKey {
    pub(crate) fn new(candidate: impl Into<String>) -> Option<Self> {
        let candidate = candidate.into();
        let safe = !candidate.is_empty()
            && !candidate.starts_with('-')
            && candidate.chars().count() <= MAX_ACCEPTED_KEY_LENGTH
            && !candidate.chars().any(|character| {
                character == '/'
                    || character == '\\'
                    || character == '='
                    || character.is_whitespace()
                    || character.is_control()
            });

        safe.then_some(Self(candidate))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// A private successful source payload retained behind the public projection.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ProvenanceKind {
    BuiltIn,
    UserFile(RelativePath),
    ProjectFile(RelativePath),
    Environment(AcceptedKey),
    CommandLine(AcceptedKey),
}

/// A successful source location with only its safe projection retained.
#[derive(Clone, Eq, PartialEq)]
pub struct Provenance(ProvenanceKind);

impl std::fmt::Debug for Provenance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("Provenance");
        debug.field("source", &self.source().as_str());
        if let Some(path) = self.relative_path() {
            debug.field("origin", &path);
        } else if let Some(key) = self.key() {
            debug.field("origin", &key);
        }
        debug.finish()
    }
}

impl Provenance {
    pub(crate) const fn built_in() -> Self {
        Self(ProvenanceKind::BuiltIn)
    }

    pub(crate) fn user_file(path: impl Into<PathBuf>) -> Option<Self> {
        RelativePath::new(path).map(|path| Self(ProvenanceKind::UserFile(path)))
    }

    pub(crate) fn project_file(path: impl Into<PathBuf>) -> Option<Self> {
        RelativePath::new(path).map(|path| Self(ProvenanceKind::ProjectFile(path)))
    }

    pub(crate) fn environment(key: AcceptedKey) -> Option<Self> {
        Some(Self(ProvenanceKind::Environment(key)))
    }

    pub(crate) fn command_line(key: AcceptedKey) -> Option<Self> {
        Some(Self(ProvenanceKind::CommandLine(key)))
    }

    pub const fn source(&self) -> ConfigurationSource {
        match &self.0 {
            ProvenanceKind::BuiltIn => ConfigurationSource::Default,
            ProvenanceKind::UserFile(_) => ConfigurationSource::UserFile,
            ProvenanceKind::ProjectFile(_) => ConfigurationSource::ProjectFile,
            ProvenanceKind::Environment(_) => ConfigurationSource::Environment,
            ProvenanceKind::CommandLine(_) => ConfigurationSource::CommandLine,
        }
    }

    pub fn relative_path(&self) -> Option<&Path> {
        match &self.0 {
            ProvenanceKind::UserFile(path) | ProvenanceKind::ProjectFile(path) => {
                Some(path.as_path())
            }
            ProvenanceKind::BuiltIn
            | ProvenanceKind::Environment(_)
            | ProvenanceKind::CommandLine(_) => None,
        }
    }

    pub fn key(&self) -> Option<&str> {
        match &self.0 {
            ProvenanceKind::Environment(key) | ProvenanceKind::CommandLine(key) => {
                Some(key.as_str())
            }
            ProvenanceKind::BuiltIn
            | ProvenanceKind::UserFile(_)
            | ProvenanceKind::ProjectFile(_) => None,
        }
    }
}

/// Inputs captured once at the beginning of an environment-resolution attempt.
///
/// The project root is explicit; Matinee never searches parent directories.
/// `config_path` and `state_dir` model the explicit overrides described by the
/// contract. Resolution owns normalizing and validating these paths without
/// mutating the filesystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentInput {
    project_root: PathBuf,
    config_path: Option<PathBuf>,
    state_dir: Option<PathBuf>,
}

impl EnvironmentInput {
    pub fn new(project_root: impl Into<PathBuf>) -> Self {
        Self {
            project_root: project_root.into(),
            config_path: None,
            state_dir: None,
        }
    }

    pub fn with_config_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_path = Some(path.into());
        self
    }

    pub fn with_state_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(path.into());
        self
    }

    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    pub fn state_dir(&self) -> Option<&Path> {
        self.state_dir.as_deref()
    }
}

/// All resolver outcomes use the closed failure type; no alternate error
/// channel can leak raw operating-system or parser text.
pub type EnvironmentResult<T> = Result<T, ConfigurationFailure>;

/// Validates and assembles the supplied layers into one complete configuration.
///
/// The input is captured for the resolution attempt but is deliberately not read or
/// normalized here. This stage only delegates the immutable layer merge, so a failure
/// cannot expose a partially assembled configuration or mutate product state.
pub(crate) fn assemble_configuration<'a>(
    _input: &EnvironmentInput,
    registry: &'a DescriptorRegistry,
    layers: impl IntoIterator<Item = ConfigurationLayer>,
) -> EnvironmentResult<ResolvedConfiguration<'a>> {
    registry.merge_layers(layers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigurationLayer;
    use crate::config::DescriptorRegistry;
    use crate::error::{ConfigurationFailure, ConfigurationFailureCode, FailureSource};
    use toml::Value as TomlValue;

    fn test_input(path: &std::path::Path) -> EnvironmentInput {
        EnvironmentInput::new(path)
            .with_config_path(path)
            .with_state_dir(path)
    }

    fn unknown_environment_layer() -> ConfigurationLayer {
        ConfigurationLayer::environment(vec![(
            "not_registered".to_owned(),
            TomlValue::String("discarded".to_owned()),
        )])
    }

    #[test]
    fn source_precedence_is_explicit_for_every_contract_source() {
        let cases = [
            (
                ConfigurationSource::Default,
                0,
                "default",
                LayerClass::BuiltIn,
            ),
            (
                ConfigurationSource::UserFile,
                1,
                "user_file",
                LayerClass::UserFile,
            ),
            (
                ConfigurationSource::ProjectFile,
                2,
                "project_file",
                LayerClass::ProjectFile,
            ),
            (
                ConfigurationSource::Environment,
                3,
                "environment",
                LayerClass::Environment,
            ),
            (
                ConfigurationSource::CommandLine,
                4,
                "command_line",
                LayerClass::CommandLine,
            ),
        ];

        for (source, rank, spelling, layer) in cases {
            assert_eq!(source.precedence(), rank, "rank for {spelling}");
            assert_eq!(source.as_str(), spelling, "spelling for rank {rank}");
            assert_eq!(source.layer_class(), layer, "layer for {spelling}");
        }

        for pair in cases.windows(2) {
            assert!(pair[1].0.is_higher_than(pair[0].0));
            assert!(pair[1].0.precedence() > pair[0].0.precedence());
        }
    }

    #[test]
    fn input_captures_explicit_paths_without_normalizing_or_mutating_them() {
        let input = EnvironmentInput::new("workspace/./project")
            .with_config_path("config/../config.toml")
            .with_state_dir("state-root");

        assert_eq!(input.project_root(), Path::new("workspace/./project"));
        assert_eq!(
            input.config_path(),
            Some(Path::new("config/../config.toml"))
        );
        assert_eq!(input.state_dir(), Some(Path::new("state-root")));
    }

    #[test]
    fn accepted_key_rejects_raw_paths_values_and_unsafe_text() {
        let rejected = [
            "",
            "/Users/alice/private",
            r"C:\\Users\\alice\\private",
            "--token=secret",
            "key=value",
            "key name",
            "key\tname",
            "key\u{7f}name",
            "-token",
        ];

        for candidate in rejected {
            assert!(
                AcceptedKey::new(candidate).is_none(),
                "accepted {candidate:?}"
            );
        }

        assert!(AcceptedKey::new("MATINEE_LOG_LEVEL").is_some());
        assert!(AcceptedKey::new("a".repeat(MAX_ACCEPTED_KEY_LENGTH)).is_some());
        assert!(AcceptedKey::new("a".repeat(MAX_ACCEPTED_KEY_LENGTH + 1)).is_none());
    }

    #[test]
    fn provenance_rejects_unsafe_paths_and_maps_each_safe_origin() {
        assert!(Provenance::user_file("/Users/alice/config.toml").is_none());
        assert!(Provenance::project_file("../outside/config.toml").is_none());

        let built_in = Provenance::built_in();
        assert_eq!(built_in.source(), ConfigurationSource::Default);
        assert_eq!(built_in.relative_path(), None);
        assert_eq!(built_in.key(), None);

        let user = Provenance::user_file("config.toml").expect("relative path is safe");
        assert_eq!(user.source(), ConfigurationSource::UserFile);
        assert_eq!(user.relative_path(), Some(Path::new("config.toml")));
        assert_eq!(user.key(), None);

        let project = Provenance::project_file("project.toml").expect("relative path is safe");
        assert_eq!(project.source(), ConfigurationSource::ProjectFile);
        assert_eq!(project.relative_path(), Some(Path::new("project.toml")));
        assert_eq!(project.key(), None);

        let environment_key = AcceptedKey::new("MATINEE_LOG_LEVEL").expect("key is safe");
        let environment = Provenance::environment(environment_key).expect("key is present");
        assert_eq!(environment.source(), ConfigurationSource::Environment);
        assert_eq!(environment.relative_path(), None);
        assert_eq!(environment.key(), Some("MATINEE_LOG_LEVEL"));

        let command_key = AcceptedKey::new("MATINEE_PROFILE").expect("key is safe");
        let command_line = Provenance::command_line(command_key).expect("key is present");
        assert_eq!(command_line.source(), ConfigurationSource::CommandLine);
        assert_eq!(command_line.relative_path(), None);
        assert_eq!(command_line.key(), Some("MATINEE_PROFILE"));
    }

    #[test]
    fn result_uses_the_closed_configuration_failure_type() {
        let failure = ConfigurationFailure::new(
            ConfigurationFailureCode::PathUnavailable,
            FailureSource::Layer(LayerClass::BuiltIn),
        );
        let result: EnvironmentResult<()> = Err(failure);
        let actual = match result {
            Err(failure) => failure,
            Ok(()) => panic!("failure expected"),
        };
        assert_eq!(actual.code(), ConfigurationFailureCode::PathUnavailable);
    }

    #[test]
    fn assemble_configuration_is_all_or_failure_without_partial_result() {
        let registry = DescriptorRegistry::production();
        let user = ConfigurationLayer::user_file(
            "config.toml",
            vec![(
                "state_dir".to_owned(),
                TomlValue::String("state".to_owned()),
            )],
        )
        .expect("relative user origin is safe");
        let input = EnvironmentInput::new("project");

        let result = assemble_configuration(&input, &registry, [user, unknown_environment_layer()]);
        let failure = result.expect_err("a failing layer must not produce a configuration");

        assert_eq!(failure.code(), ConfigurationFailureCode::KeyUnknown);
        assert_eq!(
            failure.source(),
            FailureSource::Layer(LayerClass::Environment)
        );
    }

    #[test]
    fn assemble_configuration_does_not_mutate_filesystem() {
        let sentinel = std::env::temp_dir().join(format!(
            "matinee-environment-assembly-{}-sentinel",
            std::process::id()
        ));
        assert!(!sentinel.exists(), "sentinel must start absent");

        let registry = DescriptorRegistry::production();
        let user = ConfigurationLayer::user_file(
            "config.toml",
            vec![(
                "state_dir".to_owned(),
                TomlValue::String("state".to_owned()),
            )],
        )
        .expect("relative user origin is safe");
        let result = assemble_configuration(&test_input(&sentinel), &registry, [user]);
        let configuration = result.expect("valid layers should assemble");

        assert_eq!(
            configuration
                .get("state_dir")
                .expect("setting is resolved")
                .value(),
            &TomlValue::String("state".to_owned())
        );
        assert!(!sentinel.exists(), "assembly must not create the sentinel");
    }

    #[test]
    fn assemble_configuration_preserves_closed_four_field_failure_projection() {
        let registry = DescriptorRegistry::production();
        let failure = assemble_configuration(
            &EnvironmentInput::new("project"),
            &registry,
            [unknown_environment_layer()],
        )
        .expect_err("unknown keys are rejected");

        assert_eq!(failure.code(), ConfigurationFailureCode::KeyUnknown);
        assert_eq!(failure.summary(), "configuration key is unknown");
        assert_eq!(failure.source().as_str(), "environment");
        assert_eq!(failure.next_action(), "Remove unknown configuration keys.");
    }

    #[test]
    fn provenance_debug_projects_source_and_origin_without_internal_types() {
        let cases = [
            (
                Provenance::built_in(),
                r#"Provenance { source: "default" }"#,
            ),
            (
                Provenance::user_file("user.toml").expect("relative path is safe"),
                r#"Provenance { source: "user_file", origin: "user.toml" }"#,
            ),
            (
                Provenance::project_file("config.toml").expect("relative path is safe"),
                r#"Provenance { source: "project_file", origin: "config.toml" }"#,
            ),
            (
                Provenance::environment(
                    AcceptedKey::new("MATINEE_LOG_LEVEL").expect("key is safe"),
                )
                .expect("key is present"),
                r#"Provenance { source: "environment", origin: "MATINEE_LOG_LEVEL" }"#,
            ),
            (
                Provenance::command_line(AcceptedKey::new("MATINEE_PROFILE").expect("key is safe"))
                    .expect("key is present"),
                r#"Provenance { source: "command_line", origin: "MATINEE_PROFILE" }"#,
            ),
        ];

        for (provenance, expected) in cases {
            assert_eq!(format!("{provenance:?}"), expected);
        }
    }
}
