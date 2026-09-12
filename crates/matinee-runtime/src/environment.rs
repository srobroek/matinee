//! Immutable inputs and redacted projections shared by environment resolution.
//!
//! The resolver is assembled by later runtime nodes. This module owns the
//! values that cross that boundary: source precedence, explicit path inputs,
//! successful provenance, and the closed failure result. Provenance
//! constructors accept only already-redacted relative paths or accepted key
//! names, so a raw absolute path cannot enter a successful diagnostic
//! projection through this API.

#![allow(dead_code)]

use crate::error::{ConfigurationFailure, LayerClass};
use std::path::{Component, Path, PathBuf};

/// The ordered configuration layers used by runtime resolution.
///
/// Declaration order is the precedence order. A larger [`Self::precedence`]
/// value is a higher-precedence source; whether it may replace a lower source
/// remains a descriptor policy owned by configuration resolution.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ConfigurationSource {
    Default,
    UserFile,
    ProjectFile,
    Environment,
    CommandLine,
}

/// The environment-oriented spelling used by callers that do not need the
/// longer configuration name.
pub(crate) type EnvironmentSource = ConfigurationSource;

impl ConfigurationSource {
    /// Returns the stable precedence rank from lowest to highest.
    pub(crate) const fn precedence(self) -> u8 {
        match self {
            Self::Default => 0,
            Self::UserFile => 1,
            Self::ProjectFile => 2,
            Self::Environment => 3,
            Self::CommandLine => 4,
        }
    }

    /// Returns whether this source is higher than the other source.
    pub(crate) const fn is_higher_than(self, other: Self) -> bool {
        self.precedence() > other.precedence()
    }

    /// Returns the contract spelling used in successful provenance.
    pub(crate) const fn as_str(self) -> &'static str {
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

/// A successful source location with only its safe projection retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Provenance {
    BuiltIn,
    UserFile(RelativePath),
    ProjectFile(RelativePath),
    Environment(String),
    CommandLine(String),
}

/// Descriptive alias for callers that use the data-model terminology.
pub(crate) type ConfigurationProvenance = Provenance;

impl Provenance {
    pub(crate) const fn built_in() -> Self {
        Self::BuiltIn
    }

    pub(crate) fn user_file(path: impl Into<PathBuf>) -> Option<Self> {
        RelativePath::new(path).map(Self::UserFile)
    }

    pub(crate) fn project_file(path: impl Into<PathBuf>) -> Option<Self> {
        RelativePath::new(path).map(Self::ProjectFile)
    }

    pub(crate) fn environment(key: impl Into<String>) -> Option<Self> {
        let key = key.into();
        (!key.is_empty()).then_some(Self::Environment(key))
    }

    pub(crate) fn command_line(key: impl Into<String>) -> Option<Self> {
        let key = key.into();
        (!key.is_empty()).then_some(Self::CommandLine(key))
    }

    pub(crate) const fn source(&self) -> ConfigurationSource {
        match self {
            Self::BuiltIn => ConfigurationSource::Default,
            Self::UserFile(_) => ConfigurationSource::UserFile,
            Self::ProjectFile(_) => ConfigurationSource::ProjectFile,
            Self::Environment(_) => ConfigurationSource::Environment,
            Self::CommandLine(_) => ConfigurationSource::CommandLine,
        }
    }

    pub(crate) fn relative_path(&self) -> Option<&Path> {
        match self {
            Self::UserFile(path) | Self::ProjectFile(path) => Some(path.as_path()),
            Self::BuiltIn | Self::Environment(_) | Self::CommandLine(_) => None,
        }
    }

    pub(crate) fn key(&self) -> Option<&str> {
        match self {
            Self::Environment(key) | Self::CommandLine(key) => Some(key),
            Self::BuiltIn | Self::UserFile(_) | Self::ProjectFile(_) => None,
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
pub(crate) struct EnvironmentInput {
    project_root: PathBuf,
    config_path: Option<PathBuf>,
    state_dir: Option<PathBuf>,
}

impl EnvironmentInput {
    pub(crate) fn new(project_root: impl Into<PathBuf>) -> Self {
        Self {
            project_root: project_root.into(),
            config_path: None,
            state_dir: None,
        }
    }

    pub(crate) fn with_config_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_path = Some(path.into());
        self
    }

    pub(crate) fn with_state_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(path.into());
        self
    }

    pub(crate) fn project_root(&self) -> &Path {
        &self.project_root
    }

    pub(crate) fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    pub(crate) fn state_dir(&self) -> Option<&Path> {
        self.state_dir.as_deref()
    }
}

/// All resolver outcomes use the closed failure type; no alternate error
/// channel can leak raw operating-system or parser text.
pub(crate) type EnvironmentResult<T> = Result<T, ConfigurationFailure>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ConfigurationFailure, ConfigurationFailureCode, FailureSource};

    #[test]
    fn source_precedence_is_the_contract_order_and_maps_to_closed_layers() {
        let sources = [
            ConfigurationSource::Default,
            ConfigurationSource::UserFile,
            ConfigurationSource::ProjectFile,
            ConfigurationSource::Environment,
            ConfigurationSource::CommandLine,
        ];

        for pair in sources.windows(2) {
            assert!(pair[1].is_higher_than(pair[0]));
            assert!(pair[1].precedence() > pair[0].precedence());
        }

        assert_eq!(ConfigurationSource::Default.as_str(), "default");
        assert_eq!(
            ConfigurationSource::UserFile.layer_class(),
            LayerClass::UserFile
        );
        assert_eq!(
            ConfigurationSource::ProjectFile.layer_class(),
            LayerClass::ProjectFile
        );
        assert_eq!(
            ConfigurationSource::Environment.layer_class(),
            LayerClass::Environment
        );
        assert_eq!(
            ConfigurationSource::CommandLine.layer_class(),
            LayerClass::CommandLine
        );
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
    fn provenance_rejects_absolute_and_parent_paths_but_keeps_safe_key_origins() {
        assert!(Provenance::user_file("/Users/alice/config.toml").is_none());
        assert!(Provenance::project_file("../outside/config.toml").is_none());

        let user = Provenance::user_file("config.toml").expect("relative path is safe");
        assert_eq!(user.source(), ConfigurationSource::UserFile);
        assert_eq!(user.relative_path(), Some(Path::new("config.toml")));

        let environment = Provenance::environment("MATINEE_LOG_LEVEL").expect("key is present");
        assert_eq!(environment.source(), ConfigurationSource::Environment);
        assert_eq!(environment.key(), Some("MATINEE_LOG_LEVEL"));
        assert!(Provenance::environment("").is_none());
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
}
