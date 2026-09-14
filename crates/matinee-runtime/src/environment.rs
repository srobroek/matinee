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
use crate::error::{
    ConfigurationFailure, ConfigurationFailureCode, FailureSource, LayerClass, RedactedFileOrigin,
};
use crate::platform::{FileIdentity, FileSnapshot, FileType, Platform};
use std::borrow::Borrow;
use std::path::{Component, Path, PathBuf};
use toml::Value as TomlValue;

/// Validate the implicit project configuration file before any read is attempted.
///
/// The selected root identity is supplied by the resolution attempt, rather than
/// rediscovered here. This keeps a root replacement between discovery and validation
/// from making the containment check self-consistent around an attacker-controlled link.
pub(crate) fn validate_implicit_project_file<P: Platform>(
    platform: &P,
    project_root: &Path,
) -> EnvironmentResult<Option<PathBuf>> {
    let root_identity = platform
        .followed_file_identity(project_root)
        .map_err(project_failure)?
        .ok_or_else(project_path_unavailable)?;
    Ok(
        validate_implicit_project_file_at(platform, project_root, root_identity)?
            .map(|validated| validated.path),
    )
}

/// Open and read the implicit project configuration only after validating its
/// containment and no-follow type. The pre-open and opened-handle snapshots are
/// compared before bytes are accepted by the resolver.
pub(crate) fn read_implicit_project_file<P: Platform>(
    platform: &P,
    project_root: &Path,
) -> EnvironmentResult<Option<Vec<u8>>> {
    let root_identity = platform
        .followed_file_identity(project_root)
        .map_err(project_failure)?
        .ok_or_else(project_path_unavailable)?;
    let Some(validated) = validate_implicit_project_file_at(platform, project_root, root_identity)?
    else {
        return Ok(None);
    };
    let read = platform
        .read_file(&validated.path)
        .map_err(project_failure)?;
    if read.snapshot != validated.snapshot {
        return Err(project_file_changed());
    }
    Ok(Some(read.contents))
}

struct ValidatedProjectFile {
    path: PathBuf,
    snapshot: FileSnapshot,
}

fn validate_implicit_project_file_at<P: Platform>(
    platform: &P,
    project_root: &Path,
    root_identity: FileIdentity,
) -> EnvironmentResult<Option<ValidatedProjectFile>> {
    let project_root =
        crate::path_identity::absolute_lexical_normalize(project_root, Path::new("."))
            .map_err(|_| project_path_unavailable())?;
    let project_file = project_root.join("matinee.toml");
    if !lexically_within(&project_root, &project_file) {
        return Err(project_escape());
    }

    let parent_identity = platform
        .followed_file_identity(project_file.parent().unwrap_or(&project_root))
        .map_err(project_failure)?
        .ok_or_else(project_path_unavailable)?;
    if parent_identity != root_identity {
        return Err(project_escape());
    }

    let Some(snapshot) = platform
        .file_snapshot(&project_file)
        .map_err(project_failure)?
    else {
        return Ok(None);
    };
    if snapshot.file_type == FileType::Symlink {
        return Err(project_escape());
    }
    if snapshot.file_type != FileType::Regular {
        return Err(project_unreadable());
    }
    Ok(Some(ValidatedProjectFile {
        path: project_file,
        snapshot,
    }))
}

fn project_failure(failure: ConfigurationFailure) -> ConfigurationFailure {
    ConfigurationFailure::new(
        failure.code(),
        FailureSource::File(RedactedFileOrigin::ProjectConfiguration),
    )
}

fn project_file_changed() -> ConfigurationFailure {
    ConfigurationFailure::new(
        ConfigurationFailureCode::FileChanged,
        FailureSource::File(RedactedFileOrigin::ProjectConfiguration),
    )
}

fn project_path_unavailable() -> ConfigurationFailure {
    ConfigurationFailure::new(
        ConfigurationFailureCode::PathUnavailable,
        FailureSource::File(RedactedFileOrigin::ProjectConfiguration),
    )
}

fn project_escape() -> ConfigurationFailure {
    ConfigurationFailure::new(
        ConfigurationFailureCode::ProjectEscape,
        FailureSource::File(RedactedFileOrigin::ProjectConfiguration),
    )
}

fn project_unreadable() -> ConfigurationFailure {
    ConfigurationFailure::new(
        ConfigurationFailureCode::FileUnreadable,
        FailureSource::File(RedactedFileOrigin::ProjectConfiguration),
    )
}

/// Assemble the supplied configuration layers after applying immutable input overrides.
///
/// This boundary deliberately receives already-loaded layers. It performs only lexical
/// validation and layer selection; filesystem discovery and reads belong to the owning
/// platform-resolution stages. The registry is the sole all-or-failure merge boundary.
pub(crate) fn assemble_configuration<I>(
    input: impl Borrow<EnvironmentInput>,
    registry: &DescriptorRegistry,
    layers: I,
) -> EnvironmentResult<ResolvedConfiguration<'_>>
where
    I: IntoIterator<Item = ConfigurationLayer>,
{
    let input = input.borrow();
    let explicit_config = input.config_path();
    if let Some(config_path) = explicit_config {
        if !lexically_within(input.project_root(), config_path) {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::ProjectEscape,
                FailureSource::File(RedactedFileOrigin::ProjectConfiguration),
            ));
        }
    }

    let state_dir_override = input.state_dir().map(|state_dir| {
        state_dir.to_str().map(str::to_owned).ok_or_else(|| {
            ConfigurationFailure::new(
                ConfigurationFailureCode::ValueInvalid,
                FailureSource::Layer(LayerClass::CommandLine),
            )
        })
    });
    let state_dir_override = state_dir_override.transpose()?;
    let original_layers = layers
        .into_iter()
        .filter(|layer| {
            !(explicit_config.is_some() && layer.source() == ConfigurationSource::ProjectFile)
        })
        .collect::<Vec<_>>();
    let resolved = registry.merge_layers(original_layers)?;

    let Some(state_dir) = state_dir_override else {
        return Ok(resolved);
    };

    // The layer type intentionally keeps entries private. Rebuild the validated winners
    // into equivalent single-entry layers so the original merge can validate every CLI
    // entry, while the replacement below removes only the state_dir winner. This retains
    // unrelated command-line settings and their source/provenance projections.
    let mut effective_layers = resolved
        .settings()
        .filter(|setting| {
            setting.key() != "state_dir"
                && (setting.provenance().source() != ConfigurationSource::Default
                    || setting.descriptor().default().is_none())
        })
        .map(layer_for_resolved_setting)
        .collect::<EnvironmentResult<Vec<_>>>()?;
    effective_layers.push(ConfigurationLayer::command_line([(
        "state_dir".to_owned(),
        TomlValue::String(state_dir),
    )]));

    registry.merge_layers(effective_layers)
}

fn layer_for_resolved_setting(
    setting: &crate::config::ResolvedSetting<'_>,
) -> EnvironmentResult<ConfigurationLayer> {
    let entry = [(setting.key().to_owned(), setting.value().clone())];
    match setting.provenance().source() {
        ConfigurationSource::Default => Ok(ConfigurationLayer::defaults(entry)),
        ConfigurationSource::UserFile => {
            let path = setting.provenance().relative_path().ok_or_else(|| {
                ConfigurationFailure::new(
                    ConfigurationFailureCode::ValueInvalid,
                    FailureSource::Layer(LayerClass::UserFile),
                )
            })?;
            ConfigurationLayer::user_file(path.to_owned(), entry)
        }
        ConfigurationSource::ProjectFile => {
            let path = setting.provenance().relative_path().ok_or_else(|| {
                ConfigurationFailure::new(
                    ConfigurationFailureCode::ValueInvalid,
                    FailureSource::Layer(LayerClass::ProjectFile),
                )
            })?;
            ConfigurationLayer::project_file(path.to_owned(), entry)
        }
        ConfigurationSource::Environment => Ok(ConfigurationLayer::environment(entry)),
        ConfigurationSource::CommandLine => Ok(ConfigurationLayer::command_line(entry)),
    }
}

fn lexically_within(root: &Path, candidate: &Path) -> bool {
    let root = lexical_normalize(root);
    let candidate = if candidate.is_absolute() {
        lexical_normalize(candidate)
    } else {
        lexical_normalize(&root.join(candidate))
    };
    candidate.starts_with(&root)
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let absolute = path.has_root();
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized.file_name().is_some() {
                    normalized.pop();
                } else if !absolute {
                    normalized.push(Component::ParentDir.as_os_str());
                }
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AllowedSources, DescriptorDefault, KeyDescriptor, MaterialClass, ValueKind,
    };
    use crate::error::{ConfigurationFailure, ConfigurationFailureCode, FailureSource};
    use crate::platform::{FileIdentity, FileRead, FileSnapshot, FixturePlatform, PlatformKind};

    fn test_registry(names: &[&str]) -> DescriptorRegistry {
        DescriptorRegistry::new(
            names
                .iter()
                .map(|name| {
                    KeyDescriptor::new(
                        *name,
                        if *name == "state_dir" {
                            ValueKind::Path
                        } else {
                            ValueKind::Text
                        },
                        AllowedSources::all(),
                        MaterialClass::NonSecret,
                    )
                })
                .collect(),
        )
        .expect("test descriptors are valid")
    }

    fn text(value: &str) -> TomlValue {
        TomlValue::String(value.to_owned())
    }

    #[test]
    fn assemble_configuration_uses_explicit_config_to_replace_project_layer() {
        let registry = test_registry(&["setting"]);
        let layers = || {
            vec![
                ConfigurationLayer::user_file(
                    "explicit.toml",
                    vec![("setting".to_owned(), text("explicit"))],
                )
                .unwrap(),
                ConfigurationLayer::project_file(
                    "matinee.toml",
                    vec![("setting".to_owned(), text("implicit"))],
                )
                .unwrap(),
            ]
        };

        let implicit = assemble_configuration(
            EnvironmentInput::new("/workspace/project"),
            &registry,
            layers(),
        )
        .expect("implicit project configuration resolves");
        assert_eq!(implicit.get("setting").unwrap().value(), &text("implicit"));

        let explicit = assemble_configuration(
            EnvironmentInput::new("/workspace/project")
                .with_config_path("/workspace/project/explicit.toml"),
            &registry,
            layers(),
        )
        .expect("explicit configuration resolves");
        assert_eq!(
            explicit.get("setting").unwrap().source(),
            ConfigurationSource::UserFile
        );
    }

    #[test]
    fn assemble_configuration_uses_state_dir_override_as_command_line_layer() {
        let registry = test_registry(&["state_dir"]);
        let layers = vec![
            ConfigurationLayer::user_file(
                "config.toml",
                vec![("state_dir".to_owned(), text("user-state"))],
            )
            .unwrap(),
            ConfigurationLayer::command_line(vec![("state_dir".to_owned(), text("command-state"))]),
        ];

        let resolved = assemble_configuration(
            EnvironmentInput::new("/workspace/project").with_state_dir("/workspace/override"),
            &registry,
            layers,
        )
        .expect("state override resolves");
        let state_dir = resolved.get("state_dir").expect("state_dir is present");
        assert_eq!(state_dir.value(), &text("/workspace/override"));
        assert_eq!(state_dir.source(), ConfigurationSource::CommandLine);
    }

    #[test]
    fn assemble_configuration_preserves_explicit_default_layer_with_state_override() {
        let registry = test_registry(&["setting", "state_dir"]);
        let resolved = assemble_configuration(
            EnvironmentInput::new("/workspace/project").with_state_dir("/workspace/override"),
            &registry,
            [ConfigurationLayer::defaults(vec![(
                "setting".to_owned(),
                text("explicit-default"),
            )])],
        )
        .expect("explicit default layer resolves with state override");

        let setting = resolved
            .get("setting")
            .expect("explicit default setting is present");
        assert_eq!(setting.value(), &text("explicit-default"));
        assert_eq!(setting.source(), ConfigurationSource::Default);
    }

    #[test]
    fn assemble_configuration_preserves_descriptor_owned_default_with_state_override() {
        let registry = DescriptorRegistry::new(vec![
            KeyDescriptor::new(
                "setting",
                ValueKind::Text,
                AllowedSources::all(),
                MaterialClass::NonSecret,
            )
            .with_default(DescriptorDefault::Text("descriptor-default".to_owned())),
            KeyDescriptor::new(
                "state_dir",
                ValueKind::Path,
                AllowedSources::all(),
                MaterialClass::NonSecret,
            ),
        ])
        .expect("test descriptors are valid");
        let resolved = assemble_configuration(
            EnvironmentInput::new("/workspace/project").with_state_dir("/workspace/override"),
            &registry,
            std::iter::empty::<ConfigurationLayer>(),
        )
        .expect("descriptor default resolves with state override");

        let setting = resolved
            .get("setting")
            .expect("descriptor default setting is present");
        assert_eq!(setting.value(), &text("descriptor-default"));
        assert_eq!(setting.source(), ConfigurationSource::Default);
    }

    #[test]
    fn assemble_configuration_preserves_unrelated_command_line_settings() {
        let registry = test_registry(&["setting", "state_dir"]);
        let resolved = assemble_configuration(
            EnvironmentInput::new("/workspace/project").with_state_dir("/workspace/override"),
            &registry,
            [ConfigurationLayer::command_line(vec![
                ("setting".to_owned(), text("command-line")),
                ("state_dir".to_owned(), text("stale-state")),
            ])],
        )
        .expect("state override preserves unrelated command-line settings");

        let setting = resolved.get("setting").expect("setting is present");
        assert_eq!(setting.value(), &text("command-line"));
        assert_eq!(setting.source(), ConfigurationSource::CommandLine);
        assert_eq!(
            resolved.get("state_dir").unwrap().value(),
            &text("/workspace/override")
        );
    }

    #[test]
    fn assemble_configuration_still_validates_unrelated_command_line_entries() {
        let cases = [
            (
                vec![("unknown".to_owned(), text("rejected"))],
                ConfigurationFailureCode::KeyUnknown,
            ),
            (
                vec![("setting".to_owned(), TomlValue::Integer(7))],
                ConfigurationFailureCode::ValueInvalid,
            ),
        ];

        for (entry, code) in cases {
            let registry = test_registry(&["setting", "state_dir"]);
            let failure = assemble_configuration(
                EnvironmentInput::new("/workspace/project").with_state_dir("/workspace/override"),
                &registry,
                [ConfigurationLayer::command_line(entry)],
            )
            .expect_err("invalid command-line entries must not be suppressed");
            assert_eq!(failure.code(), code);
        }
    }

    #[test]
    fn assemble_configuration_uses_project_root_for_config_containment() {
        let registry = test_registry(&["setting"]);
        let failure = assemble_configuration(
            EnvironmentInput::new("/workspace/project")
                .with_config_path("/workspace/project/../outside.toml"),
            &registry,
            std::iter::empty(),
        )
        .expect_err("configuration outside the project root is rejected");
        assert_eq!(
            failure.source(),
            FailureSource::File(RedactedFileOrigin::ProjectConfiguration)
        );
    }

    #[test]
    fn assemble_configuration_is_all_or_failure_without_partial_result() {
        let registry = test_registry(&["known"]);
        let result = assemble_configuration(
            EnvironmentInput::new("/workspace/project"),
            &registry,
            [ConfigurationLayer::environment(vec![
                ("known".to_owned(), text("accepted")),
                ("unregistered".to_owned(), text("rejected")),
            ])],
        );
        let failure = result.expect_err("unknown input rejects the complete result");
        assert_eq!(failure.code(), ConfigurationFailureCode::KeyUnknown);
        assert!(!failure.to_string().contains("unregistered"));
    }

    #[test]
    fn assemble_configuration_preserves_closed_four_field_failure_projection() {
        let raw_path = "/workspace/project/../outside-config.toml";
        let registry = test_registry(&["setting"]);
        let failure = assemble_configuration(
            EnvironmentInput::new("/workspace/project").with_config_path(raw_path),
            &registry,
            std::iter::empty(),
        )
        .expect_err("escaped configuration path is rejected");
        assert_eq!(
            failure.summary(),
            "project configuration is outside the project root"
        );

        assert_eq!(
            failure.source(),
            FailureSource::File(RedactedFileOrigin::ProjectConfiguration)
        );
        assert_eq!(
            failure.next_action(),
            "Select a project configuration inside the project root."
        );
        assert!(!failure.to_string().contains(raw_path));
    }

    #[test]
    fn assemble_configuration_does_not_mutate_filesystem() {
        let sentinel =
            std::env::temp_dir().join(format!("matinee-assembly-sentinel-{}", std::process::id()));
        assert!(!sentinel.exists(), "sentinel must start absent");
        let registry = test_registry(&[]);
        let result = assemble_configuration(
            EnvironmentInput::new(&sentinel),
            &registry,
            std::iter::empty(),
        )
        .expect("empty configuration resolves without filesystem access");
        assert!(result.is_empty());
        assert!(!sentinel.exists(), "assembly must not create the sentinel");
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

    fn project_fixture() -> (FixturePlatform, FileIdentity) {
        let root = FileIdentity {
            volume: 1,
            file: 10,
        };
        (
            FixturePlatform::new(PlatformKind::Linux)
                .with_snapshot("/fixture/project", FileSnapshot::directory(root, Some(1)))
                .with_followed_file_identity("/fixture/project", root),
            root,
        )
    }

    #[test]
    fn implicit_project_read_accepts_regular_file_after_validation() {
        let (platform, _) = project_fixture();
        let platform = platform.with_file(
            "/fixture/project/matinee.toml",
            FileIdentity {
                volume: 1,
                file: 11,
            },
            b"[project]\n",
            Some(2),
        );
        assert_eq!(
            read_implicit_project_file(&platform, Path::new("/fixture/project"))
                .expect("regular project file reads")
                .as_deref(),
            Some(&b"[project]\n"[..])
        );
    }

    #[test]
    fn implicit_project_read_allows_missing_file_but_rejects_link_and_nonregular() {
        let (platform, _) = project_fixture();
        assert_eq!(
            read_implicit_project_file(&platform, Path::new("/fixture/project"))
                .expect("missing project file is optional"),
            None
        );

        let (platform, _) = project_fixture();
        let symlink = platform.with_snapshot(
            "/fixture/project/matinee.toml",
            FileSnapshot::symlink(
                FileIdentity {
                    volume: 1,
                    file: 11,
                },
                Some(2),
            ),
        );
        assert_eq!(
            read_implicit_project_file(&symlink, Path::new("/fixture/project"))
                .expect_err("symlink project file is rejected")
                .code(),
            ConfigurationFailureCode::ProjectEscape
        );

        let (platform, _) = project_fixture();
        let directory = platform.with_snapshot(
            "/fixture/project/matinee.toml",
            FileSnapshot::directory(
                FileIdentity {
                    volume: 1,
                    file: 11,
                },
                Some(2),
            ),
        );
        assert_eq!(
            read_implicit_project_file(&directory, Path::new("/fixture/project"))
                .expect_err("non-regular project file is rejected")
                .code(),
            ConfigurationFailureCode::FileUnreadable
        );
    }

    #[test]
    fn implicit_project_read_rejects_escape_replacement_and_remaps_platform_failures() {
        let platform = FixturePlatform::new(PlatformKind::Linux);
        let failure = read_implicit_project_file(&platform, Path::new("/fixture/project"))
            .expect_err("missing project root is unavailable");
        assert_eq!(failure.code(), ConfigurationFailureCode::PathUnavailable);
        assert_eq!(
            failure.source(),
            FailureSource::File(RedactedFileOrigin::ProjectConfiguration)
        );

        let (platform, _) = project_fixture();
        let before = FileSnapshot::regular(
            FileIdentity {
                volume: 1,
                file: 11,
            },
            5,
            Some(2),
        );
        let after = FileSnapshot::regular(
            FileIdentity {
                volume: 1,
                file: 12,
            },
            5,
            Some(3),
        );
        let replaced = platform
            .with_snapshot_results("/fixture/project/matinee.toml", [Ok(Some(before))])
            .with_read_results(
                "/fixture/project/matinee.toml",
                [Ok(FileRead {
                    snapshot: after,
                    contents: b"hello".to_vec(),
                })],
            );
        assert_eq!(
            read_implicit_project_file(&replaced, Path::new("/fixture/project"))
                .expect_err("replacement during read is rejected")
                .code(),
            ConfigurationFailureCode::FileChanged
        );
    }
}
