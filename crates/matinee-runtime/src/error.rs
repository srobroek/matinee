//! Closed, safe diagnostics for configuration-resolution failures.
//!
//! The public projection intentionally has no text-bearing input. Callers map raw
//! operating-system and parser errors to [`ConfigurationFailureCode`] at their
//! boundary, then provide only the closed [`FailureSource`] projection.

#![allow(dead_code)]

use core::fmt;

/// The complete set of configuration failures defined by the runtime contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationFailureCode {
    FileUnreadable,
    FileChanged,
    FileTooLarge,
    SyntaxInvalid,
    KeyDuplicate,
    KeyUnknown,
    SourceForbidden,
    ValueInvalid,
    SecretForbidden,
    LimitExceeded,
    ProjectEscape,
    PathUnavailable,
}

impl ConfigurationFailureCode {
    /// Returns the stable wire name for this closed code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileUnreadable => "config.file_unreadable",
            Self::FileChanged => "config.file_changed",
            Self::FileTooLarge => "config.file_too_large",
            Self::SyntaxInvalid => "config.syntax_invalid",
            Self::KeyDuplicate => "config.key_duplicate",
            Self::KeyUnknown => "config.key_unknown",
            Self::SourceForbidden => "config.source_forbidden",
            Self::ValueInvalid => "config.value_invalid",
            Self::SecretForbidden => "config.secret_forbidden",
            Self::LimitExceeded => "config.limit_exceeded",
            Self::ProjectEscape => "config.project_escape",
            Self::PathUnavailable => "config.path_unavailable",
        }
    }
}

/// A fixed source layer used when no file-origin projection is needed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayerClass {
    BuiltIn,
    UserFile,
    ProjectFile,
    Environment,
    CommandLine,
}

impl LayerClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BuiltIn => "built-in",
            Self::UserFile => "user-file",
            Self::ProjectFile => "project-file",
            Self::Environment => "environment",
            Self::CommandLine => "command-line",
        }
    }
}

/// A file origin with its path deliberately removed from the failure projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactedFileOrigin {
    UserConfiguration,
    ProjectConfiguration,
}

impl RedactedFileOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserConfiguration => "user-configuration-file",
            Self::ProjectConfiguration => "project-configuration-file",
        }
    }
}

/// The only source values that can be carried by a configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureSource {
    Layer(LayerClass),
    File(RedactedFileOrigin),
}

impl FailureSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Layer(layer) => layer.as_str(),
            Self::File(origin) => origin.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafeSummary {
    FileUnreadable,
    FileChanged,
    FileTooLarge,
    SyntaxInvalid,
    KeyDuplicate,
    KeyUnknown,
    SourceForbidden,
    ValueInvalid,
    SecretForbidden,
    LimitExceeded,
    ProjectEscape,
    PathUnavailable,
}

impl SafeSummary {
    pub const fn for_code(code: ConfigurationFailureCode) -> Self {
        match code {
            ConfigurationFailureCode::FileUnreadable => Self::FileUnreadable,
            ConfigurationFailureCode::FileChanged => Self::FileChanged,
            ConfigurationFailureCode::FileTooLarge => Self::FileTooLarge,
            ConfigurationFailureCode::SyntaxInvalid => Self::SyntaxInvalid,
            ConfigurationFailureCode::KeyDuplicate => Self::KeyDuplicate,
            ConfigurationFailureCode::KeyUnknown => Self::KeyUnknown,
            ConfigurationFailureCode::SourceForbidden => Self::SourceForbidden,
            ConfigurationFailureCode::ValueInvalid => Self::ValueInvalid,
            ConfigurationFailureCode::SecretForbidden => Self::SecretForbidden,
            ConfigurationFailureCode::LimitExceeded => Self::LimitExceeded,
            ConfigurationFailureCode::ProjectEscape => Self::ProjectEscape,
            ConfigurationFailureCode::PathUnavailable => Self::PathUnavailable,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileUnreadable => "configuration file cannot be read",
            Self::FileChanged => "configuration file changed while being read",
            Self::FileTooLarge => "configuration file exceeds the size limit",
            Self::SyntaxInvalid => "configuration syntax is invalid",
            Self::KeyDuplicate => "configuration key is duplicated",
            Self::KeyUnknown => "configuration key is unknown",
            Self::SourceForbidden => "configuration source is not allowed",
            Self::ValueInvalid => "configuration value is invalid",
            Self::SecretForbidden => "configuration contains forbidden secret material",
            Self::LimitExceeded => "configuration limit exceeded",
            Self::ProjectEscape => "project configuration is outside the project root",
            Self::PathUnavailable => "required configuration path is unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafeNextAction {
    CheckFile,
    RetryStableFile,
    ReduceFile,
    FixSyntax,
    RemoveDuplicate,
    RemoveUnknown,
    UseAllowedSource,
    FixValue,
    RemoveSecret,
    ReduceConfiguration,
    SelectProjectFileInsideRoot,
    CheckPlatformPaths,
}

impl SafeNextAction {
    pub const fn for_code(code: ConfigurationFailureCode) -> Self {
        match code {
            ConfigurationFailureCode::FileUnreadable => Self::CheckFile,
            ConfigurationFailureCode::FileChanged => Self::RetryStableFile,
            ConfigurationFailureCode::FileTooLarge => Self::ReduceFile,
            ConfigurationFailureCode::SyntaxInvalid => Self::FixSyntax,
            ConfigurationFailureCode::KeyDuplicate => Self::RemoveDuplicate,
            ConfigurationFailureCode::KeyUnknown => Self::RemoveUnknown,
            ConfigurationFailureCode::SourceForbidden => Self::UseAllowedSource,
            ConfigurationFailureCode::ValueInvalid => Self::FixValue,
            ConfigurationFailureCode::SecretForbidden => Self::RemoveSecret,
            ConfigurationFailureCode::LimitExceeded => Self::ReduceConfiguration,
            ConfigurationFailureCode::ProjectEscape => Self::SelectProjectFileInsideRoot,
            ConfigurationFailureCode::PathUnavailable => Self::CheckPlatformPaths,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CheckFile => "Check the configuration file and its permissions.",
            Self::RetryStableFile => "Retry after ensuring the configuration file is stable.",
            Self::ReduceFile => "Reduce the configuration file below its size limit.",
            Self::FixSyntax => "Fix the configuration syntax.",
            Self::RemoveDuplicate => "Remove duplicate configuration keys.",
            Self::RemoveUnknown => "Remove unknown configuration keys.",
            Self::UseAllowedSource => "Set the value from an allowed configuration source.",
            Self::FixValue => "Fix the configuration value.",
            Self::RemoveSecret => "Remove secret material from configuration.",
            Self::ReduceConfiguration => "Reduce the configuration to stay within its limits.",
            Self::SelectProjectFileInsideRoot => {
                "Select a project configuration inside the project root."
            }
            Self::CheckPlatformPaths => "Check the platform configuration paths.",
        }
    }
}

/// A configuration failure with exactly four safe diagnostic projections.
///
/// The fields are private and can only be populated by [`Self::new`], whose
/// signature accepts a closed code and a closed source. Summaries and next
/// actions are selected by that code and contain no caller-provided text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationFailure {
    code: ConfigurationFailureCode,
    summary: SafeSummary,
    source: FailureSource,
    next_action: SafeNextAction,
}

impl ConfigurationFailure {
    /// Maps a boundary-level failure code and source into its safe projection.
    ///
    /// Raw errors, paths, values, excerpts, and secret material are intentionally
    /// absent from this signature and therefore cannot be retained by the type.
    pub(crate) const fn new(code: ConfigurationFailureCode, source: FailureSource) -> Self {
        Self {
            code,
            summary: SafeSummary::for_code(code),
            source,
            next_action: SafeNextAction::for_code(code),
        }
    }

    /// Constructs the unknown-key failure without accepting the rejected key.
    pub(crate) const fn unknown_key(source: FailureSource) -> Self {
        Self::new(ConfigurationFailureCode::KeyUnknown, source)
    }

    pub const fn code(self) -> ConfigurationFailureCode {
        self.code
    }

    pub const fn summary(self) -> &'static str {
        self.summary.as_str()
    }

    pub(crate) const fn source(self) -> FailureSource {
        self.source
    }

    pub const fn next_action(self) -> &'static str {
        self.next_action.as_str()
    }
}

impl fmt::Display for ConfigurationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {} (source: {}; next action: {})",
            self.code.as_str(),
            self.summary.as_str(),
            self.source.as_str(),
            self.next_action.as_str(),
        )
    }
}

impl std::error::Error for ConfigurationFailure {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_failure_code_projects_only_static_safe_fields() {
        let cases = [
            (
                ConfigurationFailureCode::FileUnreadable,
                "config.file_unreadable",
                "configuration file cannot be read",
                "Check the configuration file and its permissions.",
            ),
            (
                ConfigurationFailureCode::FileChanged,
                "config.file_changed",
                "configuration file changed while being read",
                "Retry after ensuring the configuration file is stable.",
            ),
            (
                ConfigurationFailureCode::FileTooLarge,
                "config.file_too_large",
                "configuration file exceeds the size limit",
                "Reduce the configuration file below its size limit.",
            ),
            (
                ConfigurationFailureCode::SyntaxInvalid,
                "config.syntax_invalid",
                "configuration syntax is invalid",
                "Fix the configuration syntax.",
            ),
            (
                ConfigurationFailureCode::KeyDuplicate,
                "config.key_duplicate",
                "configuration key is duplicated",
                "Remove duplicate configuration keys.",
            ),
            (
                ConfigurationFailureCode::KeyUnknown,
                "config.key_unknown",
                "configuration key is unknown",
                "Remove unknown configuration keys.",
            ),
            (
                ConfigurationFailureCode::SourceForbidden,
                "config.source_forbidden",
                "configuration source is not allowed",
                "Set the value from an allowed configuration source.",
            ),
            (
                ConfigurationFailureCode::ValueInvalid,
                "config.value_invalid",
                "configuration value is invalid",
                "Fix the configuration value.",
            ),
            (
                ConfigurationFailureCode::SecretForbidden,
                "config.secret_forbidden",
                "configuration contains forbidden secret material",
                "Remove secret material from configuration.",
            ),
            (
                ConfigurationFailureCode::LimitExceeded,
                "config.limit_exceeded",
                "configuration limit exceeded",
                "Reduce the configuration to stay within its limits.",
            ),
            (
                ConfigurationFailureCode::ProjectEscape,
                "config.project_escape",
                "project configuration is outside the project root",
                "Select a project configuration inside the project root.",
            ),
            (
                ConfigurationFailureCode::PathUnavailable,
                "config.path_unavailable",
                "required configuration path is unavailable",
                "Check the platform configuration paths.",
            ),
        ];

        assert_eq!(cases.len(), 12);
        for (code, expected_code, expected_summary, expected_action) in cases {
            let failure =
                ConfigurationFailure::new(code, FailureSource::Layer(LayerClass::UserFile));

            assert_eq!(failure.code(), code);
            assert_eq!(failure.code().as_str(), expected_code);
            assert_eq!(failure.summary(), expected_summary);
            assert_eq!(failure.source(), FailureSource::Layer(LayerClass::UserFile));
            assert_eq!(failure.source().as_str(), "user-file");
            assert_eq!(failure.next_action(), expected_action);
            assert!(!failure.to_string().is_empty());
        }
    }

    #[test]
    fn file_origin_is_redacted_to_a_closed_safe_projection() {
        let failure = ConfigurationFailure::new(
            ConfigurationFailureCode::FileUnreadable,
            FailureSource::File(RedactedFileOrigin::UserConfiguration),
        );

        assert_eq!(failure.source().as_str(), "user-configuration-file");
        assert_eq!(
            failure.source(),
            FailureSource::File(RedactedFileOrigin::UserConfiguration)
        );
    }

    #[test]
    fn unknown_key_does_not_enter_rendered_fields() {
        let rejected_key = "credentials.api_token";
        let map_unknown_key = |_key: &str| {
            ConfigurationFailure::unknown_key(FailureSource::Layer(LayerClass::Environment))
        };
        let failure = map_unknown_key(rejected_key);
        let rendered = format!(
            "{}|{}|{}|{}",
            failure.code().as_str(),
            failure.summary(),
            failure.source().as_str(),
            failure.next_action(),
        );

        assert_eq!(failure.code(), ConfigurationFailureCode::KeyUnknown);
        assert!(!rendered.contains(rejected_key));
        assert!(!rendered.contains("caller-supplied"));
        assert_eq!(failure.source().as_str(), "environment");
    }
}
