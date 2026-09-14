//! Lexical path resolution and existing-anchor discovery.
//!
//! A complete path cannot be canonicalized before first-use state directories exist.
//! This module therefore resolves a path lexically against an explicit base, then
//! asks the platform seam for the longest existing prefix. No filesystem entry is
//! created or followed by the resolver itself; identity and comparison semantics
//! remain attached to the platform-provided anchor.

#![allow(dead_code)]

use crate::error::{ConfigurationFailure, ConfigurationFailureCode, FailureSource, LayerClass};
use crate::platform::{FileIdentity, FileSnapshot, Platform};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
/// The stable identity of a path, made from its longest existing anchor and
/// the missing tail interpreted with that anchor's native comparison rules.
///
/// The anchor identity is deliberately kept separate from the comparison tail:
/// a first-use state directory may not exist yet, but its existing ancestor still
/// supplies the filesystem identity, case behavior, and Unicode normalization.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PathIdentity {
    existing_anchor_id: FileIdentity,
    comparison_tail: PathBuf,
}

impl PathIdentity {
    pub(crate) const fn existing_anchor_id(&self) -> FileIdentity {
        self.existing_anchor_id
    }

    pub(crate) fn comparison_tail(&self) -> &Path {
        &self.comparison_tail
    }
}

/// Resolve a path identity without creating or following any filesystem entry.
///
/// The longest existing ancestor supplies the stable file identity. Every missing
/// component is then normalized using the ancestor's native Unicode policy and
/// case behavior, so aliases converge while distinct anchor identities remain
/// distinct.
pub(crate) fn resolve_path_identity<P: Platform>(
    platform: &P,
    absolute_path: &Path,
) -> Result<PathIdentity, ConfigurationFailure> {
    let ancestor = longest_existing_ancestor(platform, absolute_path)?;
    let comparison_tail =
        normalize_comparison_tail(platform, ancestor.path(), ancestor.comparison_tail())?;
    Ok(PathIdentity {
        existing_anchor_id: ancestor.identity(),
        comparison_tail,
    })
}

fn normalize_comparison_tail<P: Platform>(
    platform: &P,
    anchor: &Path,
    tail: &Path,
) -> Result<PathBuf, ConfigurationFailure> {
    if tail.as_os_str().is_empty() {
        return Ok(PathBuf::new());
    }
    let case_behavior = platform.case_behavior(anchor)?;
    let mut normalized = PathBuf::new();
    for component in tail.components() {
        let Component::Normal(component) = component else {
            return Err(path_unavailable());
        };
        let text = component.to_str().ok_or_else(path_unavailable)?;
        let mut text = platform.normalize_component(anchor, text)?;
        if case_behavior == crate::platform::CaseBehavior::Insensitive {
            text = text.to_lowercase();
        }
        normalized.push(text);
    }
    Ok(normalized)
}

/// Resolve `input` against `base` and remove only lexical `.` and `..` segments.
///
/// The result is always absolute. An absolute input is used as-is; a relative
/// input is interpreted relative to the explicit base. This function deliberately
/// does not call `canonicalize`, inspect the filesystem, or resolve symlinks.
pub(crate) fn absolute_lexical_normalize(
    base: &Path,
    input: &Path,
) -> Result<PathBuf, ConfigurationFailure> {
    let candidate = if input.is_absolute() {
        input.to_path_buf()
    } else {
        if !base.is_absolute() {
            return Err(path_unavailable());
        }
        base.join(input)
    };

    if !candidate.is_absolute() {
        return Err(path_unavailable());
    }

    Ok(lexical_normalize(&candidate))
}

/// Remove lexical `.` and `..` segments without consulting the host filesystem.
///
/// For an absolute path, `..` at the root is discarded. Relative paths are also
/// normalized for the benefit of callers that already validated their base; their
/// leading `..` segments are retained rather than silently changing meaning.
pub(crate) fn lexical_normalize(path: &Path) -> PathBuf {
    let absolute = path.is_absolute();
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized
                    .components()
                    .next_back()
                    .is_some_and(|component| matches!(component, Component::Normal(_)))
                {
                    normalized.pop();
                } else if !absolute {
                    normalized.push(Component::ParentDir.as_os_str());
                }
            }
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Component::RootDir.as_os_str()),
            Component::Normal(component) => normalized.push(component),
        }
    }

    normalized
}

/// The longest existing path prefix and the missing lexical tail beneath it.
///
/// `snapshot` is the observation returned by the platform seam for `path`. It
/// carries the stable file identity needed by later path-identity stages while
/// preserving the exact path used for the lookup. The tail is never probed or
/// created here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExistingAncestor {
    path: PathBuf,
    snapshot: FileSnapshot,
    comparison_tail: PathBuf,
}

impl ExistingAncestor {
    pub(crate) const fn identity(&self) -> FileIdentity {
        self.snapshot.identity
    }

    pub(crate) const fn snapshot(&self) -> FileSnapshot {
        self.snapshot
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn comparison_tail(&self) -> &Path {
        &self.comparison_tail
    }
}

/// Find the longest existing ancestor of an absolute, lexically normalized path.
///
/// A missing path is not an error while walking toward its root. Host failures
/// are propagated unchanged, and the walk fails closed if no existing anchor can
/// be observed. The returned tail preserves component boundaries and ordering.
pub(crate) fn longest_existing_ancestor<P: Platform>(
    platform: &P,
    absolute_path: &Path,
) -> Result<ExistingAncestor, ConfigurationFailure> {
    if !absolute_path.is_absolute() {
        return Err(path_unavailable());
    }

    let normalized = lexical_normalize(absolute_path);
    let mut anchor = normalized.clone();
    let mut missing_components = Vec::<OsString>::new();

    loop {
        match platform.file_snapshot(&anchor)? {
            Some(snapshot) => {
                let mut comparison_tail = PathBuf::new();
                for component in missing_components.iter().rev() {
                    comparison_tail.push(component);
                }
                return Ok(ExistingAncestor {
                    path: anchor,
                    snapshot,
                    comparison_tail,
                });
            }
            None => {
                let Some(component) = anchor.file_name().map(OsString::from) else {
                    return Err(path_unavailable());
                };
                missing_components.push(component);
                if !anchor.pop() {
                    return Err(path_unavailable());
                }
            }
        }
    }
}

fn path_unavailable() -> ConfigurationFailure {
    ConfigurationFailure::new(
        ConfigurationFailureCode::PathUnavailable,
        FailureSource::Layer(LayerClass::BuiltIn),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{FileIdentity, FileSnapshot, FixturePlatform, PlatformKind};

    #[test]
    fn absolute_normalization_resolves_relative_input_without_host_access() {
        assert_eq!(
            absolute_lexical_normalize(
                Path::new("/fixture/project/./nested"),
                Path::new("../state/./root"),
            )
            .expect("absolute result"),
            Path::new("/fixture/project/state/root"),
        );
        assert_eq!(
            absolute_lexical_normalize(
                Path::new("/fixture/project"),
                Path::new("/fixture/other/../state"),
            )
            .expect("absolute input"),
            Path::new("/fixture/state"),
        );
    }

    #[test]
    fn absolute_normalization_discards_parent_segments_at_root() {
        assert_eq!(
            lexical_normalize(Path::new("/../../fixture/./project/../state")),
            Path::new("/fixture/state"),
        );
        assert_eq!(
            absolute_lexical_normalize(Path::new("relative"), Path::new("child"))
                .expect_err("relative bases cannot produce an absolute identity")
                .code(),
            ConfigurationFailureCode::PathUnavailable,
        );
    }

    #[test]
    fn longest_existing_ancestor_returns_anchor_and_ordered_missing_tail() {
        let anchor = FileSnapshot::directory(
            FileIdentity {
                volume: 7,
                file: 42,
            },
            Some(9),
        );
        let platform = FixturePlatform::new(PlatformKind::Linux)
            .with_snapshot("/fixture/project", anchor)
            .with_snapshot_results("/fixture/project/missing/deeper", [Ok(None)])
            .with_snapshot_results("/fixture/project/missing", [Ok(None)]);

        let result =
            longest_existing_ancestor(&platform, Path::new("/fixture/project/missing/./deeper"))
                .expect("configured anchor");

        assert_eq!(result.path(), Path::new("/fixture/project"));
        assert_eq!(result.identity(), anchor.identity);
        assert_eq!(result.comparison_tail(), Path::new("missing/deeper"));
    }

    #[test]
    fn longest_existing_ancestor_propagates_platform_failures() {
        let failure = ConfigurationFailure::new(
            ConfigurationFailureCode::FileUnreadable,
            FailureSource::Layer(LayerClass::BuiltIn),
        );
        let platform = FixturePlatform::new(PlatformKind::Linux)
            .with_snapshot_results("/fixture/project/missing", [Err(failure)]);

        assert_eq!(
            longest_existing_ancestor(&platform, Path::new("/fixture/project/missing"))
                .expect_err("platform failure")
                .code(),
            ConfigurationFailureCode::FileUnreadable,
        );
    }

    fn platform_with_anchor(kind: PlatformKind, identity: FileIdentity) -> FixturePlatform {
        FixturePlatform::new(kind)
            .with_snapshot("/fixture/project", FileSnapshot::directory(identity, None))
    }

    #[test]
    fn path_identity_uses_anchor_identity_and_native_comparison_rules() {
        let mac = platform_with_anchor(
            PlatformKind::MacOs,
            FileIdentity {
                volume: 1,
                file: 11,
            },
        );
        let linux = platform_with_anchor(
            PlatformKind::Linux,
            FileIdentity {
                volume: 2,
                file: 22,
            },
        );
        let windows = platform_with_anchor(
            PlatformKind::Windows,
            FileIdentity {
                volume: 3,
                file: 33,
            },
        );
        let requested = Path::new("/fixture/project/MiXeD/É");

        let mac_identity = resolve_path_identity(&mac, requested).expect("mac identity");
        assert_eq!(
            mac_identity.existing_anchor_id(),
            FileIdentity {
                volume: 1,
                file: 11,
            }
        );
        assert_eq!(mac_identity.comparison_tail(), Path::new("mixed/e\u{301}"));

        let linux_identity = resolve_path_identity(&linux, requested).expect("linux identity");
        assert_eq!(linux_identity.comparison_tail(), Path::new("MiXeD/É"));

        let windows_identity =
            resolve_path_identity(&windows, requested).expect("windows identity");
        assert_eq!(windows_identity.comparison_tail(), Path::new("mixed/é"));
    }

    #[test]
    fn path_identity_preserves_empty_tail_without_querying_comparison_policy() {
        let failure = ConfigurationFailure::new(
            ConfigurationFailureCode::FileUnreadable,
            FailureSource::Layer(LayerClass::BuiltIn),
        );
        let platform = platform_with_anchor(
            PlatformKind::Linux,
            FileIdentity {
                volume: 4,
                file: 44,
            },
        )
        .with_case_behavior_error(failure);

        let identity = resolve_path_identity(&platform, Path::new("/fixture/project"))
            .expect("existing anchors do not require tail comparison");
        assert_eq!(
            identity.existing_anchor_id(),
            FileIdentity {
                volume: 4,
                file: 44
            }
        );
        assert_eq!(identity.comparison_tail(), Path::new(""));
    }

    #[test]
    fn path_identity_propagates_native_comparison_failures() {
        let failure = ConfigurationFailure::new(
            ConfigurationFailureCode::FileUnreadable,
            FailureSource::Layer(LayerClass::BuiltIn),
        );
        let platform = platform_with_anchor(
            PlatformKind::Linux,
            FileIdentity {
                volume: 5,
                file: 55,
            },
        )
        .with_case_behavior_error(failure);

        assert_eq!(
            resolve_path_identity(&platform, Path::new("/fixture/project/missing"))
                .expect_err("comparison failure")
                .code(),
            ConfigurationFailureCode::FileUnreadable
        );
    }
}
