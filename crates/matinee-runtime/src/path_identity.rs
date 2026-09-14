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
}
