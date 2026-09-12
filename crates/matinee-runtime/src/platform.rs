#![allow(dead_code)]

//! The private host seam used by runtime resolution.
//!
//! `Platform` is the only runtime boundary that may inspect the host. The
//! production implementation delegates directory discovery to `directories`
//! and filesystem operations to `std`; `FixturePlatform` supplies the same
//! contract without consulting the host.

use crate::error::{ConfigurationFailure, ConfigurationFailureCode, FailureSource, LayerClass};
use directories::BaseDirs;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlatformKind {
    MacOs,
    Linux,
    Windows,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaseBehavior {
    Sensitive,
    Insensitive,
}

/// The native Unicode policy to use when interpreting path components.
///
/// The adapter reports the policy; path identity owns applying the policy to a
/// component. Keeping the policy explicit avoids pretending that the standard
/// library implements complete Unicode normalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnicodeNormalization {
    Preserve,
    CanonicalDecomposed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BaseDirectories {
    pub(crate) home: PathBuf,
    pub(crate) config: PathBuf,
    pub(crate) data: PathBuf,
    pub(crate) state: Option<PathBuf>,
    pub(crate) runtime: Option<PathBuf>,
    pub(crate) cache: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FileIdentity {
    pub(crate) volume: u64,
    pub(crate) file: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileType {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileSnapshot {
    pub(crate) identity: FileIdentity,
    pub(crate) file_type: FileType,
    pub(crate) byte_length: u64,
    pub(crate) modified_marker: Option<u128>,
}

impl FileSnapshot {
    pub(crate) const fn regular(
        identity: FileIdentity,
        byte_length: u64,
        modified_marker: Option<u128>,
    ) -> Self {
        Self {
            identity,
            file_type: FileType::Regular,
            byte_length,
            modified_marker,
        }
    }

    pub(crate) const fn directory(identity: FileIdentity, modified_marker: Option<u128>) -> Self {
        Self {
            identity,
            file_type: FileType::Directory,
            byte_length: 0,
            modified_marker,
        }
    }

    pub(crate) const fn symlink(identity: FileIdentity, modified_marker: Option<u128>) -> Self {
        Self {
            identity,
            file_type: FileType::Symlink,
            byte_length: 0,
            modified_marker,
        }
    }
}

/// Every host operation needed by environment and path resolution.
pub(crate) trait Platform {
    fn kind(&self) -> PlatformKind;
    fn base_directories(&self) -> Result<BaseDirectories, ConfigurationFailure>;
    fn environment_variable(&self, name: &OsStr) -> Option<OsString>;
    fn environment_variables(&self) -> Vec<(OsString, OsString)>;
    fn file_snapshot(&self, path: &Path) -> Result<FileSnapshot, ConfigurationFailure>;
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, ConfigurationFailure>;
    fn case_behavior(&self) -> CaseBehavior;
    fn unicode_normalization(&self) -> UnicodeNormalization;

    fn components_equal(&self, left: &str, right: &str) -> bool {
        match self.case_behavior() {
            CaseBehavior::Sensitive => left == right,
            CaseBehavior::Insensitive => left.to_lowercase() == right.to_lowercase(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HostPlatform {
    kind: PlatformKind,
    bases: BaseDirectories,
    case_behavior: CaseBehavior,
    unicode_normalization: UnicodeNormalization,
}

impl HostPlatform {
    pub(crate) fn new() -> Result<Self, ConfigurationFailure> {
        let base_dirs = BaseDirs::new().ok_or_else(path_unavailable)?;
        Ok(Self {
            kind: current_platform_kind(),
            bases: BaseDirectories {
                home: base_dirs.home_dir().to_path_buf(),
                config: base_dirs.config_dir().to_path_buf(),
                data: base_dirs.data_local_dir().to_path_buf(),
                state: base_dirs.state_dir().map(Path::to_path_buf),
                runtime: base_dirs.runtime_dir().map(Path::to_path_buf),
                cache: base_dirs.cache_dir().to_path_buf(),
            },
            case_behavior: current_case_behavior(),
            unicode_normalization: current_unicode_normalization(),
        })
    }
}

impl Platform for HostPlatform {
    fn kind(&self) -> PlatformKind {
        self.kind
    }

    fn base_directories(&self) -> Result<BaseDirectories, ConfigurationFailure> {
        Ok(self.bases.clone())
    }

    fn environment_variable(&self, name: &OsStr) -> Option<OsString> {
        std::env::var_os(name)
    }

    fn environment_variables(&self) -> Vec<(OsString, OsString)> {
        std::env::vars_os().collect()
    }

    fn file_snapshot(&self, path: &Path) -> Result<FileSnapshot, ConfigurationFailure> {
        let link_metadata = fs::symlink_metadata(path).map_err(|_| file_unreadable())?;
        let metadata = fs::metadata(path).map_err(|_| file_unreadable())?;
        let identity = file_identity(&metadata).ok_or_else(file_unreadable)?;
        let file_type = if link_metadata.file_type().is_symlink() {
            FileType::Symlink
        } else if metadata.is_file() {
            FileType::Regular
        } else if metadata.is_dir() {
            FileType::Directory
        } else {
            FileType::Other
        };
        Ok(FileSnapshot {
            identity,
            file_type,
            byte_length: metadata.len(),
            modified_marker: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos()),
        })
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, ConfigurationFailure> {
        fs::read(path).map_err(|_| file_unreadable())
    }

    fn case_behavior(&self) -> CaseBehavior {
        self.case_behavior
    }

    fn unicode_normalization(&self) -> UnicodeNormalization {
        self.unicode_normalization
    }
}

#[derive(Clone, Debug)]
struct FixtureEntry {
    snapshot: FileSnapshot,
    contents: Vec<u8>,
}

/// A host-independent platform implementation for contract tests.
#[derive(Clone, Debug)]
pub(crate) struct FixturePlatform {
    kind: PlatformKind,
    bases: BaseDirectories,
    environment: BTreeMap<OsString, OsString>,
    entries: BTreeMap<PathBuf, FixtureEntry>,
    case_behavior: CaseBehavior,
    unicode_normalization: UnicodeNormalization,
}

impl FixturePlatform {
    pub(crate) fn new(kind: PlatformKind) -> Self {
        let (bases, case_behavior, unicode_normalization) = match kind {
            PlatformKind::MacOs => (
                BaseDirectories {
                    home: PathBuf::from("/fixture/macos/home"),
                    config: PathBuf::from("/fixture/macos/home/Library/Application Support"),
                    data: PathBuf::from("/fixture/macos/home/Library/Application Support"),
                    state: None,
                    runtime: None,
                    cache: PathBuf::from("/fixture/macos/home/Library/Caches"),
                },
                CaseBehavior::Insensitive,
                UnicodeNormalization::CanonicalDecomposed,
            ),
            PlatformKind::Linux => (
                BaseDirectories {
                    home: PathBuf::from("/fixture/linux/home"),
                    config: PathBuf::from("/fixture/linux/home/.config"),
                    data: PathBuf::from("/fixture/linux/home/.local/share"),
                    state: Some(PathBuf::from("/fixture/linux/home/.local/state")),
                    runtime: Some(PathBuf::from("/fixture/linux/runtime")),
                    cache: PathBuf::from("/fixture/linux/home/.cache"),
                },
                CaseBehavior::Sensitive,
                UnicodeNormalization::Preserve,
            ),
            PlatformKind::Windows => (
                BaseDirectories {
                    home: PathBuf::from(r"C:\Users\fixture"),
                    config: PathBuf::from(r"C:\Users\fixture\AppData\Roaming"),
                    data: PathBuf::from(r"C:\Users\fixture\AppData\Local"),
                    state: None,
                    runtime: None,
                    cache: PathBuf::from(r"C:\Users\fixture\AppData\Local"),
                },
                CaseBehavior::Insensitive,
                UnicodeNormalization::Preserve,
            ),
        };
        Self {
            kind,
            bases,
            environment: BTreeMap::new(),
            entries: BTreeMap::new(),
            case_behavior,
            unicode_normalization,
        }
    }

    pub(crate) fn with_environment(mut self, name: &str, value: &str) -> Self {
        self.environment
            .insert(OsString::from(name), OsString::from(value));
        self
    }

    pub(crate) fn with_file(
        mut self,
        path: impl Into<PathBuf>,
        identity: FileIdentity,
        contents: impl Into<Vec<u8>>,
        modified_marker: Option<u128>,
    ) -> Self {
        let contents = contents.into();
        self.entries.insert(
            path.into(),
            FixtureEntry {
                snapshot: FileSnapshot::regular(identity, contents.len() as u64, modified_marker),
                contents,
            },
        );
        self
    }

    pub(crate) fn with_snapshot(
        mut self,
        path: impl Into<PathBuf>,
        snapshot: FileSnapshot,
    ) -> Self {
        self.entries.insert(
            path.into(),
            FixtureEntry {
                snapshot,
                contents: Vec::new(),
            },
        );
        self
    }
}

impl Platform for FixturePlatform {
    fn kind(&self) -> PlatformKind {
        self.kind
    }

    fn base_directories(&self) -> Result<BaseDirectories, ConfigurationFailure> {
        Ok(self.bases.clone())
    }

    fn environment_variable(&self, name: &OsStr) -> Option<OsString> {
        self.environment.get(name).cloned()
    }

    fn environment_variables(&self) -> Vec<(OsString, OsString)> {
        self.environment
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }

    fn file_snapshot(&self, path: &Path) -> Result<FileSnapshot, ConfigurationFailure> {
        self.entries
            .get(path)
            .map(|entry| entry.snapshot)
            .ok_or_else(file_unreadable)
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, ConfigurationFailure> {
        self.entries
            .get(path)
            .map(|entry| entry.contents.clone())
            .ok_or_else(file_unreadable)
    }

    fn case_behavior(&self) -> CaseBehavior {
        self.case_behavior
    }

    fn unicode_normalization(&self) -> UnicodeNormalization {
        self.unicode_normalization
    }
}

fn path_unavailable() -> ConfigurationFailure {
    ConfigurationFailure::new(
        ConfigurationFailureCode::PathUnavailable,
        FailureSource::Layer(LayerClass::BuiltIn),
    )
}

fn file_unreadable() -> ConfigurationFailure {
    ConfigurationFailure::new(
        ConfigurationFailureCode::FileUnreadable,
        FailureSource::Layer(LayerClass::BuiltIn),
    )
}

fn file_identity(metadata: &fs::Metadata) -> Option<FileIdentity> {
    #[cfg(unix)]
    {
        Some(FileIdentity {
            volume: metadata.dev(),
            file: metadata.ino(),
        })
    }
    #[cfg(windows)]
    {
        Some(FileIdentity {
            volume: metadata.volume_serial_number()? as u64,
            file: metadata.file_index()?,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        None
    }
}

const fn current_platform_kind() -> PlatformKind {
    #[cfg(target_os = "macos")]
    {
        PlatformKind::MacOs
    }
    #[cfg(target_os = "windows")]
    {
        PlatformKind::Windows
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        PlatformKind::Linux
    }
}

const fn current_case_behavior() -> CaseBehavior {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        CaseBehavior::Insensitive
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        CaseBehavior::Sensitive
    }
}

const fn current_unicode_normalization() -> UnicodeNormalization {
    #[cfg(target_os = "macos")]
    {
        UnicodeNormalization::CanonicalDecomposed
    }
    #[cfg(not(target_os = "macos"))]
    {
        UnicodeNormalization::Preserve
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_covers_macos_linux_and_windows_directory_shapes() {
        let cases = [
            (
                PlatformKind::MacOs,
                "/fixture/macos/home/Library/Application Support",
                None,
            ),
            (
                PlatformKind::Linux,
                "/fixture/linux/home/.config",
                Some("/fixture/linux/home/.local/state"),
            ),
            (
                PlatformKind::Windows,
                r"C:\Users\fixture\AppData\Roaming",
                None,
            ),
        ];
        for (kind, config, state) in cases {
            let platform = FixturePlatform::new(kind);
            let bases = platform.base_directories().expect("fixture bases");
            assert_eq!(bases.config, PathBuf::from(config));
            assert_eq!(bases.state, state.map(PathBuf::from));
            assert_eq!(platform.kind(), kind);
        }
    }

    #[test]
    fn fixture_exposes_environment_and_file_identity_without_host_access() {
        let platform = FixturePlatform::new(PlatformKind::Linux)
            .with_environment("MATINEE_STATE_DIR", "/fixture/state")
            .with_file(
                "/fixture/project/matine.toml",
                FileIdentity {
                    volume: 7,
                    file: 11,
                },
                b"[project]\n",
                Some(42),
            );
        assert_eq!(
            platform.environment_variable(OsStr::new("MATINEE_STATE_DIR")),
            Some(OsString::from("/fixture/state"))
        );
        let snapshot = platform
            .file_snapshot(Path::new("/fixture/project/matine.toml"))
            .expect("fixture snapshot");
        assert_eq!(
            snapshot.identity,
            FileIdentity {
                volume: 7,
                file: 11
            }
        );
        assert_eq!(snapshot.file_type, FileType::Regular);
        assert_eq!(snapshot.byte_length, 10);
        assert_eq!(snapshot.modified_marker, Some(42));
        assert_eq!(
            platform.read_file(Path::new("/fixture/project/matine.toml")),
            Ok(b"[project]\n".to_vec())
        );
    }

    #[test]
    fn fixture_case_and_unicode_policies_are_explicit() {
        let mac = FixturePlatform::new(PlatformKind::MacOs);
        let linux = FixturePlatform::new(PlatformKind::Linux);
        let windows = FixturePlatform::new(PlatformKind::Windows);
        assert!(mac.components_equal("Config", "config"));
        assert!(!linux.components_equal("Config", "config"));
        assert!(windows.components_equal("Config", "config"));
        assert_eq!(
            mac.unicode_normalization(),
            UnicodeNormalization::CanonicalDecomposed
        );
        assert_eq!(
            linux.unicode_normalization(),
            UnicodeNormalization::Preserve
        );
        assert_eq!(
            windows.unicode_normalization(),
            UnicodeNormalization::Preserve
        );
    }

    #[test]
    fn fixture_maps_host_failures_to_closed_runtime_errors() {
        let platform = FixturePlatform::new(PlatformKind::Linux);
        let failure = platform
            .file_snapshot(Path::new("/fixture/missing"))
            .expect_err("missing fixture must fail");
        assert_eq!(failure.code(), ConfigurationFailureCode::FileUnreadable);
        assert_eq!(failure.source(), FailureSource::Layer(LayerClass::BuiltIn));
    }

    #[test]
    fn host_reports_this_platform_through_the_interface() {
        let host = HostPlatform::new().expect("host platform");
        assert_eq!(host.kind(), current_platform_kind());
        let bases = host.base_directories().expect("host bases");
        assert!(bases.home.is_absolute());
        assert!(host.environment_variable(OsStr::new("PATH")).is_some());
        assert!(!host.environment_variables().is_empty());
    }
}
