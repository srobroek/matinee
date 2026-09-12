#![allow(dead_code)]

//! The private host seam used by runtime resolution.
//!
//! `Platform` is the only runtime boundary that may inspect the host. The
//! production implementation delegates directory discovery to `directories`
//! and filesystem operations to `std`; `FixturePlatform` supplies the same
//! contract without consulting the host.

use crate::error::{ConfigurationFailure, ConfigurationFailureCode, FailureSource, LayerClass};
use directories::BaseDirs;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

pub(crate) const MAX_FILE_BYTES: usize = 1_048_576;

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

/// Bytes read from one opened handle and the metadata observed on that handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileRead {
    pub(crate) snapshot: FileSnapshot,
    pub(crate) contents: Vec<u8>,
}

/// Every host operation needed by environment and path resolution.
pub(crate) trait Platform {
    fn kind(&self) -> PlatformKind;
    fn base_directories(&self) -> Result<BaseDirectories, ConfigurationFailure>;
    fn environment_variable(&self, name: &OsStr) -> Option<OsString>;
    fn environment_variables(&self) -> Vec<(OsString, OsString)>;
    /// Returns `Ok(None)` only when the path is absent. An existing path that
    /// cannot be interrogated remains a closed configuration failure.
    fn file_snapshot(&self, path: &Path) -> Result<Option<FileSnapshot>, ConfigurationFailure>;
    /// Opens and reads one handle, returning the bytes and that handle's
    /// identity evidence together. The implementation enforces the bound.
    fn read_file(&self, path: &Path) -> Result<FileRead, ConfigurationFailure>;
    fn case_behavior(&self, anchor: &Path) -> CaseBehavior;
    fn unicode_normalization(&self, anchor: &Path) -> UnicodeNormalization;

    fn components_equal(&self, anchor: &Path, left: &str, right: &str) -> bool {
        match self.case_behavior(anchor) {
            CaseBehavior::Sensitive => left == right,
            CaseBehavior::Insensitive => left.to_lowercase() == right.to_lowercase(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HostPlatform {
    kind: PlatformKind,
    bases: BaseDirectories,
    default_case_behavior: CaseBehavior,
    default_unicode_normalization: UnicodeNormalization,
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
            default_case_behavior: current_case_behavior(),
            default_unicode_normalization: current_unicode_normalization(),
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

    fn file_snapshot(&self, path: &Path) -> Result<Option<FileSnapshot>, ConfigurationFailure> {
        let link_metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(file_unreadable()),
        };
        if link_metadata.file_type().is_symlink() {
            let identity = file_identity(&link_metadata).ok_or_else(file_unreadable)?;
            return Ok(Some(FileSnapshot {
                identity,
                file_type: FileType::Symlink,
                byte_length: 0,
                modified_marker: modified_marker(&link_metadata),
            }));
        }
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(file_unreadable()),
        };
        let identity = file_identity(&metadata).ok_or_else(file_unreadable)?;
        Ok(Some(FileSnapshot {
            identity,
            file_type: file_type(&metadata),
            byte_length: metadata.len(),
            modified_marker: modified_marker(&metadata),
        }))
    }

    fn read_file(&self, path: &Path) -> Result<FileRead, ConfigurationFailure> {
        let file = fs::File::open(path).map_err(|_| file_unreadable())?;
        let metadata = file.metadata().map_err(|_| file_unreadable())?;
        let snapshot = FileSnapshot {
            identity: file_identity(&metadata).ok_or_else(file_unreadable)?,
            file_type: file_type(&metadata),
            byte_length: metadata.len(),
            modified_marker: modified_marker(&metadata),
        };
        if snapshot.file_type != FileType::Regular {
            return Err(file_unreadable());
        }
        if snapshot.byte_length > MAX_FILE_BYTES as u64 {
            return Err(file_too_large());
        }
        let mut contents = Vec::with_capacity(
            snapshot.byte_length.min((MAX_FILE_BYTES + 1) as u64) as usize,
        );
        file.take((MAX_FILE_BYTES + 1) as u64)
            .read_to_end(&mut contents)
            .map_err(|_| file_unreadable())?;
        if contents.len() > MAX_FILE_BYTES {
            return Err(file_too_large());
        }
        Ok(FileRead { snapshot, contents })
    }

    fn case_behavior(&self, _anchor: &Path) -> CaseBehavior {
        self.default_case_behavior
    }

    fn unicode_normalization(&self, _anchor: &Path) -> UnicodeNormalization {
        self.default_unicode_normalization
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AnchorPolicy {
    case_behavior: CaseBehavior,
    unicode_normalization: UnicodeNormalization,
}

#[derive(Clone, Debug)]
struct FixtureEntry {
    snapshots: VecDeque<Result<Option<FileSnapshot>, ConfigurationFailure>>,
    snapshot_fallback: Result<Option<FileSnapshot>, ConfigurationFailure>,
    reads: VecDeque<Result<FileRead, ConfigurationFailure>>,
    read_fallback: Result<FileRead, ConfigurationFailure>,
}

impl FixtureEntry {
    fn empty() -> Self {
        Self {
            snapshots: VecDeque::new(),
            snapshot_fallback: Err(file_unreadable()),
            reads: VecDeque::new(),
            read_fallback: Err(file_unreadable()),
        }
    }

    fn file(snapshot: FileSnapshot, contents: Vec<u8>) -> Self {
        let read = Ok(FileRead { snapshot, contents });
        Self {
            snapshots: VecDeque::from([Ok(Some(snapshot))]),
            snapshot_fallback: Ok(Some(snapshot)),
            reads: VecDeque::from([read.clone()]),
            read_fallback: read,
        }
    }

    fn snapshot_only(snapshot: FileSnapshot) -> Self {
        let mut entry = Self::empty();
        entry.snapshots.push_back(Ok(Some(snapshot)));
        entry.snapshot_fallback = Ok(Some(snapshot));
        entry
    }

    fn next_snapshot(&mut self) -> Result<Option<FileSnapshot>, ConfigurationFailure> {
        self.snapshots
            .pop_front()
            .unwrap_or_else(|| self.snapshot_fallback.clone())
    }

    fn next_read(&mut self) -> Result<FileRead, ConfigurationFailure> {
        self.reads
            .pop_front()
            .unwrap_or_else(|| self.read_fallback.clone())
    }
}

/// A host-independent platform implementation for contract tests.
#[derive(Clone, Debug)]
pub(crate) struct FixturePlatform {
    kind: PlatformKind,
    bases: Result<BaseDirectories, ConfigurationFailure>,
    environment: BTreeMap<OsString, OsString>,
    entries: RefCell<BTreeMap<PathBuf, FixtureEntry>>,
    default_case_behavior: CaseBehavior,
    default_unicode_normalization: UnicodeNormalization,
    anchor_policies: BTreeMap<PathBuf, AnchorPolicy>,
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
            bases: Ok(bases),
            environment: BTreeMap::new(),
            entries: RefCell::new(BTreeMap::new()),
            default_case_behavior: case_behavior,
            default_unicode_normalization: unicode_normalization,
            anchor_policies: BTreeMap::new(),
        }
    }

    pub(crate) fn with_environment(mut self, name: &str, value: &str) -> Self {
        self.environment
            .insert(OsString::from(name), OsString::from(value));
        self
    }

    pub(crate) fn with_file(
        self,
        path: impl Into<PathBuf>,
        identity: FileIdentity,
        contents: impl Into<Vec<u8>>,
        modified_marker: Option<u128>,
    ) -> Self {
        let contents = contents.into();
        self.entries.borrow_mut().insert(
            path.into(),
            FixtureEntry::file(
                FileSnapshot::regular(identity, contents.len() as u64, modified_marker),
                contents,
            ),
        );
        self
    }

    pub(crate) fn with_snapshot(
        self,
        path: impl Into<PathBuf>,
        snapshot: FileSnapshot,
    ) -> Self {
        self.entries
            .borrow_mut()
            .insert(path.into(), FixtureEntry::snapshot_only(snapshot));
        self
    }

    pub(crate) fn with_snapshot_results<I>(
        self,
        path: impl Into<PathBuf>,
        results: I,
    ) -> Self
    where
        I: IntoIterator<Item = Result<Option<FileSnapshot>, ConfigurationFailure>>,
    {
        let results: Vec<_> = results.into_iter().collect();
        let fallback = results
            .last()
            .cloned()
            .unwrap_or_else(|| Err(file_unreadable()));
        let mut entries = self.entries.borrow_mut();
        let entry = entries.entry(path.into()).or_insert_with(FixtureEntry::empty);
        entry.snapshots = results.into();
        entry.snapshot_fallback = fallback;
        drop(entries);
        self
    }

    pub(crate) fn with_read_results<I>(self, path: impl Into<PathBuf>, results: I) -> Self
    where
        I: IntoIterator<Item = Result<FileRead, ConfigurationFailure>>,
    {
        let results: Vec<_> = results.into_iter().collect();
        let fallback = results
            .last()
            .cloned()
            .unwrap_or_else(|| Err(file_unreadable()));
        let mut entries = self.entries.borrow_mut();
        let entry = entries.entry(path.into()).or_insert_with(FixtureEntry::empty);
        entry.reads = results.into();
        entry.read_fallback = fallback;
        drop(entries);
        self
    }

    pub(crate) fn with_base_directories(mut self, bases: BaseDirectories) -> Self {
        self.bases = Ok(bases);
        self
    }

    pub(crate) fn with_base_directory_failure(mut self) -> Self {
        self.bases = Err(path_unavailable());
        self
    }

    pub(crate) fn with_anchor_policy(
        mut self,
        anchor: impl Into<PathBuf>,
        case_behavior: CaseBehavior,
        unicode_normalization: UnicodeNormalization,
    ) -> Self {
        self.anchor_policies.insert(
            anchor.into(),
            AnchorPolicy {
                case_behavior,
                unicode_normalization,
            },
        );
        self
    }

    fn policy_for(&self, anchor: &Path) -> AnchorPolicy {
        self.anchor_policies
            .iter()
            .filter(|(root, _)| anchor.starts_with(root))
            .max_by_key(|(root, _)| root.components().count())
            .map(|(_, policy)| *policy)
            .unwrap_or(AnchorPolicy {
                case_behavior: self.default_case_behavior,
                unicode_normalization: self.default_unicode_normalization,
            })
    }
}

impl Platform for FixturePlatform {
    fn kind(&self) -> PlatformKind {
        self.kind
    }

    fn base_directories(&self) -> Result<BaseDirectories, ConfigurationFailure> {
        self.bases.clone()
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

    fn file_snapshot(&self, path: &Path) -> Result<Option<FileSnapshot>, ConfigurationFailure> {
        self.entries
            .borrow_mut()
            .get_mut(path)
            .map(FixtureEntry::next_snapshot)
            .unwrap_or(Ok(None))
    }

    fn read_file(&self, path: &Path) -> Result<FileRead, ConfigurationFailure> {
        let result = self
            .entries
            .borrow_mut()
            .get_mut(path)
            .map(FixtureEntry::next_read)
            .unwrap_or_else(|| Err(file_unreadable()))?;
        if result.contents.len() > MAX_FILE_BYTES {
            return Err(file_too_large());
        }
        Ok(result)
    }

    fn case_behavior(&self, anchor: &Path) -> CaseBehavior {
        self.policy_for(anchor).case_behavior
    }

    fn unicode_normalization(&self, anchor: &Path) -> UnicodeNormalization {
        self.policy_for(anchor).unicode_normalization
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

fn file_too_large() -> ConfigurationFailure {
    ConfigurationFailure::new(
        ConfigurationFailureCode::FileTooLarge,
        FailureSource::Layer(LayerClass::BuiltIn),
    )
}

fn file_type(metadata: &fs::Metadata) -> FileType {
    if metadata.is_file() {
        FileType::Regular
    } else if metadata.is_dir() {
        FileType::Directory
    } else {
        FileType::Other
    }
}

fn modified_marker(metadata: &fs::Metadata) -> Option<u128> {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
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

    fn snapshot(file: u64, bytes: u64, marker: u128) -> FileSnapshot {
        FileSnapshot::regular(
            FileIdentity { volume: 7, file },
            bytes,
            Some(marker),
        )
    }

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
            .expect("fixture snapshot")
            .expect("fixture file is present");
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
        let read = platform
            .read_file(Path::new("/fixture/project/matine.toml"))
            .expect("fixture read");
        assert_eq!(read.snapshot, snapshot);
        assert_eq!(read.contents, b"[project]\n".to_vec());
    }

    #[test]
    fn fixture_read_enforces_one_mib_bound() {
        // FR-005-017 and contracts/configuration.md pin the file-read limit at 1 MiB.
        assert_eq!(MAX_FILE_BYTES, 1_048_576);
        let at_bound = vec![b'a'; 1_048_576];
        let over_bound = vec![b'b'; 1_048_577];
        let platform = FixturePlatform::new(PlatformKind::Linux)
            .with_file("/fixture/bound", FileIdentity { volume: 1, file: 1 }, at_bound, None)
            .with_file(
                "/fixture/over-bound",
                FileIdentity { volume: 1, file: 2 },
                over_bound,
                None,
            );
        assert_eq!(
            platform
                .read_file(Path::new("/fixture/bound"))
                .expect("exactly one MiB is accepted")
                .contents
                .len(),
            1_048_576
        );
        assert_eq!(
            platform
                .read_file(Path::new("/fixture/over-bound"))
                .expect_err("one byte over the bound is rejected")
                .code(),
            ConfigurationFailureCode::FileTooLarge
        );
    }

    #[test]
    fn fixture_distinguishes_absence_from_inaccessibility_while_walking_ancestor() {
        let platform = FixturePlatform::new(PlatformKind::Linux)
            .with_snapshot_results(
                "/fixture/home/missing/project.toml",
                [Ok(None)],
            )
            .with_snapshot_results("/fixture/home/missing", [Ok(None)])
            .with_snapshot_results(
                "/fixture/home",
                [Err(file_unreadable())],
            );
        assert_eq!(
            platform
                .file_snapshot(Path::new("/fixture/home/missing/project.toml"))
                .expect("missing descendant is not a failure"),
            None
        );
        assert_eq!(
            platform
                .file_snapshot(Path::new("/fixture/home/missing"))
                .expect("missing directory is not a failure"),
            None
        );
        assert_eq!(
            platform
                .file_snapshot(Path::new("/fixture/home"))
                .expect_err("inaccessible existing ancestor rejects")
                .code(),
            ConfigurationFailureCode::FileUnreadable
        );
    }

    #[test]
    fn fixture_case_and_unicode_policies_are_explicit() {
        let mac = FixturePlatform::new(PlatformKind::MacOs);
        let linux = FixturePlatform::new(PlatformKind::Linux);
        let windows = FixturePlatform::new(PlatformKind::Windows);
        assert!(mac.components_equal(Path::new("/fixture/macos"), "Config", "config"));
        assert!(!linux.components_equal(Path::new("/fixture/linux"), "Config", "config"));
        assert!(windows.components_equal(Path::new(r"C:\Users"), "Config", "config"));
        assert_eq!(
            mac.unicode_normalization(Path::new("/fixture/macos")),
            UnicodeNormalization::CanonicalDecomposed
        );
        assert_eq!(
            linux.unicode_normalization(Path::new("/fixture/linux")),
            UnicodeNormalization::Preserve
        );
        assert_eq!(
            windows.unicode_normalization(Path::new(r"C:\Users")),
            UnicodeNormalization::Preserve
        );
    }

    #[test]
    fn fixture_anchor_policies_can_differ_on_one_host_shape() {
        let platform = FixturePlatform::new(PlatformKind::Linux)
            .with_anchor_policy(
                "/fixture/volume-sensitive",
                CaseBehavior::Sensitive,
                UnicodeNormalization::Preserve,
            )
            .with_anchor_policy(
                "/fixture/volume-insensitive",
                CaseBehavior::Insensitive,
                UnicodeNormalization::Preserve,
            );
        assert!(!platform.components_equal(
            Path::new("/fixture/volume-sensitive/project"),
            "Config",
            "config"
        ));
        assert!(platform.components_equal(
            Path::new("/fixture/volume-insensitive/project"),
            "Config",
            "config"
        ));
    }

    #[test]
    fn fixture_scripts_per_call_snapshots_and_same_handle_read_evidence() {
        let first = snapshot(11, 5, 1);
        let second = snapshot(12, 6, 2);
        let platform = FixturePlatform::new(PlatformKind::Linux)
            .with_snapshot_results(
                "/fixture/project/matine.toml",
                [Ok(Some(first)), Ok(Some(second))],
            )
            .with_read_results(
                "/fixture/project/matine.toml",
                [Ok(FileRead {
                    snapshot: first,
                    contents: b"hello".to_vec(),
                })],
            );
        assert_eq!(
            platform
                .file_snapshot(Path::new("/fixture/project/matine.toml"))
                .expect("first observation"),
            Some(first)
        );
        assert_eq!(
            platform
                .file_snapshot(Path::new("/fixture/project/matine.toml"))
                .expect("second observation"),
            Some(second)
        );
        let read = platform
            .read_file(Path::new("/fixture/project/matine.toml"))
            .expect("scripted read");
        assert_eq!(read.snapshot, first);
        assert_eq!(read.contents, b"hello".to_vec());
    }

    #[test]
    fn fixture_base_directory_failure_and_override_are_scriptable() {
        let override_bases = BaseDirectories {
            home: PathBuf::from("/override/home"),
            config: PathBuf::from("/override/config"),
            data: PathBuf::from("/override/data"),
            state: None,
            runtime: None,
            cache: PathBuf::from("/override/cache"),
        };
        let overridden = FixturePlatform::new(PlatformKind::Linux)
            .with_base_directories(override_bases.clone());
        assert_eq!(overridden.base_directories(), Ok(override_bases));
        assert_eq!(
            FixturePlatform::new(PlatformKind::Linux)
                .with_base_directory_failure()
                .base_directories()
                .expect_err("base discovery failure is expressible")
                .code(),
            ConfigurationFailureCode::PathUnavailable
        );
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
