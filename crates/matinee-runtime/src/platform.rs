#![allow(dead_code)]

//! The private host seam used by runtime resolution.
//!
//! `Platform` is the only runtime boundary that may inspect the host. The
//! production implementation delegates directory discovery to `directories`
//! and filesystem operations to `std`; `FixturePlatform` supplies the same
//! contract without consulting the host.

use crate::error::{ConfigurationFailure, ConfigurationFailureCode, FailureSource, LayerClass};
use directories::BaseDirs;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization as UnicodeNormalizationTrait;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    ERROR_INVALID_FUNCTION, ERROR_INVALID_LEVEL, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
    GetLastError, HANDLE, WIN32_ERROR,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FileAttributeTagInfo,
    FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
    GetVolumeInformationByHandleW,
};

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

/// Matinee-owned directories derived from the operating system base locations.
///
/// The values are paths only: resolution never creates any of these directories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MatineePaths {
    pub(crate) config: PathBuf,
    pub(crate) state: PathBuf,
    pub(crate) runtime: PathBuf,
    pub(crate) cache: PathBuf,
    pub(crate) logs: PathBuf,
}

impl MatineePaths {
    pub(crate) fn config(&self) -> &Path {
        &self.config
    }

    pub(crate) fn state(&self) -> &Path {
        &self.state
    }

    pub(crate) fn runtime(&self) -> &Path {
        &self.runtime
    }

    pub(crate) fn cache(&self) -> &Path {
        &self.cache
    }

    pub(crate) fn logs(&self) -> &Path {
        &self.logs
    }
}

impl BaseDirectories {
    /// Derive Matinee's stable directory layout from platform base locations.
    pub(crate) fn matinee_paths(
        &self,
        kind: PlatformKind,
    ) -> Result<MatineePaths, ConfigurationFailure> {
        match kind {
            PlatformKind::MacOs => {
                let config_base = required_base(&self.config, kind)?;
                let home = required_base(&self.home, kind)?;
                let config = append_component(&config_base, kind, "Matinee");
                let state = append_component(&config, kind, "state");
                let runtime = append_component(&state, kind, "run");
                let cache = append_component(&required_base(&self.cache, kind)?, kind, "Matinee");
                let logs = append_component(
                    &append_component(&append_component(&home, kind, "Library"), kind, "Logs"),
                    kind,
                    "Matinee",
                );
                Ok(MatineePaths {
                    config,
                    state,
                    runtime,
                    cache,
                    logs,
                })
            }
            PlatformKind::Linux => {
                let config = append_component(&required_base(&self.config, kind)?, kind, "matinee");
                let state_base =
                    required_base(self.state.as_deref().ok_or_else(path_unavailable)?, kind)?;
                let state = append_component(&state_base, kind, "matinee");
                let runtime_base = self
                    .runtime
                    .as_deref()
                    .map(|path| required_base(path, kind))
                    .transpose()?
                    .unwrap_or_else(|| state.clone());
                let runtime = if self.runtime.is_some() {
                    append_component(&runtime_base, kind, "matinee")
                } else {
                    append_component(&runtime_base, kind, "run")
                };
                let cache = append_component(&required_base(&self.cache, kind)?, kind, "matinee");
                let logs = append_component(&state, kind, "logs");
                Ok(MatineePaths {
                    config,
                    state,
                    runtime,
                    cache,
                    logs,
                })
            }
            PlatformKind::Windows => {
                let config = append_component(&required_base(&self.config, kind)?, kind, "Matinee");
                let local = append_component(&required_base(&self.data, kind)?, kind, "Matinee");
                let state = append_component(&local, kind, "state");
                let runtime = append_component(&state, kind, "run");
                let cache = append_component(&local, kind, "cache");
                let logs = append_component(&state, kind, "logs");
                Ok(MatineePaths {
                    config,
                    state,
                    runtime,
                    cache,
                    logs,
                })
            }
        }
    }
}

fn required_base(path: &Path, kind: PlatformKind) -> Result<PathBuf, ConfigurationFailure> {
    if path.as_os_str().is_empty() || !is_absolute_for_platform(path, kind) {
        return Err(path_unavailable());
    }
    Ok(path.to_path_buf())
}

fn is_absolute_for_platform(path: &Path, kind: PlatformKind) -> bool {
    let text = path.to_string_lossy();
    match kind {
        PlatformKind::MacOs | PlatformKind::Linux => text.starts_with('/'),
        PlatformKind::Windows => {
            text.starts_with("\\\\")
                || text.starts_with("//")
                || (text.len() >= 3
                    && text.as_bytes()[0].is_ascii_alphabetic()
                    && text.as_bytes()[1] == b':'
                    && matches!(text.as_bytes()[2], b'\\' | b'/'))
        }
    }
}

fn append_component(base: &Path, kind: PlatformKind, component: &str) -> PathBuf {
    if kind == PlatformKind::Windows && cfg!(not(windows)) {
        let trailing = base.to_string_lossy();
        let mut joined = base.as_os_str().to_os_string();
        if !trailing.ends_with('\\') && !trailing.ends_with('/') {
            joined.push("\\");
        }
        joined.push(component);
        PathBuf::from(joined)
    } else {
        base.join(component)
    }
}

/// Which host API produced an identity's numeric payload.
///
/// A 64-bit legacy file index and a complete 128-bit file id are not
/// interchangeable evidence: the narrow form can repeat where the wide form
/// does not. Recording the scheme inside the identity makes that distinction
/// part of equality and hashing instead of a caller's obligation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum IdentityScheme {
    /// The complete 128-bit file id reported for the volume.
    Full128,
    /// The 64-bit file index reported by the legacy handle information API.
    Legacy64,
}

/// Identity evidence for one file, qualified by the scheme that produced it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FileIdentity {
    /// Private so that every identity names its scheme through a constructor.
    /// Two schemes never compare or hash as equal, even for equal payloads.
    scheme: IdentityScheme,
    pub(crate) volume: u64,
    pub(crate) file: u128,
}

impl FileIdentity {
    /// Records identity evidence whose file component is a complete file id.
    pub(crate) const fn full(volume: u64, file: u128) -> Self {
        Self {
            scheme: IdentityScheme::Full128,
            volume,
            file,
        }
    }

    /// Records identity evidence narrowed to a 64-bit file index. Only the
    /// legacy Windows handle information API reports identity in this form.
    const fn legacy(volume: u64, file: u64) -> Self {
        Self {
            scheme: IdentityScheme::Legacy64,
            volume,
            file: file as u128,
        }
    }
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

pub(crate) trait Platform {
    fn kind(&self) -> PlatformKind;
    fn base_directories(&self) -> Result<BaseDirectories, ConfigurationFailure>;
    fn matinee_paths(&self) -> Result<MatineePaths, ConfigurationFailure> {
        self.base_directories()?.matinee_paths(self.kind())
    }
    fn environment_variable(&self, name: &OsStr) -> Option<OsString>;
    fn environment_variables(&self) -> Vec<(OsString, OsString)>;
    /// Returns `Ok(None)` only when the path is absent. An existing path that
    /// cannot be interrogated remains a closed configuration failure.
    fn file_snapshot(&self, path: &Path) -> Result<Option<FileSnapshot>, ConfigurationFailure>;
    /// Returns the stable identity of the target named by `path`, following symbolic links.
    /// This is deliberately separate from [`Self::file_snapshot`], whose file type and
    /// identity are the no-follow evidence used to reject implicit linked project files.
    fn followed_file_identity(
        &self,
        path: &Path,
    ) -> Result<Option<FileIdentity>, ConfigurationFailure>;
    /// Opens and reads one handle, returning the bytes and that handle's
    /// identity evidence together. The implementation enforces the bound.
    fn read_file(&self, path: &Path) -> Result<FileRead, ConfigurationFailure>;
    fn case_behavior(&self, anchor: &Path) -> Result<CaseBehavior, ConfigurationFailure>;
    fn unicode_normalization(
        &self,
        anchor: &Path,
    ) -> Result<UnicodeNormalization, ConfigurationFailure>;

    fn normalize_component(
        &self,
        anchor: &Path,
        text: &str,
    ) -> Result<String, ConfigurationFailure> {
        Ok(match self.unicode_normalization(anchor)? {
            UnicodeNormalization::Preserve => text.to_owned(),
            UnicodeNormalization::CanonicalDecomposed => text.nfd().collect(),
        })
    }

    fn components_equal(
        &self,
        anchor: &Path,
        left: &str,
        right: &str,
    ) -> Result<bool, ConfigurationFailure> {
        Ok(match self.case_behavior(anchor)? {
            CaseBehavior::Sensitive => left == right,
            CaseBehavior::Insensitive => left.to_lowercase() == right.to_lowercase(),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct HostPlatform {
    kind: PlatformKind,
    bases: BaseDirectories,
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
        #[cfg(windows)]
        {
            let mut options = fs::OpenOptions::new();
            options
                .access_mode(0)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
            let file = match options.open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(file_unreadable()),
            };
            let metadata = file.metadata().map_err(|_| file_unreadable())?;
            let file_type = no_follow_file_type(&file, &metadata);
            let identity = identity_from_open_file(&file, &metadata).ok_or_else(file_unreadable)?;
            return Ok(Some(FileSnapshot {
                identity,
                file_type,
                byte_length: if file_type == FileType::Symlink {
                    0
                } else {
                    metadata.len()
                },
                modified_marker: modified_marker(&metadata),
            }));
        }

        #[cfg(not(windows))]
        {
            let link_metadata = match fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(file_unreadable()),
            };
            if link_metadata.file_type().is_symlink() {
                #[cfg(windows)]
                let identity = identity_for_path(path, false)?.ok_or_else(file_unreadable)?;
                #[cfg(not(windows))]
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
            #[cfg(windows)]
            let identity = identity_for_path(path, true)?.ok_or_else(file_unreadable)?;
            #[cfg(not(windows))]
            let identity = file_identity(&metadata).ok_or_else(file_unreadable)?;
            Ok(Some(FileSnapshot {
                identity,
                file_type: file_type(&metadata),
                byte_length: metadata.len(),
                modified_marker: modified_marker(&metadata),
            }))
        }
    }
    fn followed_file_identity(
        &self,
        path: &Path,
    ) -> Result<Option<FileIdentity>, ConfigurationFailure> {
        identity_for_path(path, true)
    }

    fn read_file(&self, path: &Path) -> Result<FileRead, ConfigurationFailure> {
        let file = fs::File::open(path).map_err(|_| file_unreadable())?;
        let metadata = file.metadata().map_err(|_| file_unreadable())?;
        let snapshot = FileSnapshot {
            identity: identity_from_open_file(&file, &metadata).ok_or_else(file_unreadable)?,
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
        let mut contents =
            Vec::with_capacity(snapshot.byte_length.min((MAX_FILE_BYTES + 1) as u64) as usize);
        (&file)
            .take((MAX_FILE_BYTES + 1) as u64)
            .read_to_end(&mut contents)
            .map_err(|_| file_unreadable())?;
        if contents.len() > MAX_FILE_BYTES {
            return Err(file_too_large());
        }
        let post_read_metadata = file.metadata().map_err(|_| file_unreadable())?;
        let post_read_snapshot = FileSnapshot {
            identity: identity_from_open_file(&file, &post_read_metadata)
                .ok_or_else(file_unreadable)?,
            file_type: file_type(&post_read_metadata),
            byte_length: post_read_metadata.len(),
            modified_marker: modified_marker(&post_read_metadata),
        };
        if post_read_snapshot.file_type != FileType::Regular {
            return Err(file_unreadable());
        }
        Ok(FileRead {
            snapshot: post_read_snapshot,
            contents,
        })
    }

    fn case_behavior(&self, anchor: &Path) -> Result<CaseBehavior, ConfigurationFailure> {
        probe_case_behavior(anchor)
    }

    fn unicode_normalization(
        &self,
        anchor: &Path,
    ) -> Result<UnicodeNormalization, ConfigurationFailure> {
        probe_unicode_normalization(anchor, self.kind)
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
        self.snapshots.pop_front().unwrap_or(self.snapshot_fallback)
    }

    fn followed_identity(&self) -> Result<Option<FileIdentity>, ConfigurationFailure> {
        self.snapshots
            .front()
            .cloned()
            .unwrap_or(self.snapshot_fallback)
            .map(|snapshot| snapshot.map(|snapshot| snapshot.identity))
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
    read_file_count: Cell<usize>,
    entries: RefCell<BTreeMap<PathBuf, FixtureEntry>>,
    followed_identities: BTreeMap<PathBuf, Result<Option<FileIdentity>, ConfigurationFailure>>,
    default_case_behavior: CaseBehavior,
    default_unicode_normalization: UnicodeNormalization,
    anchor_policies: BTreeMap<PathBuf, AnchorPolicy>,
    case_behavior_error: Option<ConfigurationFailure>,
    unicode_normalization_error: Option<ConfigurationFailure>,
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
            read_file_count: Cell::new(0),
            followed_identities: BTreeMap::new(),
            entries: RefCell::new(BTreeMap::new()),
            default_case_behavior: case_behavior,
            default_unicode_normalization: unicode_normalization,
            anchor_policies: BTreeMap::new(),
            case_behavior_error: None,
            unicode_normalization_error: None,
        }
    }

    pub(crate) fn with_environment(self, name: &str, value: &str) -> Self {
        self.with_environment_os(OsString::from(name), OsString::from(value))
    }

    pub(crate) fn with_environment_os(mut self, name: OsString, value: OsString) -> Self {
        self.environment.insert(name, value);
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

    pub(crate) fn with_snapshot(self, path: impl Into<PathBuf>, snapshot: FileSnapshot) -> Self {
        self.entries
            .borrow_mut()
            .insert(path.into(), FixtureEntry::snapshot_only(snapshot));
        self
    }
    pub(crate) fn with_followed_file_identity(
        mut self,
        path: impl Into<PathBuf>,
        identity: FileIdentity,
    ) -> Self {
        self.followed_identities
            .insert(path.into(), Ok(Some(identity)));
        self
    }
    #[cfg(test)]
    pub(crate) fn with_followed_file_identity_result(
        mut self,
        path: impl Into<PathBuf>,
        result: Result<Option<FileIdentity>, ConfigurationFailure>,
    ) -> Self {
        self.followed_identities.insert(path.into(), result);
        self
    }

    pub(crate) fn with_snapshot_results<I>(self, path: impl Into<PathBuf>, results: I) -> Self
    where
        I: IntoIterator<Item = Result<Option<FileSnapshot>, ConfigurationFailure>>,
    {
        let results: Vec<_> = results.into_iter().collect();
        let fallback = results
            .last()
            .cloned()
            .unwrap_or_else(|| Err(file_unreadable()));
        let mut entries = self.entries.borrow_mut();
        let entry = entries
            .entry(path.into())
            .or_insert_with(FixtureEntry::empty);
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
        let entry = entries
            .entry(path.into())
            .or_insert_with(FixtureEntry::empty);
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

    pub(crate) fn with_case_behavior_error(mut self, failure: ConfigurationFailure) -> Self {
        self.case_behavior_error = Some(failure);
        self
    }

    pub(crate) fn with_unicode_normalization_error(
        mut self,
        failure: ConfigurationFailure,
    ) -> Self {
        self.unicode_normalization_error = Some(failure);
        self
    }

    #[cfg(test)]
    pub(crate) fn read_file_count(&self) -> usize {
        self.read_file_count.get()
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
    fn followed_file_identity(
        &self,
        path: &Path,
    ) -> Result<Option<FileIdentity>, ConfigurationFailure> {
        if let Some(identity) = self.followed_identities.get(path) {
            return *identity;
        }
        self.entries
            .borrow()
            .get(path)
            .map(FixtureEntry::followed_identity)
            .unwrap_or(Ok(None))
    }

    fn read_file(&self, path: &Path) -> Result<FileRead, ConfigurationFailure> {
        self.read_file_count.set(self.read_file_count.get() + 1);
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

    fn case_behavior(&self, anchor: &Path) -> Result<CaseBehavior, ConfigurationFailure> {
        if let Some(failure) = self.case_behavior_error {
            return Err(failure);
        }
        Ok(self.policy_for(anchor).case_behavior)
    }

    fn unicode_normalization(
        &self,
        anchor: &Path,
    ) -> Result<UnicodeNormalization, ConfigurationFailure> {
        if let Some(failure) = self.unicode_normalization_error {
            return Err(failure);
        }
        Ok(self.policy_for(anchor).unicode_normalization)
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

#[cfg(windows)]
fn no_follow_file_type(file: &fs::File, metadata: &fs::Metadata) -> FileType {
    if metadata.file_type().is_symlink() {
        return FileType::Symlink;
    }
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return file_type(metadata);
    }

    let mut tag_info = unsafe { std::mem::zeroed::<FILE_ATTRIBUTE_TAG_INFO>() };
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileAttributeTagInfo,
            &mut tag_info as *mut FILE_ATTRIBUTE_TAG_INFO as *mut _,
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if succeeded != 0 && tag_info.ReparseTag & 0x2000_0000 == 0 {
        file_type(metadata)
    } else {
        FileType::Other
    }
}

#[cfg(not(windows))]
fn file_identity(metadata: &fs::Metadata) -> Option<FileIdentity> {
    #[cfg(unix)]
    {
        Some(FileIdentity::full(metadata.dev(), metadata.ino() as u128))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        None
    }
}
#[cfg(windows)]
fn file_identity_from_handle(file: &fs::File) -> Option<FileIdentity> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut information = unsafe { std::mem::zeroed::<FILE_ID_INFO>() };
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            &mut information as *mut FILE_ID_INFO as *mut _,
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if succeeded != 0 {
        return Some(FileIdentity::full(
            information.VolumeSerialNumber,
            // FILE_ID_128 is opaque; this explicit representation preserves all bytes.
            u128::from_le_bytes(information.FileId.Identifier),
        ));
    }
    // The thread error belongs to the call above, so it is read before any
    // other host call can overwrite it.
    let error = unsafe { GetLastError() };
    if !file_id_info_unsupported(error) || !legacy_file_index_identifies(handle) {
        return None;
    }

    let mut legacy = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    let succeeded = unsafe { GetFileInformationByHandle(handle, &mut legacy) };
    (succeeded != 0).then(|| {
        FileIdentity::legacy(
            legacy.dwVolumeSerialNumber as u64,
            ((legacy.nFileIndexHigh as u64) << 32) | legacy.nFileIndexLow as u64,
        )
    })
}

/// Whether `error` reports that the host cannot answer `FileIdInfo` at all.
///
/// Only these four errors describe an unsupported or unrecognised request. A
/// permission, transient, or unknown failure says nothing about the volume's
/// identity scheme, so it must not license the narrower legacy query.
#[cfg(windows)]
const fn file_id_info_unsupported(error: WIN32_ERROR) -> bool {
    matches!(
        error,
        ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED | ERROR_INVALID_PARAMETER | ERROR_INVALID_LEVEL
    )
}

/// Whether the filesystem behind `handle` numbers its files inside 64 bits.
///
/// ReFS assigns 128-bit file ids, so its legacy index is a truncation rather
/// than an identity. The name is read from the same live handle; a failed or
/// unnamed answer counts as insufficient, because refusing identity evidence
/// is correct where guessing its width is not.
#[cfg(windows)]
fn legacy_file_index_identifies(handle: HANDLE) -> bool {
    /// Filesystem names whose file identity needs more than 64 bits.
    const WIDE_IDENTITY_FILESYSTEMS: [&str; 1] = ["ReFS"];

    // A filesystem name is bounded by MAX_PATH characters plus its terminator.
    let mut name = [0u16; 261];
    let succeeded = unsafe {
        GetVolumeInformationByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    if succeeded == 0 {
        return false;
    }
    let length = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    if length == 0 {
        return false;
    }
    let filesystem = String::from_utf16_lossy(&name[..length]);
    !WIDE_IDENTITY_FILESYSTEMS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(filesystem.as_str()))
}

fn identity_from_open_file(file: &fs::File, metadata: &fs::Metadata) -> Option<FileIdentity> {
    #[cfg(windows)]
    {
        let _ = metadata;
        file_identity_from_handle(file)
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        file_identity(metadata)
    }
}

fn identity_for_path(
    path: &Path,
    follow_links: bool,
) -> Result<Option<FileIdentity>, ConfigurationFailure> {
    #[cfg(windows)]
    {
        let mut flags = FILE_FLAG_BACKUP_SEMANTICS;
        if !follow_links {
            flags |= FILE_FLAG_OPEN_REPARSE_POINT;
        }
        let mut options = fs::OpenOptions::new();
        options.access_mode(0).custom_flags(flags);
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(file_unreadable()),
        };
        return file_identity_from_handle(&file)
            .map(Some)
            .ok_or_else(file_unreadable);
    }
    #[cfg(not(windows))]
    {
        let metadata = if follow_links {
            fs::metadata(path)
        } else {
            fs::symlink_metadata(path)
        };
        match metadata {
            Ok(metadata) => file_identity(&metadata)
                .map(Some)
                .ok_or_else(file_unreadable),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(file_unreadable()),
        }
    }
}

fn existing_anchor(anchor: &Path) -> Result<PathBuf, ConfigurationFailure> {
    if !anchor.is_absolute() {
        return Err(path_unavailable());
    }
    match fs::metadata(anchor) {
        Ok(metadata) if metadata.is_dir() => Ok(anchor.to_path_buf()),
        Ok(_) => Err(path_unavailable()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(path_unavailable()),
        Err(_) => Err(file_unreadable()),
    }
}

fn identity_at(path: &Path) -> Result<Option<FileIdentity>, ConfigurationFailure> {
    identity_for_path(path, true)
}

fn flip_ascii_case(component: &OsStr) -> Option<OsString> {
    let text = component.to_str()?;
    let mut changed = false;
    let flipped: String = text
        .chars()
        .map(|character| {
            if character.is_ascii_lowercase() {
                changed = true;
                character.to_ascii_uppercase()
            } else if character.is_ascii_uppercase() {
                changed = true;
                character.to_ascii_lowercase()
            } else {
                character
            }
        })
        .collect();
    changed.then(|| OsString::from(flipped))
}

fn flipped_path(path: &Path) -> Option<PathBuf> {
    let components: Vec<_> = path.components().collect();
    let index = components.len().checked_sub(1)?;
    let replacement = flip_ascii_case(components[index].as_os_str())?;
    let mut flipped = PathBuf::new();
    for (component_index, component) in components.iter().enumerate() {
        if component_index == index {
            flipped.push(&replacement);
        } else {
            flipped.push(component.as_os_str());
        }
    }
    Some(flipped)
}

fn probe_case_behavior(anchor: &Path) -> Result<CaseBehavior, ConfigurationFailure> {
    let ancestor = existing_anchor(anchor)?;
    let comparison = flipped_path(&ancestor).ok_or_else(file_unreadable)?;
    let identity = identity_at(&ancestor)?.ok_or_else(file_unreadable)?;
    Ok(match identity_at(&comparison)? {
        Some(comparison_identity) if comparison_identity == identity => CaseBehavior::Insensitive,
        Some(_) | None => CaseBehavior::Sensitive,
    })
}

fn probe_unicode_normalization(
    anchor: &Path,
    kind: PlatformKind,
) -> Result<UnicodeNormalization, ConfigurationFailure> {
    let _ = existing_anchor(anchor)?;
    Ok(match kind {
        PlatformKind::MacOs => UnicodeNormalization::CanonicalDecomposed,
        PlatformKind::Linux | PlatformKind::Windows => UnicodeNormalization::Preserve,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(file: u128, bytes: u64, marker: u128) -> FileSnapshot {
        FileSnapshot::regular(FileIdentity::full(7, file), bytes, Some(marker))
    }

    fn independent_identity(path: &Path) -> Result<Option<FileIdentity>, ConfigurationFailure> {
        identity_for_path(path, true)
    }

    fn independent_case_behavior(anchor: &Path) -> Result<CaseBehavior, ConfigurationFailure> {
        if !anchor.is_absolute() {
            return Err(path_unavailable());
        }
        let metadata = fs::metadata(anchor).map_err(|_| file_unreadable())?;
        if !metadata.is_dir() {
            return Err(path_unavailable());
        }
        let anchor_identity = identity_for_path(anchor, true)?.ok_or_else(file_unreadable)?;
        let name = anchor
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(file_unreadable)?;
        let mut changed = false;
        let flipped_name: String = name
            .chars()
            .map(|character| {
                if character.is_ascii_lowercase() {
                    changed = true;
                    character.to_ascii_uppercase()
                } else if character.is_ascii_uppercase() {
                    changed = true;
                    character.to_ascii_lowercase()
                } else {
                    character
                }
            })
            .collect();
        if !changed {
            return Err(file_unreadable());
        }
        let mut flipped = anchor.to_path_buf();
        flipped.set_file_name(flipped_name);
        match independent_identity(&flipped)? {
            Some(flipped_identity) if flipped_identity == anchor_identity => {
                Ok(CaseBehavior::Insensitive)
            }
            Some(_) | None => Ok(CaseBehavior::Sensitive),
        }
    }

    fn independent_unicode_normalization(
        anchor: &Path,
    ) -> Result<UnicodeNormalization, ConfigurationFailure> {
        if !anchor.is_absolute() {
            return Err(path_unavailable());
        }
        let metadata = fs::metadata(anchor).map_err(|_| file_unreadable())?;
        if !metadata.is_dir() {
            return Err(path_unavailable());
        }
        let mut directory = anchor.to_path_buf();
        loop {
            for entry in fs::read_dir(&directory).map_err(|_| file_unreadable())? {
                let entry = entry.map_err(|_| file_unreadable())?;
                let name = entry.file_name();
                let Some(text) = name.to_str() else {
                    continue;
                };
                let variants = if text.contains('\u{00e9}') {
                    Some((
                        OsString::from(text),
                        OsString::from(text.replace('\u{00e9}', "e\u{0301}")),
                    ))
                } else if text.contains("e\u{0301}") {
                    Some((
                        OsString::from(text.replace("e\u{0301}", "\u{00e9}")),
                        OsString::from(text),
                    ))
                } else {
                    None
                };
                let Some((composed, decomposed)) = variants else {
                    continue;
                };
                let composed_identity = independent_identity(&directory.join(composed))?;
                let decomposed_identity = independent_identity(&directory.join(decomposed))?;
                return Ok(match (composed_identity, decomposed_identity) {
                    (Some(left), Some(right)) if left == right => {
                        UnicodeNormalization::CanonicalDecomposed
                    }
                    _ => UnicodeNormalization::Preserve,
                });
            }
            let Some(parent) = directory.parent() else {
                break;
            };
            if parent == directory {
                break;
            }
            directory = parent.to_path_buf();
        }
        Err(file_unreadable())
    }

    fn assert_case_probe_result(
        actual: Result<CaseBehavior, ConfigurationFailure>,
        independent: Result<CaseBehavior, ConfigurationFailure>,
    ) {
        match actual {
            Ok(actual) => assert_eq!(independent, Ok(actual)),
            Err(failure) => assert!(matches!(
                failure.code(),
                ConfigurationFailureCode::FileUnreadable
                    | ConfigurationFailureCode::PathUnavailable
            )),
        }
    }

    fn assert_unicode_probe_result(
        actual: Result<UnicodeNormalization, ConfigurationFailure>,
        independent: Result<UnicodeNormalization, ConfigurationFailure>,
    ) {
        match actual {
            Ok(actual) => assert_eq!(independent, Ok(actual)),
            Err(failure) => assert!(matches!(
                failure.code(),
                ConfigurationFailureCode::FileUnreadable
                    | ConfigurationFailureCode::PathUnavailable
            )),
        }
    }

    fn propagate_case_query<P: Platform>(
        platform: &P,
        anchor: &Path,
    ) -> Result<bool, ConfigurationFailure> {
        platform.components_equal(anchor, "Config", "config")
    }

    fn propagate_unicode_query<P: Platform>(
        platform: &P,
        anchor: &Path,
    ) -> Result<UnicodeNormalization, ConfigurationFailure> {
        platform.unicode_normalization(anchor)
    }

    #[test]
    fn flipped_path_flips_final_component_only() {
        let original = Path::new("/before/Middle/Final");
        let flipped = flipped_path(original).expect("final component contains ASCII letters");
        let original_components: Vec<_> = original.components().collect();
        let flipped_components: Vec<_> = flipped.components().collect();

        assert_eq!(flipped, Path::new("/before/Middle/fINAL"));
        assert_eq!(flipped_components[0], original_components[0]);
        assert_eq!(flipped_components[1], original_components[1]);
        assert_eq!(flipped_components[2], original_components[2]);
        assert_ne!(flipped_components[3], original_components[3]);
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
    fn absolute_path_validation_follows_requested_platform() {
        let unix_root = Path::new("/fixture/linux/home/.config");
        let windows_drive = Path::new(r"C:\Users\fixture\AppData");
        let windows_unc = Path::new(r"\\server\share\Matinee");

        assert!(is_absolute_for_platform(unix_root, PlatformKind::MacOs));
        assert!(is_absolute_for_platform(unix_root, PlatformKind::Linux));
        assert!(!is_absolute_for_platform(unix_root, PlatformKind::Windows));
        assert!(is_absolute_for_platform(
            windows_drive,
            PlatformKind::Windows
        ));
        assert!(is_absolute_for_platform(windows_unc, PlatformKind::Windows));
        assert!(!is_absolute_for_platform(
            windows_drive,
            PlatformKind::Linux
        ));
        assert!(!is_absolute_for_platform(windows_unc, PlatformKind::MacOs));
    }

    #[test]
    fn fixture_derives_matinee_paths_for_all_supported_platforms() {
        let mac = FixturePlatform::new(PlatformKind::MacOs)
            .matinee_paths()
            .expect("macOS paths");
        assert_eq!(
            mac.config(),
            Path::new("/fixture/macos/home/Library/Application Support/Matinee")
        );
        assert_eq!(
            mac.state(),
            Path::new("/fixture/macos/home/Library/Application Support/Matinee/state")
        );
        assert_eq!(
            mac.runtime(),
            Path::new("/fixture/macos/home/Library/Application Support/Matinee/state/run")
        );
        assert_eq!(
            mac.cache(),
            Path::new("/fixture/macos/home/Library/Caches/Matinee")
        );
        assert_eq!(
            mac.logs(),
            Path::new("/fixture/macos/home/Library/Logs/Matinee")
        );

        let linux = FixturePlatform::new(PlatformKind::Linux)
            .matinee_paths()
            .expect("Linux paths");
        assert_eq!(
            linux.config(),
            Path::new("/fixture/linux/home/.config/matinee")
        );
        assert_eq!(
            linux.state(),
            Path::new("/fixture/linux/home/.local/state/matinee")
        );
        assert_eq!(linux.runtime(), Path::new("/fixture/linux/runtime/matinee"));
        assert_eq!(
            linux.cache(),
            Path::new("/fixture/linux/home/.cache/matinee")
        );
        assert_eq!(
            linux.logs(),
            Path::new("/fixture/linux/home/.local/state/matinee/logs")
        );

        let windows = FixturePlatform::new(PlatformKind::Windows)
            .matinee_paths()
            .expect("Windows paths");
        assert_eq!(
            windows.config(),
            Path::new(r"C:\Users\fixture\AppData\Roaming\Matinee")
        );
        assert_eq!(
            windows.state(),
            Path::new(r"C:\Users\fixture\AppData\Local\Matinee\state")
        );
        assert_eq!(
            windows.runtime(),
            Path::new(r"C:\Users\fixture\AppData\Local\Matinee\state\run")
        );
        assert_eq!(
            windows.cache(),
            Path::new(r"C:\Users\fixture\AppData\Local\Matinee\cache")
        );
        assert_eq!(
            windows.logs(),
            Path::new(r"C:\Users\fixture\AppData\Local\Matinee\state\logs")
        );
    }

    #[test]
    fn linux_runtime_falls_back_to_state_run_without_mutation() {
        let bases = BaseDirectories {
            home: PathBuf::from("/fixture/linux/home"),
            config: PathBuf::from("/fixture/linux/home/.config"),
            data: PathBuf::from("/fixture/linux/home/.local/share"),
            state: Some(PathBuf::from("/fixture/linux/home/.local/state")),
            runtime: None,
            cache: PathBuf::from("/fixture/linux/home/.cache"),
        };
        let paths = bases
            .matinee_paths(PlatformKind::Linux)
            .expect("state fallback");
        assert_eq!(
            paths.runtime(),
            Path::new("/fixture/linux/home/.local/state/matinee/run")
        );
    }

    #[test]
    fn missing_linux_state_base_is_a_closed_path_failure() {
        let bases = BaseDirectories {
            home: PathBuf::from("/fixture/linux/home"),
            config: PathBuf::from("/fixture/linux/home/.config"),
            data: PathBuf::from("/fixture/linux/home/.local/share"),
            state: None,
            runtime: Some(PathBuf::from("/fixture/linux/runtime")),
            cache: PathBuf::from("/fixture/linux/home/.cache"),
        };
        assert_eq!(
            bases
                .matinee_paths(PlatformKind::Linux)
                .expect_err("missing state base")
                .code(),
            ConfigurationFailureCode::PathUnavailable
        );
    }

    #[test]
    fn fixture_exposes_environment_and_file_identity_without_host_access() {
        let platform = FixturePlatform::new(PlatformKind::Linux)
            .with_environment("MATINEE_STATE_DIR", "/fixture/state")
            .with_file(
                "/fixture/project/matine.toml",
                FileIdentity::full(7, 11),
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
            FileIdentity::full(7, 11)
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
            .with_file(
                "/fixture/bound",
                FileIdentity::full(1, 1),
                at_bound,
                None,
            )
            .with_file(
                "/fixture/over-bound",
                FileIdentity::full(1, 2),
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
            .with_snapshot_results("/fixture/home/missing/project.toml", [Ok(None)])
            .with_snapshot_results("/fixture/home/missing", [Ok(None)])
            .with_snapshot_results("/fixture/home", [Err(file_unreadable())]);
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
                .file_snapshot(Path::new("/fixture/home/missing/unconfigured.toml"))
                .expect("an unconfigured absent path is not a failure"),
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
        assert!(
            mac.components_equal(Path::new("/fixture/macos"), "Config", "config")
                .expect("fixture case policy"),
        );
        assert!(
            !linux
                .components_equal(Path::new("/fixture/linux"), "Config", "config")
                .expect("fixture case policy")
        );
        assert!(
            windows
                .components_equal(Path::new(r"C:\Users"), "Config", "config")
                .expect("fixture case policy"),
        );
        assert_eq!(
            mac.unicode_normalization(Path::new("/fixture/macos"))
                .expect("fixture Unicode policy"),
            UnicodeNormalization::CanonicalDecomposed
        );
        assert_eq!(
            linux
                .unicode_normalization(Path::new("/fixture/linux"))
                .expect("fixture Unicode policy"),
            UnicodeNormalization::Preserve
        );
        assert_eq!(
            windows
                .unicode_normalization(Path::new(r"C:\Users"))
                .expect("fixture Unicode policy"),
            UnicodeNormalization::Preserve
        );
    }

    #[test]
    fn fixture_normalize_component_uses_anchor_policy() {
        let platform = FixturePlatform::new(PlatformKind::Linux)
            .with_anchor_policy(
                "/fixture/canonical",
                CaseBehavior::Sensitive,
                UnicodeNormalization::CanonicalDecomposed,
            )
            .with_anchor_policy(
                "/fixture/preserve",
                CaseBehavior::Sensitive,
                UnicodeNormalization::Preserve,
            );
        assert_eq!(
            platform.normalize_component(Path::new("/fixture/canonical"), "Å"),
            Ok("A\u{030a}".to_owned())
        );
        assert_eq!(
            platform.normalize_component(Path::new("/fixture/canonical"), "A\u{030a}"),
            Ok("A\u{030a}".to_owned())
        );
        assert_eq!(
            platform.normalize_component(Path::new("/fixture/preserve"), "Å"),
            Ok("Å".to_owned())
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
        assert!(
            !platform
                .components_equal(
                    Path::new("/fixture/volume-sensitive/project"),
                    "Config",
                    "config"
                )
                .expect("fixture case policy")
        );
        assert!(
            platform
                .components_equal(
                    Path::new("/fixture/volume-insensitive/project"),
                    "Config",
                    "config"
                )
                .expect("fixture case policy")
        );
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
    fn fixture_policy_errors_are_closed_and_propagate_through_callers() {
        let case_failure = file_unreadable();
        let unicode_failure = path_unavailable();
        let platform = FixturePlatform::new(PlatformKind::Linux)
            .with_case_behavior_error(case_failure)
            .with_unicode_normalization_error(unicode_failure);
        let anchor = Path::new("/fixture/linux");
        assert_eq!(
            propagate_case_query(&platform, anchor)
                .expect_err("caller must propagate scripted case failure")
                .code(),
            case_failure.code(),
        );
        assert_eq!(
            propagate_unicode_query(&platform, anchor)
                .expect_err("caller must propagate scripted Unicode failure")
                .code(),
            unicode_failure.code(),
        );
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
        let overridden =
            FixturePlatform::new(PlatformKind::Linux).with_base_directories(override_bases.clone());
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
    fn host_case_behavior_matches_anchor_identity_probe_or_closes() {
        let host = HostPlatform::new().expect("host platform");
        let anchor = Path::new(env!("CARGO_MANIFEST_DIR"));
        let independent = independent_case_behavior(anchor);
        assert_case_probe_result(host.case_behavior(anchor), independent);
    }

    #[test]
    fn host_unicode_normalization_is_total_for_valid_anchor_without_variant_probe() {
        let host = HostPlatform::new().expect("host platform");
        let anchor = Path::new(env!("CARGO_MANIFEST_DIR"));
        let expected = match current_platform_kind() {
            PlatformKind::MacOs => UnicodeNormalization::CanonicalDecomposed,
            PlatformKind::Linux | PlatformKind::Windows => UnicodeNormalization::Preserve,
        };
        assert_eq!(host.unicode_normalization(anchor), Ok(expected));
    }

    #[test]
    fn host_policy_queries_reject_relative_and_nonexistent_anchors() {
        let host = HostPlatform::new().expect("host platform");
        let missing =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("__matinee_missing_policy_anchor_7c7f3d");
        for anchor in [Path::new("relative"), missing.as_path()] {
            assert_eq!(
                host.case_behavior(anchor)
                    .expect_err("relative or missing case anchor must close")
                    .code(),
                ConfigurationFailureCode::PathUnavailable,
            );
            assert_eq!(
                host.unicode_normalization(anchor)
                    .expect_err("relative or missing Unicode anchor must close")
                    .code(),
                ConfigurationFailureCode::PathUnavailable,
            );
        }
    }

    #[test]
    fn fixture_anchor_case_and_unicode_behaviors_can_differ() {
        let platform = FixturePlatform::new(PlatformKind::Linux)
            .with_anchor_policy(
                "/fixture/volume-sensitive",
                CaseBehavior::Sensitive,
                UnicodeNormalization::Preserve,
            )
            .with_anchor_policy(
                "/fixture/volume-insensitive",
                CaseBehavior::Insensitive,
                UnicodeNormalization::CanonicalDecomposed,
            );
        assert_eq!(
            platform
                .case_behavior(Path::new("/fixture/volume-sensitive/project"))
                .expect("fixture case policy"),
            CaseBehavior::Sensitive
        );
        assert_eq!(
            platform
                .case_behavior(Path::new("/fixture/volume-insensitive/project"))
                .expect("fixture case policy"),
            CaseBehavior::Insensitive
        );
        assert_eq!(
            platform
                .unicode_normalization(Path::new("/fixture/volume-sensitive/project"))
                .expect("fixture Unicode policy"),
            UnicodeNormalization::Preserve
        );
        assert_eq!(
            platform
                .unicode_normalization(Path::new("/fixture/volume-insensitive/project"))
                .expect("fixture Unicode policy"),
            UnicodeNormalization::CanonicalDecomposed
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
