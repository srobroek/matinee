//! Typed configuration descriptors and the closed spec-005 registry.
//!
//! Configuration values are classified by their descriptor, never by inspecting
//! arbitrary input text. The registry is intentionally small and closed: adding
//! a key requires adding a descriptor with an explicit material class, source
//! policy, and value shape.

use crate::environment::{AcceptedKey, ConfigurationSource};
use crate::error::{ConfigurationFailure, ConfigurationFailureCode, FailureSource};
use std::io::Read;

/// The maximum number of descriptors accepted by one registry.
#[allow(dead_code)]
pub(crate) const MAX_REGISTERED_KEYS: usize = 100;

/// The maximum size of one configuration file, in bytes.
#[allow(dead_code)]
pub(crate) const MAX_FILE_BYTES: usize = 1024 * 1024;

/// The maximum number of assignments in one configuration document.
#[allow(dead_code)]
pub(crate) const MAX_ASSIGNMENTS: usize = 100;

/// The maximum number of segments in one effective dotted key.
#[allow(dead_code)]
pub(crate) const MAX_DOTTED_SEGMENTS: usize = 4;

/// The maximum number of Unicode scalar values in one text value.
#[allow(dead_code)]
pub(crate) const MAX_TEXT_SCALARS: usize = 4_096;

const MAX_LEXICAL_NESTING: usize = 64;

/// The typed shape a descriptor expects after TOML deserialization.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ValueKind {
    Text,
    Boolean,
    Integer,
    Float,
    Path,
}

/// The descriptor-owned material policy.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MaterialClass {
    NonSecret,
    OpaqueSecretReference,
    SecretMaterial,
}

/// A value-specific normalization policy declared by a descriptor.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Normalizer {
    Identity,
    TrimAsciiWhitespace,
    LowercaseAscii,
}

/// The owner that is allowed to define a protected descriptor.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DescriptorOwner {
    RuntimeFoundation,
    Unassigned,
}

/// A typed default retained by a descriptor when one is defined.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum DescriptorDefault {
    Text(String),
    Boolean(bool),
    Integer(i64),
    Float(f64),
}

/// A compact source permission set for one descriptor.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AllowedSources(u8);

#[allow(dead_code)]
impl AllowedSources {
    const DEFAULT: u8 = 1 << 0;
    const USER_FILE: u8 = 1 << 1;
    const PROJECT_FILE: u8 = 1 << 2;
    const ENVIRONMENT: u8 = 1 << 3;
    const COMMAND_LINE: u8 = 1 << 4;

    pub(crate) const fn empty() -> Self {
        Self(0)
    }
    pub(crate) const fn all() -> Self {
        Self(
            Self::DEFAULT
                | Self::USER_FILE
                | Self::PROJECT_FILE
                | Self::ENVIRONMENT
                | Self::COMMAND_LINE,
        )
    }
    pub(crate) const fn user_and_command_line() -> Self {
        Self(Self::USER_FILE | Self::COMMAND_LINE)
    }
    pub(crate) const fn contains(self, source: ConfigurationSource) -> bool {
        self.0 & Self::bit(source) != 0
    }
    const fn bit(source: ConfigurationSource) -> u8 {
        match source {
            ConfigurationSource::Default => Self::DEFAULT,
            ConfigurationSource::UserFile => Self::USER_FILE,
            ConfigurationSource::ProjectFile => Self::PROJECT_FILE,
            ConfigurationSource::Environment => Self::ENVIRONMENT,
            ConfigurationSource::CommandLine => Self::COMMAND_LINE,
        }
    }
}

/// One accepted configuration key and its complete validation policy.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct KeyDescriptor {
    name: String,
    value_kind: ValueKind,
    default: Option<DescriptorDefault>,
    allowed_sources: AllowedSources,
    material_class: MaterialClass,
    sensitive: bool,
    normalizer: Normalizer,
    owner: DescriptorOwner,
}

#[allow(dead_code)]
impl KeyDescriptor {
    pub(crate) fn new(
        name: impl Into<String>,
        value_kind: ValueKind,
        allowed_sources: AllowedSources,
        material_class: MaterialClass,
    ) -> Self {
        Self {
            name: name.into(),
            value_kind,
            default: None,
            allowed_sources,
            material_class,
            sensitive: false,
            normalizer: Normalizer::Identity,
            owner: DescriptorOwner::Unassigned,
        }
    }
    pub(crate) fn with_default(mut self, default: DescriptorDefault) -> Self {
        self.default = Some(default);
        self
    }
    pub(crate) fn with_sensitive(mut self, sensitive: bool) -> Self {
        self.sensitive = sensitive;
        self
    }
    pub(crate) fn with_normalizer(mut self, normalizer: Normalizer) -> Self {
        self.normalizer = normalizer;
        self
    }
    pub(crate) fn with_owner(mut self, owner: DescriptorOwner) -> Self {
        self.owner = owner;
        self
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) const fn value_kind(&self) -> ValueKind {
        self.value_kind
    }
    pub(crate) fn default(&self) -> Option<&DescriptorDefault> {
        self.default.as_ref()
    }
    pub(crate) const fn allowed_sources(&self) -> AllowedSources {
        self.allowed_sources
    }
    pub(crate) const fn material_class(&self) -> MaterialClass {
        self.material_class
    }
    pub(crate) const fn sensitive(&self) -> bool {
        self.sensitive
    }
    pub(crate) const fn normalizer(&self) -> Normalizer {
        self.normalizer
    }
    pub(crate) const fn owner(&self) -> DescriptorOwner {
        self.owner
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegistryError {
    EmptyName,
    InvalidName,
    EmptySourceSet,
    TooManySegments,
    DuplicateName,
    TooManyDescriptors,
}

/// A closed descriptor registry.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DescriptorRegistry {
    descriptors: Vec<KeyDescriptor>,
}

#[allow(dead_code)]
impl DescriptorRegistry {
    pub(crate) fn new(descriptors: Vec<KeyDescriptor>) -> Result<Self, RegistryError> {
        if descriptors.len() > MAX_REGISTERED_KEYS {
            return Err(RegistryError::TooManyDescriptors);
        }
        for (index, descriptor) in descriptors.iter().enumerate() {
            if descriptor.name.is_empty() {
                return Err(RegistryError::EmptyName);
            }
            if AcceptedKey::new(descriptor.name.clone()).is_none() {
                return Err(RegistryError::InvalidName);
            }
            if descriptor.name.split('.').count() > 4
                || descriptor.name.split('.').any(str::is_empty)
            {
                return Err(RegistryError::TooManySegments);
            }
            if descriptor.allowed_sources.0 == 0 {
                return Err(RegistryError::EmptySourceSet);
            }
            if descriptors[..index]
                .iter()
                .any(|previous| previous.name == descriptor.name)
            {
                return Err(RegistryError::DuplicateName);
            }
        }
        Ok(Self { descriptors })
    }

    /// Builds the production registry owned by spec 005.
    pub(crate) fn production() -> Self {
        let state_dir = KeyDescriptor::new(
            "state_dir",
            ValueKind::Path,
            AllowedSources::user_and_command_line(),
            MaterialClass::NonSecret,
        )
        .with_owner(DescriptorOwner::RuntimeFoundation);
        Self::new(vec![state_dir]).expect("the production descriptor registry is valid")
    }
    pub(crate) fn descriptors(&self) -> &[KeyDescriptor] {
        &self.descriptors
    }
    pub(crate) fn descriptor(&self, name: &str) -> Option<&KeyDescriptor> {
        self.descriptors
            .iter()
            .find(|descriptor| descriptor.name == name)
    }

    /// Resolves one registered key in the contract's classification order.
    /// Lookup is deliberately per key: a secret descriptor in a fixture registry
    /// cannot poison resolution of an unrelated non-secret descriptor.
    pub(crate) fn resolve(
        &self,
        name: &str,
        source: ConfigurationSource,
    ) -> Result<&KeyDescriptor, ConfigurationFailure> {
        let descriptor = self.descriptor(name).ok_or_else(|| {
            ConfigurationFailure::unknown_key(FailureSource::Layer(source.layer_class()))
        })?;
        if descriptor.material_class != MaterialClass::NonSecret {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::SecretForbidden,
                FailureSource::Layer(source.layer_class()),
            ));
        }
        if !descriptor.allowed_sources.contains(source) {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::SourceForbidden,
                FailureSource::Layer(source.layer_class()),
            ));
        }
        Ok(descriptor)
    }
}

/// Reads one configuration stream without retaining more than the file bound.
#[allow(dead_code)]
pub(crate) fn bounded_toml_read<R: Read>(
    reader: R,
    source: FailureSource,
) -> Result<Vec<u8>, ConfigurationFailure> {
    let mut contents = Vec::with_capacity(MAX_FILE_BYTES + 1);
    reader
        .take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut contents)
        .map_err(|_| ConfigurationFailure::new(ConfigurationFailureCode::FileUnreadable, source))?;
    if contents.len() > MAX_FILE_BYTES {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::FileTooLarge,
            source,
        ));
    }
    Ok(contents)
}

/// Runs the bounded lexical pass that must precede typed TOML deserialization.
#[allow(dead_code)]
pub(crate) fn toml_lexical_preflight(
    contents: &[u8],
    source: FailureSource,
) -> Result<(), ConfigurationFailure> {
    if contents.len() > MAX_FILE_BYTES {
        return Err(ConfigurationFailure::new(
            ConfigurationFailureCode::FileTooLarge,
            source,
        ));
    }
    TomlScanner::new(contents, source).run()
}

/// Reads and preflights one configuration stream in the required order.
#[allow(dead_code)]
pub(crate) fn bounded_toml_read_and_preflight<R: Read>(
    reader: R,
    source: FailureSource,
) -> Result<Vec<u8>, ConfigurationFailure> {
    let contents = bounded_toml_read(reader, source)?;
    toml_lexical_preflight(&contents, source)?;
    Ok(contents)
}

#[derive(Clone, Copy)]
enum KeyTerminator {
    Assignment,
    InlineTable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DefinitionKind {
    Assignment,
    Table,
    ArrayTable,
    InlineTable,
}

struct StructuralDefinition {
    path: Vec<String>,
    scope: Option<usize>,
    kind: DefinitionKind,
}

struct TomlScanner<'a> {
    input: &'a [u8],
    source: FailureSource,
    assignments: usize,
    table_prefix: Vec<String>,
    active_array_scope: Option<usize>,
    array_table_root: Option<Vec<String>>,
    next_array_scope: usize,
    definitions: Vec<StructuralDefinition>,
}

impl<'a> TomlScanner<'a> {
    fn new(input: &'a [u8], source: FailureSource) -> Self {
        Self {
            input,
            source,
            assignments: 0,
            table_prefix: Vec::new(),
            active_array_scope: None,
            array_table_root: None,
            next_array_scope: 0,
            definitions: Vec::new(),
        }
    }

    fn run(mut self) -> Result<(), ConfigurationFailure> {
        let mut position = 0;
        while position < self.input.len() {
            self.skip_layout(&mut position);
            if position >= self.input.len() {
                break;
            }
            if self.input[position] == b'[' {
                self.scan_table_header(&mut position)?;
                continue;
            }
            let Some((key, equals)) = self.parse_key(&mut position, KeyTerminator::Assignment)?
            else {
                self.skip_line(&mut position);
                continue;
            };
            let full_key = self.join_path(&self.table_prefix, &key)?;
            let scope = self.active_array_scope;
            self.register_assignment(full_key.clone(), scope, false)?;
            position = equals + 1;
            self.scan_value(&mut position, &full_key, 0, scope, false)?;
        }
        Ok(())
    }

    fn scan_table_header(&mut self, position: &mut usize) -> Result<(), ConfigurationFailure> {
        let array_table = self.input.get(*position..*position + 2) == Some(b"[[");
        *position += if array_table { 2 } else { 1 };
        let mut path = Vec::new();
        loop {
            self.skip_horizontal(position);
            let Some((segment, next)) = self.parse_key_segment(*position) else {
                self.skip_line(position);
                return Ok(());
            };
            path.push(segment);
            if path.len() > MAX_DOTTED_SEGMENTS {
                return Err(self.limit_failure());
            }
            *position = next;
            self.skip_horizontal(position);
            if self
                .input
                .get(*position..*position + if array_table { 2 } else { 1 })
                == Some(if array_table { b"]]" } else { b"]" })
            {
                *position += if array_table { 2 } else { 1 };
                let scope = if array_table {
                    None
                } else {
                    self.array_scope_for_path(&path)
                };
                self.register_table(&path, array_table, scope)?;
                self.table_prefix = path.clone();
                if array_table {
                    self.active_array_scope = Some(self.next_array_scope);
                    self.next_array_scope += 1;
                    self.array_table_root = Some(path);
                } else {
                    self.active_array_scope = scope;
                    if scope.is_none() {
                        self.array_table_root = None;
                    }
                }
                self.skip_line(position);
                return Ok(());
            }
            if self.input.get(*position) == Some(&b'.') {
                *position += 1;
                continue;
            }
            self.skip_line(position);
            return Ok(());
        }
    }

    fn scan_value(
        &mut self,
        position: &mut usize,
        context: &[String],
        depth: usize,
        scope: Option<usize>,
        inside_inline: bool,
    ) -> Result<(), ConfigurationFailure> {
        if depth > MAX_LEXICAL_NESTING {
            return Err(self.limit_failure());
        }
        loop {
            self.skip_horizontal(position);
            let Some(&byte) = self.input.get(*position) else {
                return Ok(());
            };
            match byte {
                b'\n' | b'\r' | b',' | b']' | b'}' => return Ok(()),
                b'#' => {
                    self.skip_line(position);
                    return Ok(());
                }
                b'"' | b'\'' => {
                    self.scan_string(position)?;
                }
                b'[' => {
                    self.scan_array(position, context, depth + 1, scope, inside_inline)?;
                }
                b'{' => {
                    self.mark_inline_table(context, scope);
                    self.scan_inline_table(position, context, depth + 1, scope)?;
                }
                _ => *position += 1,
            }
        }
    }

    fn scan_array(
        &mut self,
        position: &mut usize,
        context: &[String],
        depth: usize,
        scope: Option<usize>,
        inside_inline: bool,
    ) -> Result<(), ConfigurationFailure> {
        if depth > MAX_LEXICAL_NESTING {
            return Err(self.limit_failure());
        }
        *position += 1;
        loop {
            self.skip_layout(position);
            let Some(&byte) = self.input.get(*position) else {
                return Ok(());
            };
            if byte == b']' {
                *position += 1;
                return Ok(());
            }
            if byte == b'{' {
                self.scan_inline_table(position, context, depth + 1, scope)?;
            } else {
                self.scan_value(position, context, depth, scope, inside_inline)?;
            }
            self.skip_horizontal(position);
            match self.input.get(*position) {
                Some(b',') => *position += 1,
                Some(b']') => {
                    *position += 1;
                    return Ok(());
                }
                Some(b'\n' | b'\r' | b'#') => self.skip_layout(position),
                Some(_) => *position += 1,
                None => return Ok(()),
            }
        }
    }

    fn scan_inline_table(
        &mut self,
        position: &mut usize,
        context: &[String],
        depth: usize,
        scope: Option<usize>,
    ) -> Result<(), ConfigurationFailure> {
        if depth > MAX_LEXICAL_NESTING {
            return Err(self.limit_failure());
        }
        *position += 1;
        loop {
            self.skip_layout(position);
            let Some(&byte) = self.input.get(*position) else {
                return Ok(());
            };
            if byte == b'}' {
                *position += 1;
                return Ok(());
            }
            let Some((key, equals)) = self.parse_key(position, KeyTerminator::InlineTable)? else {
                *position += 1;
                continue;
            };
            let full_key = self.join_path(context, &key)?;
            self.register_assignment(full_key.clone(), scope, true)?;
            self.mark_inline_table(&full_key, scope);
            *position = equals + 1;
            self.scan_value(position, &full_key, depth, scope, true)?;
            self.skip_horizontal(position);
            match self.input.get(*position) {
                Some(b',') => *position += 1,
                Some(b'}') => {
                    *position += 1;
                    return Ok(());
                }
                Some(_) => *position += 1,
                None => return Ok(()),
            }
        }
    }

    fn parse_key(
        &self,
        position: &mut usize,
        terminator: KeyTerminator,
    ) -> Result<Option<(Vec<String>, usize)>, ConfigurationFailure> {
        let mut cursor = *position;
        let mut path = Vec::new();
        loop {
            while matches!(self.input.get(cursor), Some(b' ' | b'\t')) {
                cursor += 1;
            }
            let Some((segment, next)) = self.parse_key_segment(cursor) else {
                return Ok(None);
            };
            path.push(segment);
            if path.len() > MAX_DOTTED_SEGMENTS {
                return Err(self.limit_failure());
            }
            cursor = next;
            while matches!(self.input.get(cursor), Some(b' ' | b'\t')) {
                cursor += 1;
            }
            match self.input.get(cursor) {
                Some(b'.') => {
                    cursor += 1;
                }
                Some(b'=') => {
                    *position = cursor;
                    return Ok(Some((path, cursor)));
                }
                Some(b',') | Some(b'}') if matches!(terminator, KeyTerminator::InlineTable) => {
                    return Ok(None);
                }
                _ => return Ok(None),
            }
        }
    }

    fn parse_key_segment(&self, position: usize) -> Option<(String, usize)> {
        match self.input.get(position) {
            Some(b'"') => self.parse_quoted_segment(position, b'"'),
            Some(b'\'') => self.parse_quoted_segment(position, b'\''),
            Some(_) => {
                let mut end = position;
                while !matches!(
                    self.input.get(end),
                    None | Some(
                        b'.' | b'=' | b',' | b'}' | b']' | b'#' | b' ' | b'\t' | b'\r' | b'\n'
                    )
                ) {
                    end += 1;
                }
                (end > position).then(|| {
                    (
                        String::from_utf8_lossy(&self.input[position..end]).into_owned(),
                        end,
                    )
                })
            }
            None => None,
        }
    }

    fn parse_quoted_segment(&self, position: usize, quote: u8) -> Option<(String, usize)> {
        let mut cursor = position + 1;
        let mut value = String::new();
        while let Some(&byte) = self.input.get(cursor) {
            if byte == quote {
                return Some((value, cursor + 1));
            }
            if quote == b'"' && byte == b'\\' {
                cursor += 1;
                self.append_escape(&mut cursor, &mut value);
            } else {
                let (character, width) = next_character(&self.input[cursor..]);
                value.push(character);
                cursor += width;
            }
        }
        None
    }

    fn append_escape(&self, cursor: &mut usize, value: &mut String) {
        let Some(&escape) = self.input.get(*cursor) else {
            return;
        };
        *cursor += 1;
        match escape {
            b'b' => value.push('\u{0008}'),
            b't' => value.push('\t'),
            b'n' => value.push('\n'),
            b'f' => value.push('\u{000c}'),
            b'r' => value.push('\r'),
            b'u' => self.append_unicode_escape(cursor, value, 4),
            b'U' => self.append_unicode_escape(cursor, value, 8),
            other => value.push(other as char),
        }
    }

    fn append_unicode_escape(&self, cursor: &mut usize, value: &mut String, digits: usize) {
        let start = *cursor;
        let end = start.saturating_add(digits).min(self.input.len());
        let mut number = 0u32;
        let mut valid = end - start == digits;
        for &byte in &self.input[start..end] {
            let Some(digit) = hex_digit(byte) else {
                valid = false;
                break;
            };
            number = number.saturating_mul(16).saturating_add(digit as u32);
        }
        *cursor = end;
        if valid {
            if let Some(character) = char::from_u32(number) {
                value.push(character);
                return;
            }
        }
        value.push('\u{fffd}');
    }

    fn scan_string(&self, position: &mut usize) -> Result<(), ConfigurationFailure> {
        let quote = self.input[*position];
        let multiline = self.input.get(*position..*position + 3) == Some(&[quote, quote, quote]);
        *position += if multiline { 3 } else { 1 };
        if multiline {
            consume_initial_newline(self.input, position);
        }
        let mut scalar_count = 0;
        loop {
            if *position >= self.input.len() {
                return Ok(());
            }
            if multiline && self.input.get(*position..*position + 3) == Some(&[quote, quote, quote])
            {
                *position += 3;
                return Ok(());
            }
            let byte = self.input[*position];
            if !multiline && byte == quote {
                *position += 1;
                return Ok(());
            }
            if !multiline && matches!(byte, b'\r' | b'\n') {
                return Ok(());
            }
            if quote == b'"' && byte == b'\\' {
                *position += 1;
                self.scan_string_escape(position, &mut scalar_count, multiline)?;
            } else {
                let (_, width) = next_character(&self.input[*position..]);
                *position += width;
                scalar_count = scalar_count.saturating_add(1);
                if scalar_count > MAX_TEXT_SCALARS {
                    return Err(self.limit_failure());
                }
            }
        }
    }

    fn scan_string_escape(
        &self,
        position: &mut usize,
        scalar_count: &mut usize,
        multiline: bool,
    ) -> Result<(), ConfigurationFailure> {
        let Some(&escape) = self.input.get(*position) else {
            return Ok(());
        };
        if multiline && matches!(escape, b'\r' | b'\n') {
            consume_line_continuation(self.input, position);
            return Ok(());
        }
        if matches!(escape, b'u' | b'U') {
            *position += 1;
            let digits = if escape == b'u' { 4 } else { 8 };
            for _ in 0..digits {
                if self.input.get(*position).is_some() {
                    *position += 1;
                }
            }
        } else {
            *position += next_character(&self.input[*position..]).1;
        }
        *scalar_count = scalar_count.saturating_add(1);
        if *scalar_count > MAX_TEXT_SCALARS {
            return Err(self.limit_failure());
        }
        Ok(())
    }

    fn join_path(
        &self,
        prefix: &[String],
        suffix: &[String],
    ) -> Result<Vec<String>, ConfigurationFailure> {
        if prefix.len().saturating_add(suffix.len()) > MAX_DOTTED_SEGMENTS {
            return Err(self.limit_failure());
        }
        let mut result = Vec::with_capacity(prefix.len() + suffix.len());
        result.extend(prefix.iter().cloned());
        result.extend(suffix.iter().cloned());
        Ok(result)
    }

    fn register_assignment(
        &mut self,
        path: Vec<String>,
        scope: Option<usize>,
        inside_inline: bool,
    ) -> Result<(), ConfigurationFailure> {
        if self.assignments >= MAX_ASSIGNMENTS {
            return Err(self.limit_failure());
        }
        self.register_definition(path, scope, DefinitionKind::Assignment, inside_inline)?;
        self.assignments += 1;
        Ok(())
    }

    fn register_table(
        &mut self,
        path: &[String],
        array_table: bool,
        scope: Option<usize>,
    ) -> Result<(), ConfigurationFailure> {
        let kind = if array_table {
            DefinitionKind::ArrayTable
        } else {
            DefinitionKind::Table
        };
        if array_table
            && self.definitions.iter().any(|definition| {
                definition.path == path
                    && definition.kind == DefinitionKind::ArrayTable
                    && Self::scopes_overlap(definition.scope, scope)
            })
        {
            return Ok(());
        }
        self.register_definition(path.to_vec(), scope, kind, false)
    }

    fn register_definition(
        &mut self,
        path: Vec<String>,
        scope: Option<usize>,
        kind: DefinitionKind,
        inside_inline: bool,
    ) -> Result<(), ConfigurationFailure> {
        let duplicate = self.definitions.iter().any(|definition| {
            if !Self::scopes_overlap(definition.scope, scope) {
                return false;
            }
            if definition.path == path {
                return true;
            }
            if definition.path.len() < path.len() && path.starts_with(&definition.path) {
                return matches!(
                    definition.kind,
                    DefinitionKind::Assignment | DefinitionKind::InlineTable
                ) && !(inside_inline && definition.kind == DefinitionKind::InlineTable);
            }
            if path.len() < definition.path.len() && definition.path.starts_with(&path) {
                return true;
            }
            false
        });
        if duplicate {
            return Err(ConfigurationFailure::new(
                ConfigurationFailureCode::KeyDuplicate,
                self.source,
            ));
        }
        self.definitions
            .push(StructuralDefinition { path, scope, kind });
        Ok(())
    }

    fn mark_inline_table(&mut self, path: &[String], scope: Option<usize>) {
        let matching = self.definitions.iter_mut().rev().find(|definition| {
            definition.path == path
                && definition.kind == DefinitionKind::Assignment
                && Self::scopes_overlap(definition.scope, scope)
        });
        if let Some(definition) = matching {
            definition.kind = DefinitionKind::InlineTable;
        }
    }

    fn scopes_overlap(left: Option<usize>, right: Option<usize>) -> bool {
        left.is_none() || right.is_none() || left == right
    }

    fn array_scope_for_path(&self, path: &[String]) -> Option<usize> {
        match (&self.array_table_root, self.active_array_scope) {
            (Some(root), Some(scope)) if path.starts_with(root) => Some(scope),
            _ => None,
        }
    }

    fn limit_failure(&self) -> ConfigurationFailure {
        ConfigurationFailure::new(ConfigurationFailureCode::LimitExceeded, self.source)
    }

    fn skip_horizontal(&self, position: &mut usize) {
        while matches!(self.input.get(*position), Some(b' ' | b'\t')) {
            *position += 1;
        }
    }

    fn skip_layout(&self, position: &mut usize) {
        loop {
            self.skip_horizontal(position);
            match self.input.get(*position) {
                Some(b'\r' | b'\n') => *position += 1,
                Some(b'#') => self.skip_line(position),
                _ => return,
            }
        }
    }

    fn skip_line(&self, position: &mut usize) {
        while !matches!(self.input.get(*position), None | Some(b'\r' | b'\n')) {
            *position += 1;
        }
    }
}

fn next_character(input: &[u8]) -> (char, usize) {
    let Some(&first) = input.first() else {
        return ('\u{fffd}', 1);
    };
    let width = match first {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 1,
    };
    let end = width.min(input.len());
    std::str::from_utf8(&input[..end])
        .ok()
        .and_then(|text| text.chars().next().map(|character| (character, width)))
        .unwrap_or(('\u{fffd}', 1))
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn consume_initial_newline(input: &[u8], position: &mut usize) {
    if input.get(*position) == Some(&b'\r') {
        *position += 1;
        if input.get(*position) == Some(&b'\n') {
            *position += 1;
        }
    } else if input.get(*position) == Some(&b'\n') {
        *position += 1;
    }
}

fn consume_line_continuation(input: &[u8], position: &mut usize) {
    consume_initial_newline(input, position);
    while matches!(input.get(*position), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        *position += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::LayerClass;
    use std::fmt::Write as _;
    use std::io::Cursor;
    fn descriptor(name: impl Into<String>) -> KeyDescriptor {
        KeyDescriptor::new(
            name,
            ValueKind::Text,
            AllowedSources::all(),
            MaterialClass::NonSecret,
        )
    }
    fn registry_with_count(count: usize) -> DescriptorRegistry {
        DescriptorRegistry::new(
            (0..count)
                .map(|index| descriptor(format!("key_{index}")))
                .collect(),
        )
        .expect("fixture registry should be valid")
    }

    #[test]
    fn production_registry_contains_only_non_secret_descriptors() {
        let registry = DescriptorRegistry::production();
        assert!(!registry.descriptors().is_empty());
        assert!(
            registry
                .descriptors()
                .iter()
                .all(|descriptor| descriptor.material_class() == MaterialClass::NonSecret)
        );
    }
    #[test]
    fn production_state_dir_is_owned_by_runtime_foundation() {
        let registry = DescriptorRegistry::production();
        let state_dir = registry
            .descriptor("state_dir")
            .expect("state_dir is registered by spec 005");
        assert_eq!(state_dir.owner(), DescriptorOwner::RuntimeFoundation);
        assert_eq!(state_dir.value_kind(), ValueKind::Path);
        assert_eq!(
            state_dir.allowed_sources(),
            AllowedSources::user_and_command_line()
        );
        assert_eq!(state_dir.material_class(), MaterialClass::NonSecret);
    }
    #[test]
    fn production_state_dir_accepts_only_its_allowed_sources() {
        let registry = DescriptorRegistry::production();
        assert!(
            registry
                .resolve("state_dir", ConfigurationSource::UserFile)
                .is_ok()
        );
        assert!(
            registry
                .resolve("state_dir", ConfigurationSource::CommandLine)
                .is_ok()
        );
        let failure = registry
            .resolve("state_dir", ConfigurationSource::ProjectFile)
            .expect_err("project files cannot select state_dir");
        assert_eq!(failure.code(), ConfigurationFailureCode::SourceForbidden);
    }
    #[test]
    fn registered_secret_class_is_rejected_for_that_key() {
        let registry = DescriptorRegistry::new(vec![KeyDescriptor::new(
            "secret",
            ValueKind::Text,
            AllowedSources::all(),
            MaterialClass::SecretMaterial,
        )])
        .expect("secret fixture is structurally valid");
        let failure = registry
            .resolve("secret", ConfigurationSource::UserFile)
            .expect_err("secret material is forbidden by spec 005");
        assert_eq!(failure.code(), ConfigurationFailureCode::SecretForbidden);
        assert_eq!(failure.source().as_str(), "user-file");
    }
    #[test]
    fn opaque_secret_reference_is_rejected_for_that_key() {
        let registry = DescriptorRegistry::new(vec![KeyDescriptor::new(
            "reference",
            ValueKind::Text,
            AllowedSources::all(),
            MaterialClass::OpaqueSecretReference,
        )])
        .expect("secret-reference fixture is structurally valid");
        let failure = registry
            .resolve("reference", ConfigurationSource::Environment)
            .expect_err("opaque secret references are not accepted by spec 005");
        assert_eq!(failure.code(), ConfigurationFailureCode::SecretForbidden);
    }
    #[test]
    fn secret_descriptor_does_not_poison_unrelated_key_resolution() {
        let registry = DescriptorRegistry::new(vec![
            KeyDescriptor::new(
                "secret",
                ValueKind::Text,
                AllowedSources::all(),
                MaterialClass::SecretMaterial,
            ),
            descriptor("ordinary"),
        ])
        .expect("mixed fixture registry is structurally valid");
        let resolved = registry
            .resolve("ordinary", ConfigurationSource::Environment)
            .expect("unrelated ordinary key remains resolvable");
        assert_eq!(resolved.name(), "ordinary");
    }
    #[test]
    fn material_class_is_not_inferred_from_arbitrary_raw_text() {
        let registry = DescriptorRegistry::new(vec![descriptor("api.token")])
            .expect("ordinary descriptor with token-like name is valid");
        let resolved = registry
            .resolve("api.token", ConfigurationSource::UserFile)
            .expect("descriptor class, not raw text, controls classification");
        assert_eq!(resolved.material_class(), MaterialClass::NonSecret);
    }
    #[test]
    fn unknown_keys_fail_before_material_or_source_checks() {
        let registry = DescriptorRegistry::production();
        let failure = registry
            .resolve("reserved.future", ConfigurationSource::ProjectFile)
            .expect_err("unregistered reserved keys are unknown");
        assert_eq!(failure.code(), ConfigurationFailureCode::KeyUnknown);
        assert_eq!(failure.source().as_str(), "project-file");
    }
    #[test]
    fn registry_accepts_exactly_100_descriptors() {
        let registry = registry_with_count(MAX_REGISTERED_KEYS);
        assert_eq!(registry.descriptors().len(), 100);
    }
    #[test]
    fn registry_rejects_101_descriptors() {
        let descriptors = (0..=MAX_REGISTERED_KEYS)
            .map(|index| descriptor(format!("key_{index}")))
            .collect();
        assert_eq!(
            DescriptorRegistry::new(descriptors),
            Err(RegistryError::TooManyDescriptors)
        );
    }
    #[test]
    fn registry_rejects_duplicate_names() {
        let result = DescriptorRegistry::new(vec![descriptor("same"), descriptor("same")]);
        assert_eq!(result, Err(RegistryError::DuplicateName));
    }
    #[test]
    fn registry_rejects_invalid_names_and_empty_sources() {
        assert_eq!(
            DescriptorRegistry::new(vec![descriptor("bad/name")]),
            Err(RegistryError::InvalidName)
        );
        assert_eq!(
            DescriptorRegistry::new(vec![KeyDescriptor::new(
                "empty",
                ValueKind::Text,
                AllowedSources::empty(),
                MaterialClass::NonSecret
            )]),
            Err(RegistryError::EmptySourceSet)
        );
    }
    #[test]
    fn registry_rejects_names_with_more_than_four_segments() {
        assert_eq!(
            DescriptorRegistry::new(vec![descriptor("one.two.three.four.five")]),
            Err(RegistryError::TooManySegments)
        );
        assert_eq!(
            DescriptorRegistry::new(vec![descriptor("one..three")]),
            Err(RegistryError::TooManySegments)
        );
    }
    #[test]
    fn source_sets_match_every_contract_source() {
        let all = AllowedSources::all();
        for source in [
            ConfigurationSource::Default,
            ConfigurationSource::UserFile,
            ConfigurationSource::ProjectFile,
            ConfigurationSource::Environment,
            ConfigurationSource::CommandLine,
        ] {
            assert!(all.contains(source));
        }
        let protected = AllowedSources::user_and_command_line();
        assert!(!protected.contains(ConfigurationSource::Default));
        assert!(protected.contains(ConfigurationSource::UserFile));
        assert!(!protected.contains(ConfigurationSource::ProjectFile));
        assert!(!protected.contains(ConfigurationSource::Environment));
        assert!(protected.contains(ConfigurationSource::CommandLine));
    }
    #[test]
    fn bounded_read_enforces_exact_file_byte_limit() {
        const FILE_LIMIT: usize = 1024 * 1024;
        let source = FailureSource::Layer(LayerClass::UserFile);

        let exact = bounded_toml_read(Cursor::new(vec![b'x'; FILE_LIMIT]), source)
            .expect("a file at the byte limit is accepted");
        assert_eq!(exact.len(), FILE_LIMIT);

        let failure = bounded_toml_read(Cursor::new(vec![b'x'; FILE_LIMIT + 1]), source)
            .expect_err("a file over the byte limit is rejected");
        assert_eq!(failure.code(), ConfigurationFailureCode::FileTooLarge);
    }

    #[test]
    fn lexical_preflight_enforces_exact_assignment_limit() {
        const ASSIGNMENT_LIMIT: usize = 100;
        let source = FailureSource::Layer(LayerClass::UserFile);
        let document = |count: usize| {
            let mut document = String::new();
            for index in 0..count {
                writeln!(document, "key_{index} = {index}").expect("writing to String cannot fail");
            }
            document
        };

        assert!(toml_lexical_preflight(document(ASSIGNMENT_LIMIT).as_bytes(), source).is_ok());
        let failure = toml_lexical_preflight(document(ASSIGNMENT_LIMIT + 1).as_bytes(), source)
            .expect_err("the assignment after the limit is rejected");
        assert_eq!(failure.code(), ConfigurationFailureCode::LimitExceeded);
    }

    #[test]
    fn lexical_preflight_enforces_exact_dotted_segment_limit() {
        let source = FailureSource::Layer(LayerClass::UserFile);

        assert!(toml_lexical_preflight(b"one.two.three.four = \"ok\"\n", source).is_ok());
        let failure = toml_lexical_preflight(b"one.two.three.four.five = \"too-deep\"\n", source)
            .expect_err("the fifth dotted segment is rejected");
        assert_eq!(failure.code(), ConfigurationFailureCode::LimitExceeded);
    }

    #[test]
    fn lexical_preflight_enforces_exact_text_scalar_limit() {
        const TEXT_SCALAR_LIMIT: usize = 4_096;
        let source = FailureSource::Layer(LayerClass::UserFile);
        let document = |count: usize| format!("text = \"{}\"\n", "x".repeat(count));

        assert!(toml_lexical_preflight(document(TEXT_SCALAR_LIMIT).as_bytes(), source).is_ok());
        let failure = toml_lexical_preflight(document(TEXT_SCALAR_LIMIT + 1).as_bytes(), source)
            .expect_err("the scalar after the limit is rejected");
        assert_eq!(failure.code(), ConfigurationFailureCode::LimitExceeded);
    }

    #[test]
    fn lexical_preflight_detects_duplicates_per_table_scope() {
        let source = FailureSource::Layer(LayerClass::UserFile);
        assert!(
            toml_lexical_preflight(b"[first]\nvalue = 1\n[second]\nvalue = 2\n", source,).is_ok()
        );

        let failure = toml_lexical_preflight(b"[first]\nvalue = 1\nvalue = 2\n", source)
            .expect_err("a repeated key in one table scope is rejected");
        assert_eq!(failure.code(), ConfigurationFailureCode::KeyDuplicate);
    }

    #[test]
    fn lexical_preflight_rejects_reentered_table_definition() {
        let source = FailureSource::Layer(LayerClass::UserFile);
        let failure = toml_lexical_preflight(b"[first]\nvalue = 1\n[first]\nvalue = 2\n", source)
            .expect_err("re-entering a table definition is rejected");
        assert_eq!(failure.code(), ConfigurationFailureCode::KeyDuplicate);
    }

    #[test]
    fn lexical_preflight_rejects_dotted_key_table_collision() {
        let source = FailureSource::Layer(LayerClass::UserFile);
        let failure = toml_lexical_preflight(b"first.value = 1\n[first]\nvalue = 2\n", source)
            .expect_err("a dotted key and table definition cannot collide");
        assert_eq!(failure.code(), ConfigurationFailureCode::KeyDuplicate);
    }

    #[test]
    fn lexical_preflight_rejects_inline_table_key_collision() {
        let source = FailureSource::Layer(LayerClass::UserFile);
        let failure = toml_lexical_preflight(b"first.value = 1\nfirst = { value = 2 }\n", source)
            .expect_err("a dotted key and inline table cannot collide");
        assert_eq!(failure.code(), ConfigurationFailureCode::KeyDuplicate);
    }

    #[test]
    fn lexical_preflight_covers_toml_edge_cases() {
        let source = FailureSource::Layer(LayerClass::UserFile);
        let mut pathological = vec![b'['; MAX_FILE_BYTES + 1];
        pathological[MAX_FILE_BYTES] = b']';
        let mut invalid_utf8 = b"value = \"".to_vec();
        invalid_utf8.push(0xff);
        invalid_utf8.extend_from_slice(b"\"\n");
        let cases = vec![
            (
                "literal string",
                b"value = 'literal # [syntax] \"quote\"'\n".to_vec(),
                None,
            ),
            (
                "multiline basic string",
                b"value = \"\"\"multi\nline\"\"\"\n".to_vec(),
                None,
            ),
            (
                "multiline literal string",
                b"value = \x27\x27\x27multi\nline\x27\x27\x27\n".to_vec(),
                None,
            ),
            (
                "escaped quotes",
                b"value = \"escaped \\\"quote\\\"\"\n".to_vec(),
                None,
            ),
            (
                "unicode escape at end of input",
                b"value = \"\\u".to_vec(),
                None,
            ),
            (
                "long unicode escape at end of input",
                b"value = \"\\U".to_vec(),
                None,
            ),
            (
                "multiline line continuation",
                b"value = \"\"\"first\\\n    second\"\"\"\n".to_vec(),
                None,
            ),
            (
                "comment containing syntax",
                b"# [first]\n# value = 1\nvalue = 2\n".to_vec(),
                None,
            ),
            (
                "inline table",
                b"value = { nested = 1, text = 'ok' }\n".to_vec(),
                None,
            ),
            (
                "array of table headers",
                b"[[items]]\nvalue = 1\n[[items]]\nvalue = 2\n".to_vec(),
                None,
            ),
            (
                "quoted keys",
                b"\"quoted.key\" = 1\n[\"quoted table\"]\nvalue = 2\n".to_vec(),
                None,
            ),
            (
                "non-ascii text",
                "value = \"café\"\n".as_bytes().to_vec(),
                None,
            ),
            ("invalid utf8", invalid_utf8, None),
            (
                "unterminated string",
                b"value = \"unterminated".to_vec(),
                None,
            ),
            (
                "unterminated inline table",
                b"value = { nested = 1".to_vec(),
                None,
            ),
            (
                "pathological one mib boundary",
                pathological,
                Some(ConfigurationFailureCode::FileTooLarge),
            ),
        ];

        for (name, document, expected_failure) in cases {
            let result = bounded_toml_read_and_preflight(Cursor::new(document), source);
            match expected_failure {
                Some(code) => assert_eq!(
                    result.expect_err(name).code(),
                    code,
                    "{name} should return its closed failure",
                ),
                None => assert!(result.is_ok(), "{name} should survive lexical preflight"),
            }
        }
    }
}
