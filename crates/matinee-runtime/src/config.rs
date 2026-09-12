//! Typed configuration descriptors and the closed spec-005 registry.
//!
//! Configuration values are classified by their descriptor, never by inspecting
//! arbitrary input text. The registry is intentionally small and closed: adding
//! a key requires adding a descriptor with an explicit material class, source
//! policy, and value shape.

use crate::environment::{AcceptedKey, ConfigurationSource};
use crate::error::{ConfigurationFailure, ConfigurationFailureCode, FailureSource};

/// The maximum number of descriptors accepted by one registry.
#[allow(dead_code)]
pub(crate) const MAX_REGISTERED_KEYS: usize = 100;

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

#[cfg(test)]
mod tests {
    use super::*;
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
    fn descriptor_retains_typed_policy_fields() {
        let descriptor = KeyDescriptor::new(
            "display_name",
            ValueKind::Text,
            AllowedSources::all(),
            MaterialClass::NonSecret,
        )
        .with_default(DescriptorDefault::Text("Matinee".to_owned()))
        .with_sensitive(true)
        .with_normalizer(Normalizer::TrimAsciiWhitespace)
        .with_owner(DescriptorOwner::RuntimeFoundation);
        assert_eq!(descriptor.name(), "display_name");
        assert_eq!(descriptor.value_kind(), ValueKind::Text);
        assert_eq!(
            descriptor.default(),
            Some(&DescriptorDefault::Text("Matinee".to_owned()))
        );
        assert!(descriptor.sensitive());
        assert_eq!(descriptor.normalizer(), Normalizer::TrimAsciiWhitespace);
        assert_eq!(descriptor.owner(), DescriptorOwner::RuntimeFoundation);
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
    fn every_material_class_is_explicitly_distinct() {
        assert_ne!(
            MaterialClass::NonSecret,
            MaterialClass::OpaqueSecretReference
        );
        assert_ne!(MaterialClass::NonSecret, MaterialClass::SecretMaterial);
        assert_ne!(
            MaterialClass::OpaqueSecretReference,
            MaterialClass::SecretMaterial
        );
    }
}
