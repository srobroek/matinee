use matinee_runtime::{
    ConfigurationFailure, ConfigurationFailureCode, ConfigurationSource, EnvironmentInput,
    EnvironmentResult, Provenance,
};
use std::path::Path;

fn round_trip(result: EnvironmentResult<EnvironmentInput>) -> EnvironmentResult<EnvironmentInput> {
    result
}

// The resolver that produces Provenance is intentionally not public yet. Keeping this
// projection reader outside the crate still proves the opaque value's consumer methods.
fn read_provenance(provenance: &Provenance) {
    let _ = provenance.source();
    let _ = provenance.relative_path();
    let _ = provenance.key();
}

// ConfigurationFailure cannot be constructed from the six-item surface: its safe
// constructor requires the crate-private failure source. Keep this type-only carrier
// instead of asserting on an unobservable placeholder value.
fn carry_failure(failure: ConfigurationFailure) -> ConfigurationFailure {
    failure
}

#[test]
fn crate_root_exposes_environment_resolution_contract() {
    let input = EnvironmentInput::new("/workspace/project")
        .with_config_path("config.toml")
        .with_state_dir("state");
    assert_eq!(input.project_root(), Path::new("/workspace/project"));
    assert_eq!(input.config_path(), Some(Path::new("config.toml")));
    assert_eq!(input.state_dir(), Some(Path::new("state")));

    let source = ConfigurationSource::ProjectFile;
    assert_eq!(source.precedence(), 2);
    assert!(source.is_higher_than(ConfigurationSource::UserFile));
    assert_eq!(source.as_str(), "project_file");

    let result: EnvironmentResult<EnvironmentInput> = Ok(input.clone());
    assert_eq!(round_trip(result).expect("successful input"), input);
    assert_eq!(
        ConfigurationFailureCode::KeyUnknown.as_str(),
        "config.key_unknown"
    );

    let _ = read_provenance as fn(&Provenance);
    let _ = carry_failure as fn(ConfigurationFailure) -> ConfigurationFailure;
}
