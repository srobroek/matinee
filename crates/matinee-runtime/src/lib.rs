pub(crate) mod config;
pub(crate) mod environment;
pub(crate) mod error;
pub(crate) mod platform;

pub(crate) mod path_identity;
pub use environment::{ConfigurationSource, EnvironmentInput, EnvironmentResult, Provenance};
pub use error::{ConfigurationFailure, ConfigurationFailureCode};
