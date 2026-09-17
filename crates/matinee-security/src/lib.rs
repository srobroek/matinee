//! Private security implementation with a deliberately narrow crate boundary.
//!
//! Protocol framing, transcript handling, cryptographic operations, authorization
//! policy, origin validation, adapter access, and transition state remain behind
//! private modules. Consumers interact only through the typed session boundary and
//! the closed lifecycle command interface below.

// Foundational modules. These declarations are intentionally private: sibling
// implementation work fills their bodies without widening this crate's API.
mod adapters;
mod authorization;
mod channel;
mod enrollment;
mod events;
mod failures;
mod identity;
mod transition;

// The session owns validation, decryption, authorization ordering, filtering, and
// framing. Raw frames, plaintext, keys, counters, and policy helpers are not
// re-exported from this crate.
pub use channel::{AuthorizedInput, AuthorizedOutput, ChannelSession, SessionInput};

// Lifecycle changes are represented by one closed command enum. Callers cannot
// construct an open-ended command or mutate lifecycle/epoch fields directly.
pub use transition::SecurityCommand;
