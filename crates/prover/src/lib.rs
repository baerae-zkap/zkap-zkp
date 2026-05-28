//! ZKAP release staging utilities.
//!
//! Native proof generation is owned by `ark-ar1cs`. Downstream SDKs load
//! `zkap-service::ArtifactSet` and pass its prepared artifacts to
//! `ark_ar1cs::prove_with_mode(..., VerifyAfter)` directly. This crate now
//! only stages flat zkap-circuit release bundles into manifest-compatible
//! directories.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod release;

pub use error::ReleaseError;
pub use release::{load_release, LoadedRelease};
