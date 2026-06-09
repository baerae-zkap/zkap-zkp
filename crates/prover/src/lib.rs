//! ZKAP release staging utilities.
//!
//! Native proof generation runs through the `zkap-service` façade:
//! downstream SDKs load `zkap_service::ArtifactSet` and call
//! `zkap_service::prove_bundles(..., PreflightMode::VerifyAfter)` /
//! `zkap_service::verify(...)`. `ark-ar1cs` is an internal detail of the
//! façade, no longer a direct SDK dependency. This crate only stages flat
//! zkap-circuit release bundles into manifest-compatible directories.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod release;

pub use error::ReleaseError;
pub use release::{load_release, load_witness_gen, LoadedRelease};
