// SPDX-License-Identifier: GPL-3.0-or-later
//! Verified mapped-object inputs and finite provider observation facts.
//! Discovery does not establish activation, execution, or policy compliance.
mod assembly;
pub mod objects;
pub mod schema;
pub use objects::{
    ApiSite, TransientCodeAddress, VerifiedProcess, VerifiedSite, acquire,
    inspect_expected_exports, inspect_exports,
};
pub use schema::*;

pub mod session;
pub mod wire;
pub use session::{ObservationBatch, ProviderSession, VerifiedSiteCandidate};
