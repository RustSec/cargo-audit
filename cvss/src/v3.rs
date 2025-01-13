//! Common Vulnerability Scoring System (v3.1)
//!
//! <https://www.first.org/cvss/specification-document>

// TODO(tarcieri): Environmental and Temporal Metrics

pub mod base;
#[allow(missing_docs)]
pub mod cvss;
#[allow(missing_docs)]
pub mod environmental;
mod score;
#[allow(missing_docs)]
pub mod temporal;

pub use self::{base::Base, score::Score};
