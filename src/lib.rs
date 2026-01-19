//! This instantiation of Covercrypt is based on Curve25519 and Kyber512, and as such delivers 128
//! bits of both pre- and post-quantum CCA security.
//!
//! The KEMAC defined in [1] is extended by a PKE interface using AES256-GCM as DEM in the KEM/DEM
//! framework described in [2].
//!
//! [1] "Covercrypt: an Efficient Early-Abort KEM for Hidden Access Policies with Traceability from
//! the DDH and LWE", T. Brézot, P. de Perthuis and D. Pointcheval 2023.
//! [2] "A Proposal for an ISO Standard for Public Key Encryption (version 2.1)", Shoup 2001.

mod abe;
mod data_struct;
mod error;
mod providers;
mod traits;

#[cfg(any(test, feature = "test-utils"))]
mod test_utils;

pub mod base;

pub use abe::api;
pub use abe::*;

pub use error::Error;
