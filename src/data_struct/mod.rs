// Data-structures implemented here are voluntarily more exhaustive than they need to be for the
// sake of Covercrypt.
#![allow(dead_code)]

mod dictionary;
mod revision_map;
mod revision_vec;

pub mod error;
pub use dictionary::Dict;
pub use revision_map::RevisionMap;
pub use revision_vec::RevisionVec;
