#[cfg(feature = "poseidon")]
pub mod poseidon;
#[cfg(feature = "sha256")]
pub mod sha256;

#[cfg(feature = "poseidon")]
pub use poseidon::{
    FieldArity, PoseidonDomain, PoseidonFunction, PoseidonHasher, POSEIDON_CONSTANTS,
};
#[cfg(feature = "sha256")]
pub use sha256::{Sha256Domain, Sha256Function, Sha256Hasher};
