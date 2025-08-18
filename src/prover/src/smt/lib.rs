//! # Custom 254-bit SMT
//! Modified Sparse Merkle Tree implementation optimized for:
//! - Exactly 254-bit depth (BN254 compatibility)
//! - Poseidon hash function only
//! - RocksDB storage only
//!
//! This is a customized version of monotree for ZK-SNARK circomlib compatibility.

/// Size of fixed length byte-array from a `Hasher`. Equivalent to `key` length.
pub const HASH_LEN: usize = 32;

/// Maximum depth of the SMT (exactly 254 bits for BN254 compatibility)
pub const SMT_DEPTH: u16 = 254;

/// A type representing length of `Bits`.
pub type BitsLen = u16;

/// A `Result` type redefined for error handling. The same as `std::result::Result<T, Errors>`.
pub type Result<T> = std::result::Result<T, Errors>;

/// A type indicating fixed length byte-array. This has the length of `HASH_LEN`.
pub type Hash = [u8; HASH_LEN];

/// A type representing a proof on `monotree`
pub type Proof = Vec<(bool, Vec<u8>)>;

/// The key to be used to restore the latest `root`
pub const ROOT_KEY: &Hash = b"_______monotree::headroot_______";

/// A generic `Error` implementation for error handling.
#[derive(Debug)]
pub struct Errors {
    details: String,
}

impl Errors {
    pub fn new(msg: &str) -> Errors {
        Errors {
            details: msg.to_string(),
        }
    }
}

impl std::fmt::Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl std::error::Error for Errors {
    fn description(&self) -> &str {
        &self.details
    }
}

// Default configuration for our 254-bit SMT
pub type DefaultDatabase = crate::smt::database::RocksDB;
pub type DefaultHasher = crate::smt::hasher::PoseidonHasher;

// Re-export key traits and types for ease of use
pub use crate::smt::bits::Bits;
pub use crate::smt::database::Database;
pub use crate::smt::hasher::Hasher;
pub use crate::smt::node::{Cell, Node, Unit};
