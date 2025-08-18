//! A module for implementing Poseidon hash function for the 254-bit SMT.
use crate::smt::lib::*;
use ff_ce::PrimeField;
use num_bigint::BigUint;
use num_traits::Num;
use poseidon_rs::{Fr, Poseidon};

/// A trait defining hashers used for SMT
pub trait Hasher {
    fn new() -> Self;
    fn digest(&self, bytes: &[u8]) -> Hash;
}

/// A hasher using `Poseidon` hash function optimized for ZK-SNARKs
pub struct PoseidonHasher {
    poseidon: Poseidon,
}

impl Hasher for PoseidonHasher {
    fn new() -> Self {
        PoseidonHasher {
            poseidon: Poseidon::new(),
        }
    }

    fn digest(&self, bytes: &[u8]) -> Hash {
        // Convert bytes to Fr elements for Poseidon hashing
        let mut input_elements = Vec::new();

        // Process bytes in chunks of 31 (to stay within BN254 field)
        for chunk in bytes.chunks(31) {
            let mut chunk_padded = [0u8; 32];
            chunk_padded[32 - chunk.len()..].copy_from_slice(chunk);

            let big_int = BigUint::from_bytes_be(&chunk_padded);
            let fr_element = Self::bigint_to_fr(&big_int);
            input_elements.push(fr_element);
        }

        // Ensure we have at least 2 elements for Poseidon (requirement)
        if input_elements.len() < 2 {
            input_elements.push(Fr::from_str("0").unwrap());
        }

        // Hash with Poseidon
        let result_fr = self
            .poseidon
            .hash(input_elements)
            .expect("Poseidon hash failed");
        let result_bigint = Self::fr_to_bigint(&result_fr);

        // Convert back to 32-byte array
        let result_bytes = result_bigint.to_bytes_be();
        let mut hash = [0u8; HASH_LEN];
        let len = std::cmp::min(result_bytes.len(), HASH_LEN);
        hash[HASH_LEN - len..].copy_from_slice(&result_bytes[result_bytes.len() - len..]);

        hash
    }
}

impl PoseidonHasher {
    /// Convert BigUint to Fr for hashing
    fn bigint_to_fr(value: &BigUint) -> Fr {
        let fr_str = value.to_string();
        Fr::from_str(&fr_str).expect("Failed to convert BigUint to Fr")
    }

    /// Convert Fr to BigUint
    fn fr_to_bigint(fr: &Fr) -> BigUint {
        let fr_str = fr.to_string();
        // Remove "Fr(0x" prefix and ")" suffix
        let hex_str = if fr_str.starts_with("Fr(0x") && fr_str.ends_with(')') {
            &fr_str[5..fr_str.len() - 1]
        } else {
            panic!("Unexpected Fr format: {}", fr_str);
        };
        BigUint::from_str_radix(hex_str, 16).expect("Failed to parse Fr hex")
    }
}
