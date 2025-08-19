use num_bigint::BigUint;
use std::path::Path;

// Import our custom 254-bit SMT modules
pub mod bits;
pub mod database;
pub mod hasher;
pub mod lib;
pub mod node;
pub mod tree;
#[macro_use]
pub mod utils;

// Re-export main types
pub use database::RocksDB;
pub use hasher::{Hasher, PoseidonHasher};
pub use lib::{HASH_LEN, Hash};
pub use tree::Monotree;

use std::collections::HashMap;

/// Wrapper for our custom 254-bit SMT to maintain compatibility with existing code
pub struct SparseMerkleTree {
    tree: Monotree<RocksDB, PoseidonHasher>,
    circomlib_root: BigUint, // Track circomlib-compatible root separately
    // Track inserted keys for proper siblings generation
    inserted_keys: HashMap<BigUint, BigUint>, // key -> value pairs
}

impl SparseMerkleTree {
    /// Create or open an existing 254-bit sparse merkle tree
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let path = db_path.as_ref();
        let path_str = path.to_string_lossy().to_string();

        // Initialize our custom 254-bit SMT
        let tree = Monotree::<RocksDB, PoseidonHasher>::new(&path_str);
        let mut smt = SparseMerkleTree {
            tree,
            circomlib_root: BigUint::from(0u32), // Start with empty root
            inserted_keys: HashMap::new(),
        };

        let _ = smt.print_root();

        Ok(smt)
    }

    /// Print the root hash in uint256 format
    pub fn print_root(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self.tree.get_headroot()? {
            Some(root) => {
                let root_bigint = BigUint::from_bytes_be(&root);
                println!("🌳 SMT Root: {}", root_bigint);
            }
            None => {
                println!("🌳 SMT Root: 0 (empty)");
            }
        }
        Ok(())
    }

    /// Get the current circomlib-compatible root as BigUint
    #[allow(dead_code)]
    pub fn get_root_as_biguint(&mut self) -> BigUint {
        self.circomlib_root.clone()
    }

    /// Set the root directly (for syncing with contract)
    pub fn set_root(&mut self, root: &BigUint) {
        self.circomlib_root = root.clone();
    }

    /// Insert a hash_id into the SMT and return the new root
    /// Uses circomlib-compatible hashing
    pub fn insert_hash_id(
        &mut self,
        hash_id: &BigUint,
    ) -> Result<BigUint, Box<dyn std::error::Error>> {
        // Convert hash_id to key format
        let key = self.bigint_to_hash(hash_id);
        // Value is always 1 for circomlib compatibility
        let value = self.bigint_to_hash(&BigUint::from(1u32));

        // Get current root
        let current_root = self.tree.get_headroot()?;

        // Store in monotree for proof generation (uses monotree's hashing)
        let _monotree_root = self.tree.insert(current_root.as_ref(), &key, &value)?;

        // Calculate circomlib-compatible root
        let empty_root = [0u8; 32];
        let root_ref = current_root.as_ref().unwrap_or(&empty_root);
        let circomlib_root = self.tree.insert_circomlib(root_ref, &key, &value)?;

        // Set the monotree root as head for proof generation
        self.tree.set_headroot(_monotree_root.as_ref());

        // Update our circomlib root
        self.circomlib_root = match circomlib_root {
            Some(root) => BigUint::from_bytes_be(&root),
            None => BigUint::from(0u32),
        };

        // Track the inserted key for siblings generation
        self.inserted_keys
            .insert(hash_id.clone(), BigUint::from(1u32));

        Ok(self.circomlib_root.clone())
    }

    /// Generate siblings proof for a given hash_id (key)
    /// Returns array of exactly 254 siblings for the merkle proof
    pub fn generate_siblings_proof(
        &mut self,
        hash_id: &BigUint,
    ) -> Result<[BigUint; 254], Box<dyn std::error::Error>> {
        // Generate circomlib-compatible siblings based on current tree state
        let siblings = self.generate_circomlib_siblings(hash_id)?;
        Ok(siblings)
    }

    /// Generate circomlib-compatible siblings proof
    /// This implements proper binary SMT siblings for the full merkle path
    fn generate_circomlib_siblings(
        &self,
        new_key: &BigUint,
    ) -> Result<[BigUint; 254], Box<dyn std::error::Error>> {
        let mut siblings = std::array::from_fn(|_| BigUint::from(0u32));

        if self.inserted_keys.is_empty() {
            // Empty tree - all siblings are 0
            return Ok(siblings);
        }

        // Handle trees with existing elements
        if self.inserted_keys.len() >= 1 {
            let hasher = PoseidonHasher::new();

            // Check if the key already exists (should not happen in uniqueness system)
            if self.inserted_keys.contains_key(new_key) {
                return Err("Cannot prove non-membership: key already exists in tree".into());
            }

            if self.inserted_keys.len() == 1 {
                // Tree with one element - use the existing element as reference
                let (existing_key, _value) = self.inserted_keys.iter().next().unwrap();

                // Convert keys to bit arrays for comparison
                let new_key_bits = self.bigint_to_bits(new_key);
                let existing_key_bits = self.bigint_to_bits(existing_key);

                // Find the divergence level (first level where bits differ)
                let mut divergence_level = None;
                for i in 0..254 {
                    if new_key_bits[i] != existing_key_bits[i] {
                        divergence_level = Some(i);
                        break;
                    }
                }

                if let Some(div_level) = divergence_level {
                    println!(
                        "🔍 Divergence at level {}: existing_key bit = {}, new_key bit = {}",
                        div_level, existing_key_bits[div_level], new_key_bits[div_level]
                    );

                    // Create the existing key's leaf hash
                    let existing_leaf_hash =
                        hasher.smt_hash1_bigint(existing_key, &BigUint::from(1u32));

                    // At the divergence level, the sibling is the existing key's leaf hash
                    siblings[div_level] = existing_leaf_hash.clone();

                    println!(
                        "🔍 Set sibling[{}] = {} (existing leaf hash)",
                        div_level, existing_leaf_hash
                    );

                    // All other siblings remain 0 for non-membership proof

                    // Verify by reconstructing what the root should be after insertion
                    let zero = BigUint::from(0u32);
                    let new_leaf_hash = hasher.smt_hash1_bigint(new_key, &BigUint::from(1u32));

                    // Build the tree from divergence level up
                    let mut current_hash = if new_key_bits[div_level] {
                        // new_key goes right at divergence level
                        hasher.smt_hash2_bigint(&existing_leaf_hash, &new_leaf_hash)
                    } else {
                        // new_key goes left at divergence level
                        hasher.smt_hash2_bigint(&new_leaf_hash, &existing_leaf_hash)
                    };

                    // Continue building up to root
                    for level in (div_level + 1)..254 {
                        current_hash = if new_key_bits[level] {
                            // new_key path goes right
                            hasher.smt_hash2_bigint(&zero, &current_hash)
                        } else {
                            // new_key path goes left
                            hasher.smt_hash2_bigint(&current_hash, &zero)
                        };
                    }

                    println!("🔍 Expected new root after insertion: {}", current_hash);
                    println!("🔍 Current root: {}", self.circomlib_root);
                } else {
                    // Keys are identical - this should not happen in a uniqueness system
                    return Err("Cannot prove non-membership: key already exists in tree".into());
                }
            } else {
                // Tree with multiple elements - for now, return error
                // In a full implementation, you'd need to traverse the tree structure
                return Err(
                    "Non-membership proofs for trees with multiple elements not yet implemented"
                        .into(),
                );
            }
        }

        Ok(siblings)
    }

    /// Convert BigUint to bit array (254 bits)
    /// Bits are ordered to match circomlib's Num2Bits: LSB first (little-endian)
    /// bits[0] = LSB, bits[253] = MSB (bit 253)
    fn bigint_to_bits(&self, value: &BigUint) -> [bool; 254] {
        let mut bits = [false; 254];

        // Extract bits in little-endian order to match circomlib Num2Bits
        // circomlib: out[i] <-- (in >> i) & 1
        for i in 0..254 {
            bits[i] = (value >> i) & BigUint::from(1u32) == BigUint::from(1u32);
        }

        bits
    }

    /// Check if a hash_id has been inserted
    #[allow(dead_code)]
    pub fn is_hash_id_inserted(
        &mut self,
        hash_id: &BigUint,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let key = self.bigint_to_hash(hash_id);
        let current_root = self.tree.get_headroot()?;

        match self.tree.get(current_root.as_ref(), &key)? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    /// Helper function to convert BigUint to 32-byte hash (truncated to 254 bits)
    fn bigint_to_hash(&self, value: &BigUint) -> Hash {
        // Ensure we only use 254 bits by masking out the top 2 bits
        let mask = (BigUint::from(1u32) << 254) - BigUint::from(1u32); // 2^254 - 1
        let truncated_value: BigUint = value & mask;

        let bytes = truncated_value.to_bytes_be();
        let mut hash = [0u8; HASH_LEN];

        // Ensure we don't exceed 254 bits by clearing the top 2 bits of the first byte
        let len = std::cmp::min(bytes.len(), HASH_LEN);
        hash[HASH_LEN - len..].copy_from_slice(&bytes[bytes.len() - len..]);

        // Clear the top 2 bits of the most significant byte to ensure exactly 254 bits
        if hash[0] != 0 {
            hash[0] &= 0x3F; // Clear top 2 bits: 0011_1111
        }

        hash
    }

    /// Convert merkle proof to 254-element siblings array
    fn proof_to_siblings_array(
        &self,
        proof: &[(bool, Vec<u8>)],
    ) -> Result<[BigUint; 254], Box<dyn std::error::Error>> {
        // Initialize array with zeros
        let mut siblings = std::array::from_fn(|_| BigUint::from(0u32));

        // Fill in the actual siblings from the proof
        for (level, (_, sibling_hash)) in proof.iter().enumerate() {
            if level < 254 {
                siblings[level] = BigUint::from_bytes_be(sibling_hash);
            }
        }

        Ok(siblings)
    }
}
