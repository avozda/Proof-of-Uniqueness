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
pub use hasher::PoseidonHasher;
pub use lib::{HASH_LEN, Hash, SMT_DEPTH};
pub use tree::Monotree;

/// Wrapper for our custom 254-bit SMT to maintain compatibility with existing code
pub struct SparseMerkleTree {
    tree: Monotree<RocksDB, PoseidonHasher>,
}

impl SparseMerkleTree {
    /// Create or open an existing 254-bit sparse merkle tree
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let path = db_path.as_ref();
        let path_str = path.to_string_lossy().to_string();

        if path.exists() && path.is_dir() {
            println!("✅ Database present - loading existing 254-bit SMT");
        } else {
            println!("❌ No database present - creating new 254-bit SMT");
        }

        // Initialize our custom 254-bit SMT
        let tree = Monotree::<RocksDB, PoseidonHasher>::new(&path_str);
        let mut smt = SparseMerkleTree { tree };

        // Print the current root
        let _ = smt.print_root();

        Ok(smt)
    }

    /// Print the root hash in uint256 format
    pub fn print_root(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self.tree.get_headroot()? {
            Some(root) => {
                let root_bigint = BigUint::from_bytes_be(&root);
                println!("🌳 SMT Root (uint256): {}", root_bigint);
            }
            None => {
                println!("🌳 SMT Root (uint256): 0 (empty tree)");
            }
        }
        println!("📝 Ready for 254-bit SMT operations!");
        Ok(())
    }

    /// Get the current root as BigUint
    pub fn get_root_as_biguint(&mut self) -> BigUint {
        match self.tree.get_headroot() {
            Ok(Some(root)) => BigUint::from_bytes_be(&root),
            _ => BigUint::from(0u32), // Empty tree or error
        }
    }

    /// Insert a hash_id into the SMT and return the new root
    pub fn insert_hash_id(
        &mut self,
        hash_id: &BigUint,
    ) -> Result<BigUint, Box<dyn std::error::Error>> {
        println!("🔄 Inserting hash_id {} into 254-bit SMT", hash_id);

        // Convert BigUint to 32-byte hash format
        let key = self.bigint_to_hash(hash_id);
        let leaf = key; // Use the same value as both key and leaf

        // Get current root
        let current_root = self.tree.get_headroot()?;

        // Insert into the tree
        let new_root = self.tree.insert(current_root.as_ref(), &key, &leaf)?;

        // Set the new root as head
        self.tree.set_headroot(new_root.as_ref());

        // Convert new root to BigUint
        let new_root_bigint = match new_root {
            Some(root) => BigUint::from_bytes_be(&root),
            None => BigUint::from(0u32),
        };

        println!("✅ Inserted hash_id, new root: {}", new_root_bigint);
        Ok(new_root_bigint)
    }

    /// Generate siblings proof for a given hash_id (key)
    /// Returns array of exactly 254 siblings for the merkle proof
    pub fn generate_siblings_proof(
        &mut self,
        hash_id: &BigUint,
    ) -> Result<[BigUint; 254], Box<dyn std::error::Error>> {
        println!(
            "🔧 Generating 254-level siblings proof for hash_id: {}",
            hash_id
        );

        // Convert BigUint to hash format
        let key = self.bigint_to_hash(hash_id);

        // Get current root
        let current_root = self.tree.get_headroot()?;

        // Generate merkle proof
        let proof_opt = self.tree.get_merkle_proof(current_root.as_ref(), &key)?;

        // Convert proof to 254-element array of BigUints
        let siblings = match proof_opt {
            Some(proof) => self.proof_to_siblings_array(&proof)?,
            None => {
                // No proof means non-membership - generate all zeros
                std::array::from_fn(|_| BigUint::from(0u32))
            }
        };

        println!(
            "✅ Generated exactly {} siblings for merkle proof",
            siblings.len()
        );
        println!(
            "   First few siblings: {:?}",
            &siblings[0..3.min(siblings.len())]
        );

        Ok(siblings)
    }

    /// Check if a hash_id has been inserted
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
        let len = std::cmp::min(bytes.len(), HASH_LEN);
        hash[HASH_LEN - len..].copy_from_slice(&bytes[bytes.len() - len..]);
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

        // For levels beyond the proof length, keep zeros (empty tree defaults)
        println!(
            "🔧 Converted proof of length {} to 254-level siblings array",
            proof.len()
        );

        Ok(siblings)
    }
}
