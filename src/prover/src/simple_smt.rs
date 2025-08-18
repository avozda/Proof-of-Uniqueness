use ff_ce::PrimeField;
use num_bigint::BigUint;
use num_traits::Num;
use poseidon_rs::{Fr, Poseidon};
use rocksdb::{DB, Options};
use std::path::Path;

const SMT_DEPTH: usize = 254; // Exactly what we need for BN254

pub struct SimpleSMT {
    db: DB,
    poseidon: Poseidon,
}

impl SimpleSMT {
    /// Create a new 254-bit depth SMT
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, db_path)?;

        Ok(SimpleSMT {
            db,
            poseidon: Poseidon::new(),
        })
    }

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

    /// Get the binary path for a key (254 bits, LSB first)
    fn key_to_path(key: &BigUint) -> Vec<bool> {
        let mut bits = Vec::with_capacity(SMT_DEPTH);
        let mut value = key.clone();

        for _ in 0..SMT_DEPTH {
            bits.push(&value & BigUint::from(1u32) == BigUint::from(1u32));
            value >>= 1;
        }

        bits
    }

    /// Get node from database at binary path
    fn get_node(&self, path: &str) -> Result<Option<BigUint>, Box<dyn std::error::Error>> {
        match self.db.get(path.as_bytes())? {
            Some(bytes) => {
                if bytes.len() == 32 {
                    Ok(Some(BigUint::from_bytes_be(&bytes)))
                } else {
                    Err("Invalid node data length".into())
                }
            }
            None => Ok(None),
        }
    }

    /// Set node in database at binary path
    fn set_node(&self, path: &str, value: &BigUint) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = {
            let value_bytes = value.to_bytes_be();
            let mut arr = [0u8; 32];
            let len = std::cmp::min(value_bytes.len(), 32);
            arr[32 - len..].copy_from_slice(&value_bytes[value_bytes.len() - len..]);
            arr
        };
        self.db.put(path.as_bytes(), &bytes)?;
        Ok(())
    }

    /// Hash two children
    fn hash_children(
        &self,
        left: &BigUint,
        right: &BigUint,
    ) -> Result<BigUint, Box<dyn std::error::Error>> {
        let left_fr = Self::bigint_to_fr(left);
        let right_fr = Self::bigint_to_fr(right);
        let result_fr = self.poseidon.hash(vec![left_fr, right_fr])?;
        Ok(Self::fr_to_bigint(&result_fr))
    }

    /// Insert a key-value pair and return the new root
    pub fn insert(
        &mut self,
        key: &BigUint,
        value: &BigUint,
    ) -> Result<BigUint, Box<dyn std::error::Error>> {
        println!("🔄 Inserting key {} with value {}", key, value);

        let path_bits = Self::key_to_path(key);

        // Store the leaf value at the full path
        let leaf_path = format!("leaf_{}", key);
        self.set_node(&leaf_path, value)?;

        // Recompute the root by traversing the tree structure
        let root = self.compute_root_from_key(&path_bits)?;

        // Store root
        self.db.put(b"root", &{
            let root_bytes = root.to_bytes_be();
            let mut arr = [0u8; 32];
            let len = std::cmp::min(root_bytes.len(), 32);
            arr[32 - len..].copy_from_slice(&root_bytes[root_bytes.len() - len..]);
            arr
        })?;

        println!("✅ New root: {}", root);
        Ok(root)
    }

    /// Compute root by recursively computing tree from inserted leaves
    fn compute_root_from_key(
        &self,
        path_bits: &[bool],
    ) -> Result<BigUint, Box<dyn std::error::Error>> {
        self.compute_subtree_hash(path_bits, 0)
    }

    /// Recursively compute subtree hash
    fn compute_subtree_hash(
        &self,
        path_bits: &[bool],
        level: usize,
    ) -> Result<BigUint, Box<dyn std::error::Error>> {
        if level == SMT_DEPTH {
            // We've reached a leaf level - check if this path has a value
            let key = self.path_to_key(path_bits);
            let leaf_path = format!("leaf_{}", key);

            match self.get_node(&leaf_path)? {
                Some(value) => Ok(value),
                None => Ok(BigUint::from(0u32)), // Empty leaf
            }
        } else {
            // Internal node - compute from children
            let mut left_path = path_bits.to_vec();
            left_path.push(false);
            let mut right_path = path_bits.to_vec();
            right_path.push(true);

            let left_hash = self.compute_subtree_hash(&left_path, level + 1)?;
            let right_hash = self.compute_subtree_hash(&right_path, level + 1)?;

            self.hash_children(&left_hash, &right_hash)
        }
    }

    /// Convert path bits back to key
    fn path_to_key(&self, path_bits: &[bool]) -> BigUint {
        let mut key = BigUint::from(0u32);
        for (i, &bit) in path_bits.iter().enumerate() {
            if bit {
                key |= BigUint::from(1u32) << i;
            }
        }
        key
    }

    /// Get the current root
    pub fn get_root(&self) -> Result<BigUint, Box<dyn std::error::Error>> {
        match self.db.get(b"root")? {
            Some(bytes) => {
                if bytes.len() == 32 {
                    Ok(BigUint::from_bytes_be(&bytes))
                } else {
                    Err("Invalid root data length".into())
                }
            }
            None => Ok(BigUint::from(0u32)), // Empty tree
        }
    }

    /// Generate siblings proof for a key (exactly 254 siblings)
    pub fn generate_proof(
        &self,
        key: &BigUint,
    ) -> Result<[BigUint; 254], Box<dyn std::error::Error>> {
        println!("🔧 Generating 254-level proof for key: {}", key);

        let path_bits = Self::key_to_path(key);
        let mut siblings = Vec::with_capacity(SMT_DEPTH);

        // Generate siblings from leaf to root (level 0 to 253)
        for level in 0..SMT_DEPTH {
            // Sibling path: same path up to level, then flip the bit at this level
            let mut sibling_path = path_bits[0..level].to_vec();
            sibling_path.push(!path_bits[level]);

            // Compute the sibling subtree hash
            let sibling_hash = self.compute_subtree_hash(&sibling_path, level + 1)?;
            siblings.push(sibling_hash);
        }

        let siblings_array: [BigUint; 254] = siblings
            .try_into()
            .map_err(|_| "Failed to convert siblings to array")?;

        println!("✅ Generated exactly {} siblings", siblings_array.len());
        println!(
            "   First few siblings: {:?}",
            &siblings_array[0..3.min(siblings_array.len())]
        );

        Ok(siblings_array)
    }

    /// Check if a key exists in the tree
    pub fn contains_key(&self, key: &BigUint) -> Result<bool, Box<dyn std::error::Error>> {
        let leaf_path = format!("leaf_{}", key);
        Ok(self.get_node(&leaf_path)?.is_some())
    }
}
