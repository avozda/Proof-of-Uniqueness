use ff_ce::{Field, PrimeField};
use num_bigint::BigUint;
use num_traits::{Num, One, Zero};
use poseidon_rs::{Fr, Poseidon};
use rocksdb::{DB, Options};
use std::fmt::Write as _;
use std::path::Path;
use std::str::FromStr;

/// Circom-compatible Sparse Merkle Tree, persisted in RocksDB.
struct RocksSMT {
    db: DB,
    hasher: Poseidon,
    depth: usize, // 254
}

impl RocksSMT {
    pub const DEFAULT_DEPTH: usize = 254;

    /// Open or create an SMT at `path`.
    pub fn open<P: AsRef<Path>>(path: P, depth: usize) -> Self {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path).expect("open RocksDB");
        Self {
            db,
            hasher: Poseidon::new(),
            depth,
        }
    }

    /// Current root (cached at key "root"). If missing → 0.
    pub fn root(&self) -> Fr {
        self.get_root_from_db()
    }

    /// Upsert `value` at leaf `key` (254-bit index). If `value == 0` → delete.
    /// Follows circomlib SMT logic exactly.
    pub fn upsert(&self, key: &BigUint, value: Fr) {
        // Store raw leaf value at level 0
        self.put_node(0, key, value);

        // Start accumulator from the (possibly empty) leaf
        let mut acc = if value.is_zero() {
            Fr::zero()
        } else {
            self.smt_hash1(key, value)
        };

        // Always bubble up through ALL levels to store all intermediate nodes
        // This ensures efficient proof generation
        for level in 0..self.depth {
            let idx = key >> level; // current subtree index
            let sib_idx = &idx ^ BigUint::one(); // sibling subtree index

            let sib_hash = if level == 0 {
                // Sibling is adjacent leaf (toggle LSB of full key)
                let sib_leaf_key = key ^ BigUint::one();
                let sib_leaf_val = self.get_node(0, &sib_leaf_key);
                if sib_leaf_val.is_zero() {
                    Fr::zero()
                } else {
                    self.smt_hash1(&sib_leaf_key, sib_leaf_val)
                }
            } else {
                // Internal: sibling hash already stored at this level
                self.get_node(level, &sib_idx)
            };

            // Circomlib switcher logic: bit determines left/right placement
            let bit = Self::get_bit_lsb(key, level);
            acc = if bit == 0 {
                // bit==0 => child goes left, sibling right => H(child, sibling)
                self.parent_hash_rule(acc, sib_hash)
            } else {
                // bit==1 => child goes right, sibling left => H(sibling, child)
                self.parent_hash_rule(sib_hash, acc)
            };

            // ALWAYS store the parent at the next level, even if it's the same value
            // This is crucial for efficient proof generation
            let parent_idx = &idx >> 1;
            self.put_node(level + 1, &parent_idx, acc);
        }

        // Cache root directly from accumulator
        self.put_root_to_db(acc);
    }

    /// Produce the 254 siblings proof for `key` (LSB-first), also return leaf value and computed path root.
    pub fn prove(&self, key: &BigUint) -> (Fr, Fr, Vec<Fr>) {
        let mut siblings = Vec::with_capacity(self.depth);

        // Start with leaf value (for non-membership, this is 0)
        let leaf_value = self.get_node(0, key);
        let mut acc = if leaf_value.is_zero() {
            Fr::zero() // Non-membership proof starts with 0
        } else {
            self.smt_hash1(key, leaf_value) // Membership proof starts with SMTHash1
        };

        for level in 0..self.depth {
            let idx = key >> level;
            let sib_idx = &idx ^ BigUint::one();

            // Get sibling raw value
            let sib_raw = self.get_node(level, &sib_idx);

            // For level 0, compute SMTHash1 if sibling is a leaf
            let sib = if level == 0 && !sib_raw.is_zero() {
                self.smt_hash1(&sib_idx, sib_raw)
            } else {
                sib_raw
            };

            siblings.push(sib);

            // Circomlib switcher logic: bit determines left/right placement
            let bit = Self::get_bit_lsb(key, level);
            acc = if bit == 0 {
                // bit==0 => child goes left, sibling right => H(child, sibling)
                self.parent_hash_rule(acc, sib)
            } else {
                // bit==1 => child goes right, sibling left => H(sibling, child)
                self.parent_hash_rule(sib, acc)
            };
        }

        (leaf_value, acc, siblings)
    }

    // -----------------------
    // Internal helpers
    // -----------------------

    /// SMTHash1(key, value) = H(key, value, 1) - for leaf nodes
    /// This matches circomlib's SMTHash1 exactly
    fn smt_hash1(&self, key: &BigUint, value: Fr) -> Fr {
        let key_fr = bigint_to_fr(key);
        let one = Fr::one();
        self.hasher
            .hash(vec![key_fr, value, one])
            .expect("smt_hash1")
    }

    /// SMTHash2(left, right) = H(left, right) - for internal nodes  
    /// This matches circomlib's SMTHash2 exactly
    fn smt_hash2(&self, left: Fr, right: Fr) -> Fr {
        self.hasher.hash(vec![left, right]).expect("smt_hash2")
    }

    fn parent_hash_rule(&self, left: Fr, right: Fr) -> Fr {
        if left.is_zero() && right.is_zero() {
            Fr::zero()
        } else if left.is_zero() {
            right // If left is 0, parent is just the right value
        } else if right.is_zero() {
            left // If right is 0, parent is just the left value  
        } else {
            self.smt_hash2(left, right) // Both non-zero, hash them
        }
    }

    fn get_bit_lsb(x: &BigUint, i: usize) -> u8 {
        // (x >> i) & 1
        ((x >> i) & BigUint::one()).to_u8()
    }

    #[allow(dead_code)]
    fn even_idx(x: &BigUint) -> BigUint {
        if x.bit(0) {
            x - BigUint::one()
        } else {
            x.clone()
        }
    }

    /// RocksDB key for a node at (level, index).
    /// Stored as: "n:<level>:<index_dec>"
    fn node_key(level: usize, index: &BigUint) -> String {
        let mut s = String::with_capacity(2 + 1 + 3 + 1 + 78);
        s.push_str("n:");
        // level
        let _ = write!(s, "{}", level);
        s.push(':');
        // index (decimal)
        s.push_str(&index.to_string());
        s
    }

    /// Get node value at (level, index) — returns 0 if not present.
    fn get_node(&self, level: usize, index: &BigUint) -> Fr {
        let k = Self::node_key(level, index);
        if let Ok(Some(bytes)) = self.db.get(k.as_bytes()) {
            let dec = String::from_utf8(bytes).expect("utf8");
            fr_from_dec(&dec)
        } else {
            Fr::zero()
        }
    }

    /// Put/remove node at (level, index). If value == 0 → delete.
    fn put_node(&self, level: usize, index: &BigUint, value: Fr) {
        let k = Self::node_key(level, index);
        if value.is_zero() {
            let _ = self.db.delete(k.as_bytes());
        } else {
            let v = fr_to_dec(&value);
            self.db.put(k.as_bytes(), v.as_bytes()).expect("db.put");
        }
    }

    fn get_root_from_db(&self) -> Fr {
        if let Ok(Some(bytes)) = self.db.get(b"root") {
            let dec = String::from_utf8(bytes).expect("utf8");
            fr_from_dec(&dec)
        } else {
            Fr::zero()
        }
    }

    fn put_root_to_db(&self, r: Fr) {
        let v = fr_to_dec(&r);
        self.db.put(b"root", v.as_bytes()).expect("db.put root");
    }
}

// -----------------------
// Field helpers (BN254)
// -----------------------

/// Convert Fr to decimal string (Circom-friendly).
/// We avoid depending on ark-ff here and use a stable trick:
/// - `Fr::to_string()` in ff_ce formats as "Fr(0x...)" → extract hex → BigUint → decimal.
fn fr_to_dec(x: &Fr) -> String {
    let s = x.to_string(); // "Fr(0x...)" or sometimes just decimal; handle both
    if let Some(hex) = s.strip_prefix("Fr(0x").and_then(|t| t.strip_suffix(')')) {
        let bi = BigUint::from_str_radix(hex, 16).expect("hex->biguint");
        bi.to_string()
    } else {
        // already decimal or another format
        s
    }
}

/// Parse decimal (or hex with 0x) into Fr.
fn fr_from_dec(s: &str) -> Fr {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x") {
        let bi = BigUint::from_str_radix(hex, 16).expect("hex->biguint");
        Fr::from_str(&bi.to_string()).expect("Fr from dec")
    } else {
        Fr::from_str(t).expect("Fr from dec")
    }
}

/// Convert BigUint to Fr (for circomlib compatibility)
fn bigint_to_fr(x: &BigUint) -> Fr {
    Fr::from_str(&x.to_string()).expect("bigint to fr")
}

/// Convert Fr to BigUint
fn fr_to_bigint(x: &Fr) -> BigUint {
    let dec_str = fr_to_dec(x);
    BigUint::from_str(&dec_str).expect("fr to bigint")
}

// -----------------------
// Wrapper to match existing interface
// -----------------------

/// Wrapper around RocksSMT to match our existing SparseMerkleTree interface
pub struct SparseMerkleTree {
    smt: RocksSMT,
}

impl SparseMerkleTree {
    /// Create new SMT at the given path
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let smt = RocksSMT::open(path, RocksSMT::DEFAULT_DEPTH);
        Ok(Self { smt })
    }

    /// Get current root as BigUint
    pub fn get_root_as_biguint(&self) -> BigUint {
        let root_fr = self.smt.root();
        fr_to_bigint(&root_fr)
    }

    /// Insert a hash_id into the SMT and return the new root
    pub fn insert_hash_id(
        &mut self,
        hash_id: &BigUint,
    ) -> Result<BigUint, Box<dyn std::error::Error>> {
        // Insert with value 1 (standard for membership)
        let value_fr = Fr::one();
        self.smt.upsert(hash_id, value_fr);

        // Return new root
        Ok(self.get_root_as_biguint())
    }

    /// Generate siblings proof for a key (non-membership proof)
    pub fn generate_siblings_proof(
        &mut self,
        hash_id: &BigUint,
    ) -> Result<[BigUint; 254], Box<dyn std::error::Error>> {
        let (_leaf_value, _path_root, siblings_fr) = self.smt.prove(hash_id);

        // Convert Fr siblings to BigUint array
        let mut siblings = std::array::from_fn(|_| BigUint::zero());
        for (i, sibling_fr) in siblings_fr.iter().enumerate() {
            if i >= 254 {
                break;
            }
            siblings[i] = fr_to_bigint(sibling_fr);
        }

        Ok(siblings)
    }
}

// -----------------------
// BigUint tiny helpers
// -----------------------

trait ToU8 {
    fn to_u8(&self) -> u8;
}
impl ToU8 for BigUint {
    fn to_u8(&self) -> u8 {
        if self.is_zero() { 0 } else { 1 } // since we only call it for 0/1
    }
}
