use anyhow::{Result, anyhow};
use num_bigint::BigUint;
use num_traits::Num;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

pub struct ZkProofGenerator {
    wasm_path: String,
    zkey_path: String,
    #[allow(dead_code)]
    verification_key_path: String,
}

impl ZkProofGenerator {
    pub fn new() -> Result<Self> {
        let wasm_path = "./zk/build/SMTVerification_js/SMTVerification.wasm".to_string();
        let zkey_path = "./zk/SMTVerification_0001.zkey".to_string();
        let verification_key_path = "./zk/verification_key.json".to_string();

        // Verify files exist
        if !Path::new(&wasm_path).exists() {
            return Err(anyhow!("WASM file not found: {}", wasm_path));
        }
        if !Path::new(&zkey_path).exists() {
            return Err(anyhow!("ZKey file not found: {}", zkey_path));
        }
        if !Path::new(&verification_key_path).exists() {
            return Err(anyhow!(
                "Verification key file not found: {}",
                verification_key_path
            ));
        }

        Ok(Self {
            wasm_path,
            zkey_path,
            verification_key_path,
        })
    }

    /// Generate a ZK proof for SMT verification
    /// Returns (proof_a, proof_b, proof_c, public_signals)
    pub async fn generate_smt_proof(
        &self,
        hash_id: &BigUint,
        old_root: &BigUint,
        siblings: &[BigUint; 254],
    ) -> Result<(Vec<String>, Vec<Vec<String>>, Vec<String>, Vec<String>)> {
        println!("🔧 Generating ZK proof for SMT verification...");

        // Create input JSON for the circuit
        let input = self.create_circuit_input(hash_id, old_root, siblings)?;

        // Write input to temporary file
        let input_path = "./temp_input.json";
        fs::write(input_path, serde_json::to_string_pretty(&input)?)?;

        // Generate witness using snarkjs
        println!("📝 Generating witness...");
        let witness_path = "./witness.wtns";
        let witness_output = Command::new("node")
            .args(&[
                "./zk/build/SMTVerification_js/generate_witness.js",
                &self.wasm_path,
                input_path,
                witness_path,
            ])
            .output()?;

        if !witness_output.status.success() {
            let error = String::from_utf8_lossy(&witness_output.stderr);
            return Err(anyhow!("Failed to generate witness: {}", error));
        }

        // Generate proof using snarkjs
        println!("🔐 Generating ZK proof...");
        let proof_path = "./proof.json";
        let public_path = "./public.json";

        let proof_output = Command::new("snarkjs")
            .args(&[
                "groth16",
                "prove",
                &self.zkey_path,
                witness_path,
                proof_path,
                public_path,
            ])
            .output()?;

        if !proof_output.status.success() {
            let error = String::from_utf8_lossy(&proof_output.stderr);
            return Err(anyhow!("Failed to generate proof: {}", error));
        }

        // Read and parse the generated proof
        let proof_json: Value = serde_json::from_str(&fs::read_to_string(proof_path)?)?;
        let public_json: Value = serde_json::from_str(&fs::read_to_string(public_path)?)?;

        // Extract proof components
        let proof_a = vec![
            proof_json["pi_a"][0].as_str().unwrap().to_string(),
            proof_json["pi_a"][1].as_str().unwrap().to_string(),
        ];

        let proof_b = vec![
            vec![
                proof_json["pi_b"][0][1].as_str().unwrap().to_string(),
                proof_json["pi_b"][0][0].as_str().unwrap().to_string(),
            ],
            vec![
                proof_json["pi_b"][1][1].as_str().unwrap().to_string(),
                proof_json["pi_b"][1][0].as_str().unwrap().to_string(),
            ],
        ];

        let proof_c = vec![
            proof_json["pi_c"][0].as_str().unwrap().to_string(),
            proof_json["pi_c"][1].as_str().unwrap().to_string(),
        ];

        let public_signals: Vec<String> = public_json
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        // Clean up temporary files
        let _ = fs::remove_file(input_path);
        let _ = fs::remove_file(witness_path);
        let _ = fs::remove_file(proof_path);
        let _ = fs::remove_file(public_path);

        println!("✅ ZK proof generated successfully!");
        println!("📊 Public signals: {:?}", public_signals);

        Ok((proof_a, proof_b, proof_c, public_signals))
    }

    /// Create circuit input JSON from the provided parameters
    fn create_circuit_input(
        &self,
        hash_id: &BigUint,
        old_root: &BigUint,
        siblings: &[BigUint; 254],
    ) -> Result<Value> {
        let mut input = HashMap::new();

        // Convert BigUint to string representation for circuit
        // Make sure all values are within the field size for BN254
        let field_modulus = BigUint::parse_bytes(
            b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .ok_or(anyhow!("Failed to parse field modulus"))?;

        let hash_id_mod = hash_id % &field_modulus;
        let old_root_mod = old_root % &field_modulus;

        input.insert("hashID".to_string(), json!(hash_id_mod.to_string()));
        input.insert("oldRoot".to_string(), json!(old_root_mod.to_string()));

        // Convert siblings array - ensure all are within field
        let siblings_vec: Vec<String> = siblings
            .iter()
            .map(|s| (s % &field_modulus).to_string())
            .collect();
        input.insert("siblings".to_string(), json!(siblings_vec));

        println!("🔧 Circuit inputs:");
        println!("   hashID: {}", hash_id_mod);
        println!("   oldRoot: {}", old_root_mod);
        println!("   siblings: first few = {:?}", &siblings_vec[0..3]);

        Ok(json!(input))
    }

    /// Verify a proof (for testing purposes)
    #[allow(dead_code)]
    pub async fn verify_proof(
        &self,
        proof_a: &[String],
        proof_b: &[Vec<String>],
        proof_c: &[String],
        public_signals: &[String],
    ) -> Result<bool> {
        // Create verification input
        let verification_input = json!({
            "pi_a": [proof_a[0], proof_a[1], "1"],
            "pi_b": [[proof_b[0][1], proof_b[0][0]], [proof_b[1][1], proof_b[1][0]], ["1", "0"]],
            "pi_c": [proof_c[0], proof_c[1], "1"],
            "protocol": "groth16",
            "curve": "bn128"
        });

        let proof_path = "./temp_verification_proof.json";
        let public_path = "./temp_verification_public.json";

        fs::write(
            proof_path,
            serde_json::to_string_pretty(&verification_input)?,
        )?;
        fs::write(
            public_path,
            serde_json::to_string_pretty(&json!(public_signals))?,
        )?;

        let verify_output = Command::new("snarkjs")
            .args(&[
                "groth16",
                "verify",
                &self.verification_key_path,
                public_path,
                proof_path,
            ])
            .output()?;

        let _ = fs::remove_file(proof_path);
        let _ = fs::remove_file(public_path);

        let output_str = String::from_utf8_lossy(&verify_output.stdout);
        Ok(output_str.contains("OK!"))
    }
}

/// Helper function to convert string to BigUint
#[allow(dead_code)]
pub fn string_to_biguint(s: &str) -> Result<BigUint> {
    if s.starts_with("0x") {
        BigUint::from_str_radix(&s[2..], 16)
            .map_err(|e| anyhow!("Failed to parse hex string {}: {}", s, e))
    } else {
        BigUint::from_str_radix(s, 10)
            .map_err(|e| anyhow!("Failed to parse decimal string {}: {}", s, e))
    }
}

/// Helper function to convert BigUint to hex string for Ethereum
#[allow(dead_code)]
pub fn biguint_to_hex_string(n: &BigUint) -> String {
    format!("0x{}", n.to_str_radix(16))
}
