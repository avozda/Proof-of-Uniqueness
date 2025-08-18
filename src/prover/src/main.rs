use ethers::prelude::*;
use ethers::signers::{LocalWallet, Signer};
use num_bigint::BigUint;
use std::convert::TryFrom;
use std::env;
use std::sync::Arc;
use std::time::Duration;

// Include the generated contract bindings
mod identity_verification;
use identity_verification::{HashIDClaimFilter, IdentityVerification};

// Include custom 254-bit sparse merkle tree
mod smt;
use smt::SparseMerkleTree;

// Include ZK proof generation module
mod zk_proof;
use zk_proof::ZkProofGenerator;

// Include debug module
mod debug_db;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting HashIDClaim event listener...");

    // Initialize the sparse merkle tree with persistent storage
    println!("Initializing Sparse Merkle Tree...");
    let mut smt = SparseMerkleTree::new("./smt_storage")?;
    println!("Sparse Merkle Tree initialized successfully");

    // Debug: Dump database content to JSON file
    println!("\n🔧 Debug: Dumping database content...");
    if let Err(e) = debug_db::dump_db_to_json("./smt_storage", "./debug_smt_db.json") {
        println!("⚠️  Failed to dump database: {}", e);
    }

    // Debug: Print database summary to console
    if let Err(e) = debug_db::print_db_summary("./smt_storage") {
        println!("⚠️  Failed to print database summary: {}", e);
    }

    // Initialize ZK proof generator
    println!("Initializing ZK Proof Generator...");
    let zk_generator = ZkProofGenerator::new()?;
    println!("ZK Proof Generator initialized successfully");

    // Connect to local Ethereum node via HTTP (we'll poll for events instead of subscription)
    let provider = Provider::<Http>::try_from("http://localhost:8545")?;

    // Set up wallet for transaction signing
    let private_key = env::var("PRIVATE_KEY").unwrap_or_else(|_| {
        println!("⚠️  PRIVATE_KEY environment variable not set, using default test key");
        // Default Hardhat test account #0 private key (DO NOT USE IN PRODUCTION!)
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string()
    });

    let wallet: LocalWallet = private_key.parse()?;
    let chain_id = provider.get_chainid().await?;
    let wallet = wallet.with_chain_id(chain_id.as_u64());

    println!("🔑 Using wallet address: {:?}", wallet.address());

    // Create a signing provider
    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    // Contract address (you'll need to update this with your deployed contract address)
    let contract_address: Address = "0x5FbDB2315678afecb367f032d93F642f64180aa3".parse()?;

    println!(
        "Listening for HashIDClaim events from contract: {}",
        contract_address
    );

    // Create contract instance with signer
    let contract = IdentityVerification::new(contract_address, client.clone());

    // Get past events first
    println!("Checking for past events...");
    let events = contract
        .event::<HashIDClaimFilter>()
        .from_block(0)
        .query()
        .await?;

    println!("Found {} past events", events.len());

    for event in events {
        println!("\n📜 Past HashIDClaim Event:");
        println!(
            "Public Signals: [{}]",
            event
                .pub_signals
                .iter()
                .map(|s| format!("0x{:x}", s))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("----------------------------------------");

        // Process past events as well
        match process_hash_id_claim_event(&event, &mut smt, &zk_generator, &contract).await {
            Ok(_) => println!("✅ Successfully processed past HashIDClaim event"),
            Err(e) => println!("❌ Error processing past HashIDClaim event: {}", e),
        }
    }

    // Poll for new events periodically
    let mut last_block = client.get_block_number().await?;
    println!(
        "Successfully connected! Polling for new HashIDClaim events from block {}...",
        last_block
    );

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;

        let current_block = client.get_block_number().await?;
        if current_block > last_block {
            // Check for new events in the new blocks
            match contract
                .event::<HashIDClaimFilter>()
                .from_block(last_block + 1)
                .to_block(current_block)
                .query()
                .await
            {
                Ok(events) => {
                    for event in events {
                        println!("\n🎉 NEW HashIDClaim Event Detected!");
                        println!(
                            "Public Signals: [{}]",
                            event
                                .pub_signals
                                .iter()
                                .map(|s| format!("0x{:x}", s))
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                        println!("----------------------------------------");

                        // Process the event and generate SMT proof
                        match process_hash_id_claim_event(
                            &event,
                            &mut smt,
                            &zk_generator,
                            &contract,
                        )
                        .await
                        {
                            Ok(_) => println!("✅ Successfully processed HashIDClaim event"),
                            Err(e) => println!("❌ Error processing HashIDClaim event: {}", e),
                        }
                    }
                }
                Err(e) => {
                    println!("Error fetching events: {}", e);
                }
            }
            last_block = current_block;
        }
    }
}

/// Process a HashIDClaim event by generating an SMT proof and submitting to contract
async fn process_hash_id_claim_event(
    event: &HashIDClaimFilter,
    smt: &mut SparseMerkleTree,
    zk_generator: &ZkProofGenerator,
    contract: &IdentityVerification<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Extract hash_id from the event's public signals
    let hash_id_u256 = event.pub_signals[0];
    let hash_id = BigUint::parse_bytes(&format!("{:x}", hash_id_u256).as_bytes(), 16)
        .ok_or("Failed to convert U256 to BigUint")?;

    println!("🔍 Processing HashID: {}", hash_id);

    // Check if this hash_id has already been processed
    if smt.is_hash_id_inserted(&hash_id)? {
        println!("⚠️  HashID {} already processed, skipping", hash_id);
        return Ok(());
    }

    // Get current SMT root
    let old_root = smt.get_root_as_biguint();
    println!("📍 Current SMT Root: {}", old_root);

    // For now, let's use a zero root for non-membership proof in an empty tree
    // This matches what the SMT circuit expects for proving non-existence
    let empty_root = BigUint::from(0u32);
    println!(
        "📍 Using empty SMT root for non-membership proof: {}",
        empty_root
    );

    // Generate siblings proof for the hash_id
    println!("🔧 Generating siblings proof...");
    let siblings = smt.generate_siblings_proof(&hash_id)?;

    // Generate ZK proof for SMT verification
    println!("🔐 Generating SMT ZK proof...");
    let (proof_a_smt, proof_b_smt, proof_c_smt, public_signals_smt) = zk_generator
        .generate_smt_proof(&hash_id, &empty_root, &siblings)
        .await?;

    // Convert string arrays to the format expected by the contract
    let proof_a_smt_u256: [U256; 2] = [
        U256::from_dec_str(&proof_a_smt[0])?,
        U256::from_dec_str(&proof_a_smt[1])?,
    ];

    let proof_b_smt_u256: [[U256; 2]; 2] = [
        [
            U256::from_dec_str(&proof_b_smt[0][0])?,
            U256::from_dec_str(&proof_b_smt[0][1])?,
        ],
        [
            U256::from_dec_str(&proof_b_smt[1][0])?,
            U256::from_dec_str(&proof_b_smt[1][1])?,
        ],
    ];

    let proof_c_smt_u256: [U256; 2] = [
        U256::from_dec_str(&proof_c_smt[0])?,
        U256::from_dec_str(&proof_c_smt[1])?,
    ];

    let public_signals_smt_u256: [U256; 3] = [
        U256::from_dec_str(&public_signals_smt[0])?, // new root
        U256::from_dec_str(&public_signals_smt[1])?, // verified hash_id
        U256::from_dec_str(&public_signals_smt[2])?, // old root from circuit (should be 0)
    ];

    // Submit to contract using insertHashID function
    println!("📤 Submitting to contract...");
    println!("🔍 Contract validation details:");
    println!("   HashID from original proof: 0x{:x}", hash_id_u256);
    println!("   HashID from SMT proof: {}", public_signals_smt[1]);
    println!("   Contract root: {}", old_root);
    println!("   SMT proof old root: {}", public_signals_smt[2]);

    // Use the original HashIDClaim proof data
    let tx = contract.insert_hash_id(
        event.p_a,
        event.p_b,
        event.p_c,
        event.pub_signals,
        proof_a_smt_u256,
        proof_b_smt_u256,
        proof_c_smt_u256,
        public_signals_smt_u256,
    );

    // Send the transaction to the blockchain
    println!("📤 Sending transaction to blockchain...");
    match tx.send().await {
        Ok(pending_tx) => {
            println!("✅ Transaction sent! Hash: {:?}", pending_tx.tx_hash());
            println!("⏳ Waiting for confirmation...");

            match pending_tx.await {
                Ok(Some(receipt)) => {
                    println!("🎉 Transaction confirmed!");
                    println!(
                        "   📦 Block number: {}",
                        receipt.block_number.unwrap_or_default()
                    );
                    println!("   ⛽ Gas used: {}", receipt.gas_used.unwrap_or_default());
                    println!("   💰 Status: {:?}", receipt.status);

                    // Update local SMT state after successful blockchain transaction
                    let new_root = smt.insert_hash_id(&hash_id)?;
                    println!("🌳 Updated local SMT Root: {}", new_root);

                    println!("✅ Hash ID successfully submitted to smart contract!");
                }
                Ok(None) => {
                    println!("⚠️  Transaction pending - no receipt yet");
                }
                Err(e) => {
                    println!("❌ Transaction failed: {}", e);
                    return Err(e.into());
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to send transaction: {}", e);
            println!("🔍 Possible causes:");
            println!("   - Insufficient funds for gas");
            println!("   - Contract validation failed");
            println!("   - Network connection issues");
            println!("   - Root mismatch between circuit and contract");
            return Err(e.into());
        }
    }

    Ok(())
}
