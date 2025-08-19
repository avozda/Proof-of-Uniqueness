use ethers::prelude::*;
use ethers::signers::{LocalWallet, Signer};
use num_bigint::BigUint;
use std::convert::TryFrom;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Include the generated contract bindings
mod identity_verification;
use identity_verification::{HashIDClaimFilter, HashIDInsertedFilter, IdentityVerification};

// Include custom 254-bit sparse merkle tree
mod smt;
use smt::SparseMerkleTree;

// Include ZK proof generation module
mod zk_proof;
use zk_proof::ZkProofGenerator;

// Include debug module
mod debug_db;

/// Convert a U256 value to a 254-bit BigUint by masking the top 2 bits
/// This ensures compatibility with the SMT which expects exactly 254-bit keys
fn u256_to_254bit(value: U256) -> Result<BigUint, Box<dyn std::error::Error>> {
    // Create a mask for 254 bits: 2^254 - 1
    let mask = (BigUint::from(1u32) << 254) - BigUint::from(1u32);

    // Convert U256 to BigUint
    let big_uint = BigUint::parse_bytes(&format!("{:x}", value).as_bytes(), 16)
        .ok_or("Failed to convert U256 to BigUint")?;

    // Apply mask to ensure it's exactly 254 bits
    Ok(big_uint & mask)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Starting dual event listener system...");

    // Initialize the sparse merkle tree with persistent storage
    let smt = Arc::new(Mutex::new(SparseMerkleTree::new("./smt_storage")?));
    let _ = debug_db::dump_db_to_json("./smt_storage", "./debug_smt_db.json");
    let _ = debug_db::print_db_summary("./smt_storage");

    // Initialize ZK proof generator
    let zk_generator = ZkProofGenerator::new()?;

    // Connect to local Ethereum node via HTTP
    let provider = Provider::<Http>::try_from("http://localhost:8545")?;

    // Set up wallet for transaction signing
    let private_key = env::var("PRIVATE_KEY").unwrap_or_else(|_| {
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string()
    });

    let wallet: LocalWallet = private_key.parse()?;
    let chain_id = provider.get_chainid().await?;
    let wallet = wallet.with_chain_id(chain_id.as_u64());

    // Create a signing provider
    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    let contract_address: Address = "0x5FbDB2315678afecb367f032d93F642f64180aa3".parse()?;
    let contract = IdentityVerification::new(contract_address, client.clone());

    println!("📝 Contract: {}", contract_address);
    println!("🚀 Starting dual event listeners:");
    println!("   📝 HashIDClaim events -> Skip past, process NEW claims only");
    println!("   🌳 HashIDInserted events -> Process ALL past + new to maintain tree state");

    // Start both event listeners concurrently
    let hash_id_claim_task =
        listen_for_hash_id_claim_events(contract.clone(), zk_generator, smt.clone());
    let hash_id_inserted_task =
        listen_for_hash_id_inserted_events(contract.clone(), smt.clone(), client);

    // Run both tasks concurrently
    tokio::try_join!(hash_id_claim_task, hash_id_inserted_task)?;

    Ok(())
}

/// Listen for HashIDClaim events and process them by generating proofs and submitting to contract
async fn listen_for_hash_id_claim_events(
    contract: IdentityVerification<SignerMiddleware<Provider<Http>, LocalWallet>>,
    zk_generator: ZkProofGenerator,
    smt: Arc<Mutex<SparseMerkleTree>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Skip past HashIDClaim events - only process new ones
    println!("📝 Skipping past HashIDClaim events, will only process new ones...");

    // Listen for new events
    let mut last_block = contract.client().get_block_number().await?;
    println!(
        "📝 Listening for new HashIDClaim events from block {}...",
        last_block
    );

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;

        let current_block = contract.client().get_block_number().await?;
        if current_block > last_block {
            match contract
                .event::<HashIDClaimFilter>()
                .from_block(last_block + 1)
                .to_block(current_block)
                .query()
                .await
            {
                Ok(events) => {
                    for event in events {
                        println!("📝 New HashIDClaim event detected!");
                        if let Err(e) =
                            process_hash_id_claim_event(&event, &smt, &zk_generator, &contract)
                                .await
                        {
                            println!("❌ Error processing HashIDClaim event: {}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("❌ Error querying HashIDClaim events: {}", e);
                }
            }
            last_block = current_block;
        }
    }
}

/// Listen for HashIDInserted events and update local SMT
async fn listen_for_hash_id_inserted_events(
    contract: IdentityVerification<SignerMiddleware<Provider<Http>, LocalWallet>>,
    smt: Arc<Mutex<SparseMerkleTree>>,
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Process ALL past HashIDInserted events to build current tree state
    println!("🌳 Processing ALL past HashIDInserted events to rebuild tree state...");
    let past_events = contract
        .event::<HashIDInsertedFilter>()
        .from_block(0)
        .query()
        .await?;

    for event in past_events {
        if let Err(e) = process_hash_id_inserted_event(&event, &smt, &contract).await {
            println!("❌ Error processing past HashIDInserted event: {}", e);
        }
    }

    // Listen for new events
    let mut last_block = client.get_block_number().await?;
    println!(
        "🌳 Listening for new HashIDInserted events from block {}...",
        last_block
    );

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;

        let current_block = client.get_block_number().await?;
        if current_block > last_block {
            match contract
                .event::<HashIDInsertedFilter>()
                .from_block(last_block + 1)
                .to_block(current_block)
                .query()
                .await
            {
                Ok(events) => {
                    for event in events {
                        println!("🌳 New HashIDInserted event detected!");
                        if let Err(e) =
                            process_hash_id_inserted_event(&event, &smt, &contract).await
                        {
                            println!("❌ Error processing HashIDInserted event: {}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("❌ Error querying HashIDInserted events: {}", e);
                }
            }
            last_block = current_block;
        }
    }
}

/// Process a HashIDClaim event by generating an SMT proof and submitting to contract
async fn process_hash_id_claim_event(
    event: &HashIDClaimFilter,
    smt: &Arc<Mutex<SparseMerkleTree>>,
    zk_generator: &ZkProofGenerator,
    contract: &IdentityVerification<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let hash_id_u256 = event.pub_signals[0];
    let hash_id = u256_to_254bit(hash_id_u256)?;

    println!("📝 Processing HashID: 0x{:x}", hash_id_u256);

    let (current_root, siblings) = {
        let mut smt_guard = smt.lock().unwrap();
        let current_root = smt_guard.get_root_as_biguint();
        let siblings = smt_guard.generate_siblings_proof(&hash_id)?;
        (current_root, siblings)
    };
    let (proof_a_smt, proof_b_smt, proof_c_smt, public_signals_smt) = zk_generator
        .generate_smt_proof(&hash_id, &current_root, &siblings)
        .await?;

    // Convert to contract format
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

    match tx.send().await {
        Ok(pending_tx) => {
            println!("✅ Transaction sent: {:?}", pending_tx.tx_hash());
            match pending_tx.await {
                Ok(Some(receipt)) => {
                    println!(
                        "🎉 Transaction confirmed in block {}",
                        receipt.block_number.unwrap_or_default()
                    );
                }
                Ok(None) => {
                    println!("⚠️  Transaction pending");
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
        Err(e) => {
            println!("❌ Transaction failed: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

/// Process a HashIDInserted event by updating local SMT and verifying root consistency
async fn process_hash_id_inserted_event(
    event: &HashIDInsertedFilter,
    smt: &Arc<Mutex<SparseMerkleTree>>,
    contract: &IdentityVerification<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let hash_id = u256_to_254bit(event.hash_id)?;
    let contract_new_root = u256_to_254bit(event.new_root)?;

    println!("🌳 Processing HashIDInserted: 0x{:x}", event.hash_id);
    println!("   Contract new root: {}", contract_new_root);

    // Update local SMT
    let local_new_root = {
        let mut smt_guard = smt.lock().unwrap();
        smt_guard.insert_hash_id(&hash_id)?
    };
    println!("   Local new root: {}", local_new_root);

    // Sync our local root with the contract root (contract is source of truth)
    {
        let mut smt_guard = smt.lock().unwrap();
        smt_guard.set_root(&contract_new_root);
    }
    
    // Verify root consistency
    if local_new_root == contract_new_root {
        println!("✅ Root consistency verified!");
    } else {
        println!("❌ ROOT MISMATCH! Syncing with contract root...");
        println!("   Expected (contract): {}", contract_new_root);
        println!("   Actual (local):      {}", local_new_root);
        println!("✅ Local root synced with contract");
    }

    Ok(())
}
