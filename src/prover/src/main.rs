use ethers::prelude::*;
use std::sync::Arc;
use std::time::Duration;

// Include the generated contract bindings
mod identity_verification;
use identity_verification::{HashIDClaimFilter, IdentityVerification};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting HashIDClaim event listener...");

    // Connect to local Ethereum node via HTTP (we'll poll for events instead of subscription)
    let provider = Provider::<Http>::try_from("http://localhost:8545")?;
    let provider = Arc::new(provider);

    // Contract address (you'll need to update this with your deployed contract address)
    let contract_address: Address = "0x5FbDB2315678afecb367f032d93F642f64180aa3".parse()?;

    println!(
        "Listening for HashIDClaim events from contract: {}",
        contract_address
    );

    // Create contract instance
    let contract = IdentityVerification::new(contract_address, provider.clone());

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
        println!("Proof A: {:?}", event.p_a);
        println!("Proof B: {:?}", event.p_b);
        println!("Proof C: {:?}", event.p_c);
        println!("Public Signals: {:?}", event.pub_signals);
        println!("----------------------------------------");
    }

    // Poll for new events periodically
    let mut last_block = provider.get_block_number().await?;
    println!(
        "Successfully connected! Polling for new HashIDClaim events from block {}...",
        last_block
    );

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;

        let current_block = provider.get_block_number().await?;
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
                        println!("Proof A: {:?}", event.p_a);
                        println!("Proof B: {:?}", event.p_b);
                        println!("Proof C: {:?}", event.p_c);
                        println!("Public Signals: {:?}", event.pub_signals);
                        println!("----------------------------------------");
                    }
                }
                Err(e) => {
                    println!("Error fetching events: {}", e);
                }
            }
            last_block = current_block;
        }
    }

    Ok(())
}
