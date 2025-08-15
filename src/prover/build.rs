use ethers::contract::Abigen;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate contract bindings from ABI
    Abigen::new("IdentityVerification", "./IdentityVerification.json")?
        .generate()?
        .write_to_file("src/identity_verification.rs")?;

    Ok(())
}
