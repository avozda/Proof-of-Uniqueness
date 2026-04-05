use alloy::primitives::eip191_hash_message;
use alloy::signers::SignerSync;
use alloy::signers::k256::ecdsa::SigningKey;
use alloy::signers::k256::elliptic_curve::sec1::ToEncodedPoint;
use alloy::signers::local::PrivateKeySigner;
use ark_ff::PrimeField as _;
use eyre::Context;
use oprf_testnet_authentication::{
    AuthModule,
    basic::BasicTestNetRequestAuth,
    vc_ownership::{self, VcOwnershipRequestAuth},
    wallet_ownership::TestNetRequestAuth,
    wallet_ownership::zk,
};
use rand::{CryptoRng, Rng};
use std::{
    path::Path,
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use taceo_oprf::client::{self, VerifiableOprfOutput};
use taceo_oprf::{client::Connector, core::oprf::BlindingFactor};
use tempfile::NamedTempFile;
use tracing::instrument;

#[instrument(level = "debug", skip_all)]
pub async fn basic_verifiable_oprf<R: Rng + CryptoRng>(
    nodes: &[String],
    threshold: usize,
    api_key: String,
    action: ark_babyjubjub::Fq,
    connector: Connector,
    rng: &mut R,
) -> eyre::Result<VerifiableOprfOutput> {
    tracing::info!("Running distributed OPRF with API only authentication");
    let start = Instant::now();
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF TestNet");

    let auth = BasicTestNetRequestAuth { api_key };

    let nodes = taceo_oprf::client::to_oprf_uri_many(nodes, AuthModule::Basic)
        .context("while parsing URIs")?;

    let verifiable_oprf_output = client::distributed_oprf(
        &nodes,
        threshold,
        action,
        blinding_factor,
        domain_separator,
        auth,
        connector,
    )
    .await;
    let verifiable_oprf_output = make_server_errors_human_friendly(verifiable_oprf_output)
        .context("during execution of the OPRF protocol")?;

    let elapsed = start.elapsed();
    tracing::info!("Total time taken for distributed OPRF with only API: {elapsed:?}",);

    Ok(verifiable_oprf_output)
}

#[instrument(level = "debug", skip_all)]
pub async fn wallet_ownership_verifiable_oprf<R: Rng + CryptoRng>(
    nodes: &[String],
    threshold: usize,
    api_key: String,
    private_key: SigningKey,
    connector: Connector,
    rng: &mut R,
) -> eyre::Result<(VerifiableOprfOutput, Vec<u8>, Vec<u8>)> {
    tracing::info!("Running distributed OPRF with API and Proof authentication");
    let start = Instant::now();
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF TestNet");

    let encoded_pubkey = private_key
        .verifying_key()
        .as_affine()
        .to_encoded_point(false);
    let x_affine = encoded_pubkey
        .x()
        .expect("should be possible to get x from publickey")
        .to_vec();
    let y_affine = encoded_pubkey
        .y()
        .expect("should be possible to get y from publickey")
        .to_vec();

    // Instantiate a signer
    let signer = PrivateKeySigner::from_signing_key(private_key);
    let query = ark_babyjubjub::Fq::from_be_bytes_mod_order(signer.address().as_ref());

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let msg = format!("TACEO Oprf Input: {ts}");
    let msg_hash = eip191_hash_message(msg.as_bytes());
    let mut signature = signer.sign_hash_sync(&msg_hash)?.as_bytes().to_vec();

    //Remove recovery id
    _ = signature.pop();

    let (public_inputs, proof) = zk::compute_wallet_ownership_proof(
        &blinding_factor,
        &x_affine,
        &y_affine,
        &signature,
        msg_hash.as_ref(),
    )?;

    let auth = TestNetRequestAuth {
        public_inputs,
        proof,
        api_key,
    };

    let nodes = taceo_oprf::client::to_oprf_uri_many(nodes, AuthModule::WalletOwnership)
        .context("while parsing URIs")?;
    let verifiable_oprf_output = client::distributed_oprf(
        &nodes,
        threshold,
        query,
        blinding_factor,
        domain_separator,
        auth,
        connector,
    )
    .await;
    let verifiable_oprf_output = make_server_errors_human_friendly(verifiable_oprf_output)
        .context("during execution of the OPRF protocol")?;

    tracing::debug!("Computing proof for the verifiable OPRF output..");
    let (public_inputs, proof) = zk::compute_nullifier_proof(
        verifiable_oprf_output.clone(),
        signature,
        msg_hash,
        &blinding_factor,
        x_affine,
        y_affine,
    )?;

    let vk = NamedTempFile::new().context("creating NamedTempFile for vk")?;
    std::fs::write(vk.path(), zk::VERIFIED_OPRF_PROOF_VK).context("writing VK to temp file")?;
    zk::verify_proof(&public_inputs, &proof, vk.path())?;

    let elapsed = start.elapsed();
    tracing::info!(
        "Total time taken for distributed OPRF with API and Proof authentication: {elapsed:?}",
    );

    Ok((verifiable_oprf_output, public_inputs, proof))
}

#[instrument(level = "debug", skip_all)]
pub async fn vc_ownership_verifiable_oprf<R: Rng + CryptoRng>(
    nodes: &[String],
    threshold: usize,
    api_key: String,
    vc_path: &Path,
    expected_hash_id: Option<ark_babyjubjub::Fq>,
    connector: Connector,
    rng: &mut R,
) -> eyre::Result<VerifiableOprfOutput> {
    tracing::info!("Running distributed OPRF with API and VC proof authentication");
    let start = Instant::now();
    let blinding_factor = BlindingFactor::rand(rng);
    let domain_separator = ark_babyjubjub::Fq::from_be_bytes_mod_order(b"OPRF TestNet");

    let prover_input = build_vc_prover_input(vc_path)?;
    let (public_inputs, proof) = vc_ownership::zk::compute_vc_ownership_proof(prover_input.path())?;

    let auth = VcOwnershipRequestAuth {
        public_inputs: public_inputs.clone(),
        proof,
        api_key,
        // Rust demo client does not currently derive/sign the live request challenge
        // for vc-ownership auth. These placeholders keep compilation intact; browser
        // path provides real holder request signatures.
        holder_sig_r8x: "0".to_owned(),
        holder_sig_r8y: "0".to_owned(),
        holder_sig_s: "0".to_owned(),
    };

    let hash_id = parse_hash_id_from_public_inputs(&public_inputs)
        .context("while parsing hash_id from vc proof public inputs")?;
    if let Some(expected_hash_id) = expected_hash_id {
        eyre::ensure!(
            hash_id == expected_hash_id,
            "hash_id mismatch: parsed from proof public inputs is {}, expected {}",
            hash_id,
            expected_hash_id,
        );
    }

    let nodes = taceo_oprf::client::to_oprf_uri_many(nodes, AuthModule::VcOwnership)
        .context("while parsing URIs")?;

    let verifiable_oprf_output = client::distributed_oprf(
        &nodes,
        threshold,
        hash_id,
        blinding_factor,
        domain_separator,
        auth,
        connector,
    )
    .await;
    let verifiable_oprf_output = make_server_errors_human_friendly(verifiable_oprf_output)
        .context("during execution of the OPRF protocol")?;

    let elapsed = start.elapsed();
    tracing::info!("Total time taken for distributed OPRF with VC proof: {elapsed:?}");

    Ok(verifiable_oprf_output)
}

pub fn parse_hash_id_from_public_inputs(public_inputs: &[u8]) -> eyre::Result<ark_babyjubjub::Fq> {
    let outputs = vc_ownership::parse_legacy_public_outputs(public_inputs)
        .map_err(|err| eyre::eyre!("failed parsing VC public outputs: {err}"))?;
    Ok(outputs.hash_id)
}

fn build_vc_prover_input(vc_path: &Path) -> eyre::Result<NamedTempFile> {
    let prover_input =
        NamedTempFile::new().context("creating temporary Prover.toml for VC proof")?;
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../client/scripts/build-vc-prover-input.mjs");

    eyre::ensure!(
        script.exists(),
        "missing helper script at {}",
        script.display()
    );

    let output = Command::new("node")
        .arg(script)
        .arg("--vc-path")
        .arg(vc_path)
        .arg("--out")
        .arg(prover_input.path())
        .output()
        .context("failed to execute node for VC prover input generation")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eyre::bail!("failed generating VC prover input: {stderr}");
    }

    Ok(prover_input)
}

fn make_server_errors_human_friendly(
    response: Result<VerifiableOprfOutput, client::Error>,
) -> eyre::Result<VerifiableOprfOutput> {
    response.map_err(|e| match e {
        client::Error::ThresholdServiceError(service_error) => {
            tracing::warn!("{service_error:?}");
            let message = service_error
                .msg
                .clone()
                .unwrap_or("unknown message".to_owned());
            if service_error.is_auth() {
                eyre::eyre!("Authentication error from OPRF server: {message:?}")
            } else {
                eyre::eyre!(service_error)
            }
        }
        client::Error::Networking(errors) => {
            tracing::warn!("{errors:?}");
            eyre::eyre!("Networking errors - check your internet connection and try again")
        }
        err => {
            tracing::warn!("{err:?}");
            eyre::eyre!(err)
        }
    })
}
