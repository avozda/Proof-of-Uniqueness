//! Authentication module for VC ownership proofs.
use std::path::PathBuf;

use ark_ff::PrimeField as _;
use async_trait::async_trait;
use eyre::Context;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use taceo_oprf::{
    service::Environment,
    types::{
        OprfKeyId,
        api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
    },
};

use crate::{
    AuthModule,
    unkey_api::{self},
};

/// Authentication payload for `vc-ownership` requests.
#[derive(Clone, Serialize, Deserialize)]
pub struct VcOwnershipRequestAuth {
    /// Public inputs passed to proof verifier.
    pub public_inputs: Vec<u8>,
    /// Proof bytes.
    pub proof: Vec<u8>,
    /// API key.
    pub api_key: String,
    /// Holder request signature R8.x
    pub holder_sig_r8x: String,
    /// Holder request signature R8.y
    pub holder_sig_r8y: String,
    /// Holder request signature scalar S
    pub holder_sig_s: String,
}

/// Decoded public outputs for the VC ownership proof.
#[derive(Debug, Clone)]
pub struct VcProofPublicOutputs {
    /// Blinded query x-coordinate derived in-circuit from private hash ID.
    pub blinded_query_x: ark_babyjubjub::Fq,
    /// Blinded query y-coordinate derived in-circuit from private hash ID.
    pub blinded_query_y: ark_babyjubjub::Fq,
    /// Holder public key x-coordinate.
    pub out_holder_pub_key_x: ark_babyjubjub::Fq,
    /// Holder public key y-coordinate.
    pub out_holder_pub_key_y: ark_babyjubjub::Fq,
}

fn fq_to_dec_string(value: ark_babyjubjub::Fq) -> String {
    value.into_bigint().to_string()
}

fn blinded_query_matches_request(
    outputs: &VcProofPublicOutputs,
    req: &OprfRequest<VcOwnershipRequestAuth>,
) -> bool {
    fq_to_dec_string(outputs.blinded_query_x) == req.blinded_query.x.to_string()
        && fq_to_dec_string(outputs.blinded_query_y) == req.blinded_query.y.to_string()
}

/// Authentication errors for VC ownership requests.
#[derive(Debug, thiserror::Error)]
pub enum VcOwnershipRequestAuthError {
    /// Invalid proof.
    #[error("Proof invalid")]
    ProofInvalid,
    /// Internal server error.
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

/// Close code mapping for VC ownership auth errors.
pub mod vc_ownership_request_auth_error_codes {
    /// Invalid proof close code.
    pub const PROOF_INVALID: u16 = 4610;
    /// Internal error close code.
    pub const INTERNAL: u16 = 1011;
}

impl From<&VcOwnershipRequestAuthError> for u16 {
    fn from(value: &VcOwnershipRequestAuthError) -> Self {
        match value {
            VcOwnershipRequestAuthError::ProofInvalid => {
                vc_ownership_request_auth_error_codes::PROOF_INVALID
            }
            VcOwnershipRequestAuthError::InternalServerError(_) => {
                vc_ownership_request_auth_error_codes::INTERNAL
            }
        }
    }
}

impl From<u16> for VcOwnershipRequestAuthError {
    fn from(value: u16) -> Self {
        match value {
            vc_ownership_request_auth_error_codes::PROOF_INVALID => {
                VcOwnershipRequestAuthError::ProofInvalid
            }
            vc_ownership_request_auth_error_codes::INTERNAL => {
                VcOwnershipRequestAuthError::InternalServerError(eyre::eyre!(
                    "Internal Server Error"
                ))
            }
            _ => VcOwnershipRequestAuthError::InternalServerError(eyre::eyre!(
                "Unknown authentication error code: {value}"
            )),
        }
    }
}

impl From<VcOwnershipRequestAuthError> for OprfRequestAuthenticatorError {
    fn from(value: VcOwnershipRequestAuthError) -> Self {
        let code = u16::from(&value);
        let msg = match value {
            VcOwnershipRequestAuthError::ProofInvalid => {
                taceo_oprf::types::close_frame_message!("Proof is invalid")
            }
            VcOwnershipRequestAuthError::InternalServerError(err) => {
                tracing::error!("Internal server error: {err:?}");
                taceo_oprf::types::close_frame_message!("Internal Server Error")
            }
        };
        Self::with_message(code, msg)
    }
}

/// Server-side authenticator for `vc-ownership`.
pub struct VcOwnershipRequestAuthenticator {
    client: reqwest::Client,
    root_api_key: SecretString,
    env: Environment,
    vk_path: PathBuf,
}

impl VcOwnershipRequestAuthenticator {
    /// Initializes VC ownership request authenticator.
    pub fn init(root_api_key: SecretString, env: Environment, vk_path: PathBuf) -> Self {
        Self {
            client: reqwest::Client::new(),
            root_api_key,
            env,
            vk_path,
        }
    }
}

#[async_trait]
impl OprfRequestAuthenticator for VcOwnershipRequestAuthenticator {
    type RequestAuth = VcOwnershipRequestAuth;

    async fn authenticate(
        &self,
        req: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        tracing::debug!("Authenticating with API Key and VC proof");

        // Strict payload shape validation: vc_blinded_query_auth public outputs are 4 field elements.
        if req.auth.public_inputs.len() != 4 * 32 || req.auth.proof.is_empty() {
            return Err(VcOwnershipRequestAuthError::ProofInvalid.into());
        }

        let api_valid = tokio::task::spawn({
            let client = self.client.clone();
            let root_api_key = self.root_api_key.clone();
            let api_key = req.auth.api_key.clone();
            let env = self.env;
            async move { unkey_api::verify_api_key(client, root_api_key, api_key, env).await }
        });

        zk::verify_proof(&req.auth.public_inputs, &req.auth.proof, &self.vk_path)?;
        // Browser noir_js auth payload currently serializes public inputs as little-endian
        // 32-byte field elements for verifier compatibility.
        let outputs = parse_public_outputs_le(&req.auth.public_inputs)?;
        if !blinded_query_matches_request(&outputs, req) {
            return Err(VcOwnershipRequestAuthError::ProofInvalid.into());
        }

        zk::verify_holder_request_signature(
            req.request_id.to_string(),
            req.blinded_query.x.to_string(),
            req.blinded_query.y.to_string(),
            outputs.out_holder_pub_key_x.to_string(),
            outputs.out_holder_pub_key_y.to_string(),
            req.auth.holder_sig_r8x.clone(),
            req.auth.holder_sig_r8y.clone(),
            req.auth.holder_sig_s.clone(),
        )?;

        api_valid
            .await
            .context("awaiting api verification")
            .map_err(VcOwnershipRequestAuthError::InternalServerError)??;

        Ok(AuthModule::VcOwnership.oprf_key_id())
    }
}

/// Parses VC proof public outputs from little-endian serialized field bytes.
pub fn parse_public_outputs_le(
    public_inputs: &[u8],
) -> Result<VcProofPublicOutputs, VcOwnershipRequestAuthError> {
    const OUTPUTS: usize = 4;
    const FIELD_BYTES: usize = 32;
    let expected = OUTPUTS * FIELD_BYTES;
    if public_inputs.len() < expected {
        return Err(VcOwnershipRequestAuthError::InternalServerError(
            eyre::eyre!(
                "public inputs too short: expected at least {expected} bytes, got {}",
                public_inputs.len()
            ),
        ));
    }

    let read_fq = |idx: usize| {
        let start = idx * FIELD_BYTES;
        let end = start + FIELD_BYTES;
        ark_babyjubjub::Fq::from_le_bytes_mod_order(&public_inputs[start..end])
    };

    Ok(VcProofPublicOutputs {
        blinded_query_x: read_fq(0),
        blinded_query_y: read_fq(1),
        out_holder_pub_key_x: read_fq(2),
        out_holder_pub_key_y: read_fq(3),
    })
}

/// ZK helpers for VC ownership proofs.
pub mod zk {
    use std::{io::Write, path::Path, process::Command};

    use eyre::Context;
    use tempfile::NamedTempFile;

    /// Verifies a VC ownership proof with strict input shape checks.
    pub fn verify_proof(
        public_inputs: &[u8],
        proof: &[u8],
        vk_path: &Path,
    ) -> Result<(), super::VcOwnershipRequestAuthError> {
        if public_inputs.len() != 4 * 32 || proof.is_empty() {
            return Err(super::VcOwnershipRequestAuthError::ProofInvalid);
        }

        let mut public_input_file =
            NamedTempFile::new().context("creating public inputs NamedTempFile").map_err(
                super::VcOwnershipRequestAuthError::InternalServerError,
            )?;

        let mut proof_file = NamedTempFile::new()
            .context("creating proof NamedTempFile")
            .map_err(super::VcOwnershipRequestAuthError::InternalServerError)?;

        public_input_file
            .write_all(public_inputs)
            .context("writing public inputs to temp file")
            .map_err(super::VcOwnershipRequestAuthError::InternalServerError)?;

        proof_file
            .write_all(proof)
            .context("writing proof to temp file")
            .map_err(super::VcOwnershipRequestAuthError::InternalServerError)?;

        let proof_path = proof_file.path();
        let public_inputs_path = public_input_file.path();
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let script = manifest_dir
            .join("../../client/scripts/verify-vc-ownership-auth.mjs")
            .canonicalize()
            .context("resolving verifier script path")
            .map_err(super::VcOwnershipRequestAuthError::InternalServerError)?;
        let circuit = manifest_dir
            .join("vc_blinded_query_auth_proof.json")
            .canonicalize()
            .context("resolving vc ownership circuit path")
            .map_err(super::VcOwnershipRequestAuthError::InternalServerError)?;

        let output = Command::new("node")
            .arg(script)
            .arg("verify-proof")
            .arg("--circuit")
            .arg(circuit)
            .arg("--proof")
            .arg(proof_path)
            .arg("--public-inputs")
            .arg(public_inputs_path)
            .output()
            .context("while spawning node verifier for vc ownership auth")
            .map_err(super::VcOwnershipRequestAuthError::InternalServerError)?;

        if output.status.success() {
            tracing::debug!(
                "VC ownership auth proof verified with noir_js backend: {}",
                String::from_utf8_lossy(&output.stdout).trim()
            );
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        tracing::error!(
            "VC ownership auth proof verification failed. status={:?}, stdout={stdout}, stderr={stderr}",
            output.status.code()
        );
        let _ = vk_path;
        Err(super::VcOwnershipRequestAuthError::ProofInvalid)
    }

    #[allow(clippy::too_many_arguments)]
    /// Verifies holder signature bound to the current OPRF request data.
    pub fn verify_holder_request_signature(
        request_id: String,
        blinded_x: String,
        blinded_y: String,
        holder_pub_x: String,
        holder_pub_y: String,
        sig_r8x: String,
        sig_r8y: String,
        sig_s: String,
    ) -> Result<(), super::VcOwnershipRequestAuthError> {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let script = manifest_dir
            .join("../../client/scripts/verify-vc-ownership-auth.mjs")
            .canonicalize()
            .context("resolving verifier script path")
            .map_err(super::VcOwnershipRequestAuthError::InternalServerError)?;

        let output = Command::new("node")
            .arg(script)
            .arg("verify-holder-sig")
            .arg("--request-id")
            .arg(request_id)
            .arg("--blinded-x")
            .arg(blinded_x)
            .arg("--blinded-y")
            .arg(blinded_y)
            .arg("--holder-pub-x")
            .arg(holder_pub_x)
            .arg("--holder-pub-y")
            .arg(holder_pub_y)
            .arg("--sig-r8x")
            .arg(sig_r8x)
            .arg("--sig-r8y")
            .arg(sig_r8y)
            .arg("--sig-s")
            .arg(sig_s)
            .output()
            .context("while spawning node holder signature verifier")
            .map_err(super::VcOwnershipRequestAuthError::InternalServerError)?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        tracing::error!(
            "VC ownership holder signature verification failed. status={:?}, stdout={stdout}, stderr={stderr}",
            output.status.code()
        );
        Err(super::VcOwnershipRequestAuthError::ProofInvalid)
    }
}
