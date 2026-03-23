import * as snarkjs from "snarkjs";
import type { VerifiableCredential } from "./vc";

export interface CircuitInputs {
  vcId: string;
  credentialSubjectId: string;
  credentialSubjectName: string;
  credentialSubjectDob: string;
  credentialSubjectSex: string;
  credentialSubjectNationality: string;
  validFrom: string;
  validUntil: string;
  issuer: string;
  sketchHash: string;
  biometricVk: [string, string];
  signerPubKey: [string, string];
  signatureR8: [string, string];
  signatureS: string;
}

export interface ZKProof {
  proof: snarkjs.Groth16Proof;
  publicSignals: string[];
}

export interface ProofOutputs {
  hashID: string;
  outIssuer: string;
  outValidUntil: string;
  outSketchHash: string;
  outVerificationKey: [string, string];
  outSignerPubKey: [string, string];
}

/**
 * Extract circuit inputs from a Verifiable Credential
 */
export function extractCircuitInputs(vc: VerifiableCredential): CircuitInputs {
  const ci = vc.circuitInputs;
  const proof = vc.proof;

  return {
    vcId: ci.vcId,
    credentialSubjectId: ci.credentialSubjectId,
    credentialSubjectName: ci.credentialSubjectName,
    credentialSubjectDob: ci.credentialSubjectDob,
    credentialSubjectSex: ci.credentialSubjectSex,
    credentialSubjectNationality: ci.credentialSubjectNationality,
    validFrom: ci.validFrom,
    validUntil: ci.validUntil,
    issuer: ci.issuer,
    sketchHash: ci.sketchHash,
    biometricVk: ci.biometricVk,
    signerPubKey: proof.signerPublicKey,
    signatureR8: proof.signatureR8,
    signatureS: proof.signatureS,
  };
}

/**
 * Generate a ZK proof for an enrollment credential
 */
export async function generateProof(
  vc: VerifiableCredential
): Promise<ZKProof> {
  const inputs = extractCircuitInputs(vc);

  // Fetch the WASM and zkey files
  const wasmResponse = await fetch("/circuits/IdentityEnrollment.wasm");
  const wasmBuffer = await wasmResponse.arrayBuffer();

  const zkeyResponse = await fetch("/circuits/IdentityEnrollment_0001.zkey");
  const zkeyBuffer = await zkeyResponse.arrayBuffer();

  // Generate the proof
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs as unknown as Record<string, unknown>,
    new Uint8Array(wasmBuffer),
    new Uint8Array(zkeyBuffer)
  );

  return { proof, publicSignals };
}

/**
 * Parse public signals into named outputs
 */
export function parsePublicSignals(publicSignals: string[]): ProofOutputs {
  // Output order from circuit:
  // hashID, outIssuer, outValidUntil, outSketchHash, outVerificationKey[0], outVerificationKey[1], outSignerPubKey[0], outSignerPubKey[1]
  return {
    hashID: publicSignals[0],
    outIssuer: publicSignals[1],
    outValidUntil: publicSignals[2],
    outSketchHash: publicSignals[3],
    outVerificationKey: [publicSignals[4], publicSignals[5]],
    outSignerPubKey: [publicSignals[6], publicSignals[7]],
  };
}

/**
 * Verify a ZK proof
 */
export async function verifyProof(zkProof: ZKProof): Promise<boolean> {
  const vkeyResponse = await fetch("/circuits/verification_key.json");
  const vkey = await vkeyResponse.json();

  return snarkjs.groth16.verify(vkey, zkProof.publicSignals, zkProof.proof);
}

/**
 * Export proof for Solidity verification
 */
export async function exportForSolidity(zkProof: ZKProof): Promise<string> {
  return snarkjs.groth16.exportSolidityCallData(
    zkProof.proof,
    zkProof.publicSignals
  );
}
