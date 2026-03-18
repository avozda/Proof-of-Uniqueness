import * as snarkjs from "snarkjs";
import type { VerifiableCredential } from "./vc";
import {
  stringToField,
  dateToField,
  sexToField,
  hashBytes,
  vkToFieldElements,
  fromHex,
  decodeProofValue,
  extractPublicKeyFromVerificationMethod,
  computeFieldLeaf,
  buildMerkleTree,
  getDomainSeparator,
  VC_FIELD_LABELS,
  type VCFields,
} from "./did";

export interface CircuitInputs {
  // Domain separator
  domainSeparator: string;
  // Merkle tree structure (4 levels for 12 fields padded to 16)
  merkleLeaves: string[];
  // Field values (needed to verify leaf computation in circuit)
  fieldValues: string[];
  // EdDSA signature
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

/** Extract field values from VC in the canonical label order */
function extractFieldValues(vc: VerifiableCredential): VCFields {
  const subject = vc.credentialSubject;
  
  const sketchBytes = fromHex(subject.biometricTemplate.template);
  const vkBytes = fromHex(subject.biometricVerificationKey.value);
  const vkFields = vkToFieldElements(vkBytes);

  return {
    vcId: stringToField(vc.id),
    credentialSubjectId: stringToField(subject.id),
    name: stringToField(subject.name),
    dob: dateToField(subject.dateOfBirth),
    sex: sexToField(subject.sex),
    nationality: stringToField(subject.nationality),
    validFrom: dateToField(vc.validFrom),
    validUntil: dateToField(vc.validUntil),
    issuer: stringToField(vc.issuer.id),
    sketchHash: hashBytes(sketchBytes),
    verificationKey: vkFields,
  };
}

/** Recompute all circuit inputs from VC (Merkle tree approach) */
export function extractCircuitInputs(vc: VerifiableCredential): CircuitInputs {
  const proof = vc.proof;
  
  // Extract field values in canonical order
  const fields = extractFieldValues(vc);
  
  // Build field values array matching VC_FIELD_LABELS order
  const fieldValuesOrdered: bigint[] = [
    fields.verificationKey[0],  // biometricVk.0
    fields.verificationKey[1],  // biometricVk.1
    fields.credentialSubjectId, // credentialSubjectId
    fields.dob,                 // dob
    fields.issuer,              // issuer
    fields.name,                // name
    fields.nationality,         // nationality
    fields.sex,                 // sex
    fields.sketchHash,          // sketchHash
    fields.validFrom,           // validFrom
    fields.validUntil,          // validUntil
    fields.vcId,                // vcId
  ];
  
  // Compute Merkle leaves
  const leaves = VC_FIELD_LABELS.map((label, i) => 
    computeFieldLeaf(label, fieldValuesOrdered[i])
  );
  
  // Build tree and get padded leaves
  const tree = buildMerkleTree(leaves);

  const { signatureR8, signatureS } = decodeProofValue(proof.proofValue);
  const pubKey = extractPublicKeyFromVerificationMethod(proof.verificationMethod);
  const signerPubKey: [string, string] = [pubKey.x, pubKey.y];

  return {
    domainSeparator: getDomainSeparator().toString(),
    merkleLeaves: tree.leaves.map(l => l.toString()),
    fieldValues: fieldValuesOrdered.map(v => v.toString()),
    signerPubKey,
    signatureR8,
    signatureS,
  };
}

export async function generateProof(
  vc: VerifiableCredential
): Promise<ZKProof> {
  const inputs = extractCircuitInputs(vc);

  const wasmResponse = await fetch("/circuits/Enrollment.wasm");
  const wasmBuffer = await wasmResponse.arrayBuffer();

  const zkeyResponse = await fetch("/circuits/Enrollment_0001.zkey");
  const zkeyBuffer = await zkeyResponse.arrayBuffer();

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs as unknown as Record<string, unknown>,
    new Uint8Array(wasmBuffer),
    new Uint8Array(zkeyBuffer)
  );

  return { proof, publicSignals };
}

export function parsePublicSignals(publicSignals: string[]): ProofOutputs {
  return {
    hashID: publicSignals[0],
    outIssuer: publicSignals[1],
    outValidUntil: publicSignals[2],
    outSketchHash: publicSignals[3],
    outVerificationKey: [publicSignals[4], publicSignals[5]],
    outSignerPubKey: [publicSignals[6], publicSignals[7]],
  };
}

export async function verifyProof(zkProof: ZKProof): Promise<boolean> {
  const vkeyResponse = await fetch("/circuits/verification_key.json");
  const vkey = await vkeyResponse.json();

  return snarkjs.groth16.verify(vkey, zkProof.publicSignals, zkProof.proof);
}

export async function exportForSolidity(zkProof: ZKProof): Promise<string> {
  return snarkjs.groth16.exportSolidityCallData(
    zkProof.proof,
    zkProof.publicSignals
  );
}
