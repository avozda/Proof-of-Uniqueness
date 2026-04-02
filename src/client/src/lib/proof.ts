import * as snarkjs from "snarkjs";
import type { VerifiableCredential } from "./vc";
import {
  stringToField,
  dateToField,
  sexToField,
  decodeProofValue,
  extractPublicKeyFromVerificationMethod,
  computeFieldLeaf,
  buildMerkleTree,
  getDomainSeparator,
  VC_FIELD_LABELS,
  type VCFields,
} from "./did";
import {
  buildRevokeChallengeMessage,
  signMessageWithHolderKey,
  type HolderKeyPair,
} from "./holderKey";

export interface CircuitInputs {
  // Domain separator
  domainSeparator: string;
  // Merkle tree structure (4 levels for 13 fields padded to 16)
  merkleLeaves: string[];
  // Field values (needed to verify leaf computation in circuit)
  fieldValues: string[];
  // EdDSA signature
  signerPubKey: [string, string];
  signatureR8: [string, string];
  signatureS: string;
  holderSignatureR8: [string, string];
  holderSignatureS: string;
}

export interface ZKProof {
  proof: snarkjs.Groth16Proof;
  publicSignals: string[];
}

export interface RevocationProofInputs {
  challengeDomain: string;
  holderPubKey: [string, string];
  revokeSignatureR8: [string, string];
  revokeSignatureS: string;
  contractAddressField: string;
  chainId: string;
  hashID: string;
  challengeBlock: string;
}

export interface RevocationProof {
  proof: snarkjs.Groth16Proof;
  // Circuit public order: holderPubKeyX, holderPubKeyY, hashID, challengeBlock
  publicSignals: [string, string, string, string];
}

export interface ProofOutputs {
  hashID: string;
  outIssuer: string;
  outValidUntil: string;
  outHolderPubKey: [string, string];
  outSignerPubKey: [string, string];
}

/** Extract field values from VC in the canonical label order */
function extractFieldValues(vc: VerifiableCredential): VCFields {
  const subject = vc.credentialSubject;

  const holderPubKey: [bigint, bigint] = [
    BigInt(subject.holderPublicKey.x),
    BigInt(subject.holderPublicKey.y),
  ];

  return {
    vcId: stringToField(vc.id),
    credentialSubjectId: stringToField(subject.id),
    name: stringToField(subject.name),
    dob: dateToField(subject.dateOfBirth),
    placeOfBirth: stringToField(subject.placeOfBirth),
    sex: sexToField(subject.sex),
    nationality: stringToField(subject.nationality),
    permanentAddressHash: BigInt(subject.permanentAddressHash.value),
    validFrom: dateToField(vc.validFrom),
    validUntil: dateToField(vc.validUntil),
    issuer: stringToField(vc.issuer.id),
    holderPublicKey: holderPubKey,
  };
}

/** Recompute all circuit inputs from VC (Merkle tree approach) */
export function extractCircuitInputs(vc: VerifiableCredential): CircuitInputs {
  const proof = vc.proof;

  // Extract field values in canonical order
  const fields = extractFieldValues(vc);

  // Build field values array matching VC_FIELD_LABELS order
  const fieldValuesOrdered: bigint[] = [
    fields.holderPublicKey[0], // holderPubKey.0
    fields.holderPublicKey[1], // holderPubKey.1
    fields.credentialSubjectId, // credentialSubjectId
    fields.dob, // dob
    fields.issuer, // issuer
    fields.name, // name
    fields.nationality, // nationality
    fields.permanentAddressHash, // permanentAddressHash
    fields.placeOfBirth, // placeOfBirth
    fields.sex, // sex
    fields.validFrom, // validFrom
    fields.validUntil, // validUntil
    fields.vcId, // vcId
  ];

  // Compute Merkle leaves
  const leaves = VC_FIELD_LABELS.map((label, i) =>
    computeFieldLeaf(label, fieldValuesOrdered[i]),
  );

  // Build tree and get padded leaves
  const tree = buildMerkleTree(leaves);

  const { signatureR8, signatureS } = decodeProofValue(proof.proofValue);
  const pubKey = extractPublicKeyFromVerificationMethod(
    proof.verificationMethod,
  );
  const signerPubKey: [string, string] = [pubKey.x, pubKey.y];
  const holderSig = vc.credentialSubject.holderBindingSignature;

  return {
    domainSeparator: getDomainSeparator().toString(),
    merkleLeaves: tree.leaves.map((l) => l.toString()),
    fieldValues: fieldValuesOrdered.map((v) => v.toString()),
    signerPubKey,
    signatureR8,
    signatureS,
    holderSignatureR8: [holderSig.r8x, holderSig.r8y],
    holderSignatureS: holderSig.s,
  };
}

export async function generateProof(
  vc: VerifiableCredential,
): Promise<ZKProof> {
  const inputs = extractCircuitInputs(vc);

  const wasmResponse = await fetch("/circuits/IdentityEnrollment.wasm");
  const wasmBuffer = await wasmResponse.arrayBuffer();

  const zkeyResponse = await fetch("/circuits/IdentityEnrollment_0001.zkey");
  const zkeyBuffer = await zkeyResponse.arrayBuffer();

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs as unknown as Record<string, unknown>,
    new Uint8Array(wasmBuffer),
    new Uint8Array(zkeyBuffer),
  );

  return { proof, publicSignals };
}

function addressToField(address: `0x${string}`): bigint {
  const clean = address.toLowerCase().replace("0x", "");
  if (!/^[0-9a-f]{40}$/.test(clean)) {
    throw new Error("Invalid address format");
  }
  return BigInt(`0x${clean}`);
}

export function buildRevocationCircuitInputs(
  holderKeyPair: HolderKeyPair,
  contractAddress: `0x${string}`,
  chainId: bigint,
  hashID: bigint,
  challengeBlock: bigint,
): RevocationProofInputs {
  const holderPubKey = holderKeyPair.publicKey;

  const message = buildRevokeChallengeMessage(
    contractAddress,
    chainId,
    hashID,
    challengeBlock,
  );
  const signature = signMessageWithHolderKey(holderKeyPair.privateKey, message);

  return {
    challengeDomain: stringToField("IdentityRegistry::Revoke:v2").toString(),
    holderPubKey: [holderPubKey.x.toString(), holderPubKey.y.toString()],
    revokeSignatureR8: [
      signature.R8[0].toString(),
      signature.R8[1].toString(),
    ],
    revokeSignatureS: signature.S.toString(),
    contractAddressField: addressToField(contractAddress).toString(),
    chainId: chainId.toString(),
    hashID: hashID.toString(),
    challengeBlock: challengeBlock.toString(),
  };
}

export async function generateRevocationProof(
  holderKeyPair: HolderKeyPair,
  contractAddress: `0x${string}`,
  chainId: bigint,
  hashID: bigint,
  challengeBlock: bigint,
): Promise<RevocationProof> {
  const inputs = buildRevocationCircuitInputs(
    holderKeyPair,
    contractAddress,
    chainId,
    hashID,
    challengeBlock,
  );

  const wasmResponse = await fetch("/circuits/IdentityRevocation.wasm");
  const wasmBuffer = await wasmResponse.arrayBuffer();

  const zkeyResponse = await fetch("/circuits/IdentityRevocation_0001.zkey");
  const zkeyBuffer = await zkeyResponse.arrayBuffer();

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs as unknown as Record<string, unknown>,
    new Uint8Array(wasmBuffer),
    new Uint8Array(zkeyBuffer),
  );

  return {
    proof,
    publicSignals: publicSignals as [string, string, string, string],
  };
}

export async function verifyRevocationProof(
  revokeProof: RevocationProof,
): Promise<boolean> {
  const vkeyResponse = await fetch("/circuits/verification_key_revocation.json");
  const vkey = await vkeyResponse.json();
  return snarkjs.groth16.verify(vkey, revokeProof.publicSignals, revokeProof.proof);
}

export function parsePublicSignals(publicSignals: string[]): ProofOutputs {
  return {
    hashID: publicSignals[0],
    outIssuer: publicSignals[1],
    outValidUntil: publicSignals[2],
    outHolderPubKey: [publicSignals[3], publicSignals[4]],
    outSignerPubKey: [publicSignals[5], publicSignals[6]],
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
    zkProof.publicSignals,
  );
}
