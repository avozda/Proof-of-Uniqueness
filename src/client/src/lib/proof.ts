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
} from "./did";

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

/** Recompute all circuit inputs from standard VC fields */
export function extractCircuitInputs(vc: VerifiableCredential): CircuitInputs {
  const subject = vc.credentialSubject;
  const proof = vc.proof;

  const vcId = stringToField(vc.id).toString();
  const credentialSubjectId = stringToField(subject.id).toString();
  const credentialSubjectName = stringToField(subject.name).toString();
  const credentialSubjectDob = dateToField(subject.dateOfBirth).toString();
  const credentialSubjectSex = sexToField(subject.sex).toString();
  const credentialSubjectNationality = stringToField(subject.nationality).toString();
  const validFrom = dateToField(vc.validFrom).toString();
  const validUntil = dateToField(vc.validUntil).toString();
  const issuer = stringToField(vc.issuer.id).toString();

  const sketchBytes = fromHex(subject.biometricTemplate.template);
  const sketchHash = hashBytes(sketchBytes).toString();

  const vkBytes = fromHex(subject.biometricVerificationKey.value);
  const vkFields = vkToFieldElements(vkBytes);
  const biometricVk: [string, string] = [vkFields[0].toString(), vkFields[1].toString()];

  const { signatureR8, signatureS } = decodeProofValue(proof.proofValue);
  const pubKey = extractPublicKeyFromVerificationMethod(proof.verificationMethod);
  const signerPubKey: [string, string] = [pubKey.x, pubKey.y];

  return {
    vcId,
    credentialSubjectId,
    credentialSubjectName,
    credentialSubjectDob,
    credentialSubjectSex,
    credentialSubjectNationality,
    validFrom,
    validUntil,
    issuer,
    sketchHash,
    biometricVk,
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
