import { v4 as uuidv4 } from "uuid";
import {
  createJWSSignature,
  toHex,
  stringToField,
  dateToField,
  sexToField,
  poseidonHash,
  createVCSignature,
} from "./did";
import type { DIDKeyPair } from "./did";

export interface CredentialSubject {
  id: string;
  name: string;
  dateOfBirth: string;
  nationality: string;
  sex: string;
  biometricTemplate: {
    type: string;
    template: string;
  };
  biometricVerificationKey: {
    type: string;
    value: string;
  };
}

export interface EdDSAPoseidonProof {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  // EdDSA Poseidon signature components (for circuit compatibility)
  signatureR8: [string, string]; // R8 point as hex strings
  signatureS: string; // S scalar as hex string
  signedMessage: string; // The Poseidon hash that was signed (hex)
  signerPublicKey: [string, string]; // Public key [Ax, Ay] as hex strings
  jws: string; // JWS format for traditional verification
}

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
}

export interface VerifiableCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: {
    id: string;
    name: string;
  };
  validFrom: string;
  validUntil: string;
  credentialSubject: CredentialSubject;
  proof: EdDSAPoseidonProof;
  // Circuit-compatible field representations (as decimal strings for easy parsing)
  circuitInputs: CircuitInputs;
}

export interface FormData {
  name: string;
  dateOfBirth: string;
  nationality: string;
  sex: string;
}

/**
 * Generate a random person ID
 */
function generatePersonId(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 18; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `urn:person:${result}`;
}

/**
 * Compute Poseidon hash of a Uint8Array (for sketch)
 */
function hashBytes(bytes: Uint8Array): bigint {
  // Split bytes into field-sized chunks and hash
  const chunks: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 31) {
    const chunk = bytes.slice(i, Math.min(i + 31, bytes.length));
    let value = BigInt(0);
    for (let j = 0; j < chunk.length; j++) {
      value = (value << BigInt(8)) | BigInt(chunk[j]);
    }
    chunks.push(value);
  }
  return poseidonHash(chunks);
}

/**
 * Convert verification key bytes to two field elements
 * Assumes 33-byte compressed public key format
 */
function vkToFieldElements(vk: Uint8Array): [bigint, bigint] {
  // Split the verification key into two parts for circuit input
  const half = Math.ceil(vk.length / 2);
  const part1 = vk.slice(0, half);
  const part2 = vk.slice(half);

  let x = BigInt(0);
  for (let i = 0; i < part1.length; i++) {
    x = (x << BigInt(8)) | BigInt(part1[i]);
  }

  let y = BigInt(0);
  for (let i = 0; i < part2.length; i++) {
    y = (y << BigInt(8)) | BigInt(part2[i]);
  }

  return [x, y];
}

/**
 * Create a W3C Verifiable Credential 2.0 with EdDSA Poseidon signature
 */
export function createVerifiableCredential(
  formData: FormData,
  issuer: DIDKeyPair,
  issuerName: string,
  sketch: Uint8Array,
  verificationKey: Uint8Array
): VerifiableCredential {
  const now = new Date();
  const validUntil = new Date(now);
  validUntil.setFullYear(validUntil.getFullYear() + 5); // Valid for 5 years

  const credentialId = `urn:uuid:${uuidv4()}`;
  const personId = generatePersonId();

  // Convert all fields to circuit-compatible format (field elements)
  const vcIdField = stringToField(credentialId);
  const subjectIdField = stringToField(personId);
  const nameField = stringToField(formData.name);
  const dobField = dateToField(formData.dateOfBirth);
  const sexField = sexToField(formData.sex);
  const nationalityField = stringToField(formData.nationality);
  const validFromField = dateToField(now.toISOString());
  const validUntilField = dateToField(validUntil.toISOString());
  const issuerField = stringToField(issuer.did);
  const sketchHashField = hashBytes(sketch);
  const vkFields = vkToFieldElements(verificationKey);

  // Create signature using EdDSA Poseidon
  const signatureData = createVCSignature(issuer.privateKey, issuer.publicKey, {
    vcId: vcIdField,
    credentialSubjectId: subjectIdField,
    name: nameField,
    dob: dobField,
    sex: sexField,
    nationality: nationalityField,
    validFrom: validFromField,
    issuer: issuerField,
    validUntil: validUntilField,
    sketchHash: sketchHashField,
    verificationKey: vkFields,
  });

  // Create the credential without proof first (for JWS)
  const credentialWithoutProof = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: credentialId,
    type: ["VerifiableCredential", "BiometricIdentityCredential"],
    issuer: {
      id: issuer.did,
      name: issuerName,
    },
    validFrom: now.toISOString(),
    validUntil: validUntil.toISOString(),
    credentialSubject: {
      id: personId,
      name: formData.name,
      dateOfBirth: formData.dateOfBirth,
      nationality: formData.nationality,
      sex: formData.sex,
      biometricTemplate: {
        type: "FuzzySignatureTemplate",
        template: toHex(sketch),
      },
      biometricVerificationKey: {
        type: "FuzzyVerificationKey",
        value: toHex(verificationKey),
      },
    },
  };

  // Create the JWS signature
  const jws = createJWSSignature(
    issuer.privateKey,
    credentialWithoutProof,
    signatureData.message
  );

  // Create the full credential with proof and circuit inputs
  const credential: VerifiableCredential = {
    ...credentialWithoutProof,
    proof: {
      type: "EdDSAPoseidonSignature2024",
      created: now.toISOString(),
      verificationMethod: issuer.verificationMethod,
      proofPurpose: "assertionMethod",
      signatureR8: [
        signatureData.signature.R8[0].toString(),
        signatureData.signature.R8[1].toString(),
      ],
      signatureS: signatureData.signature.S.toString(),
      signedMessage: signatureData.message.toString(),
      signerPublicKey: [
        issuer.publicKey.x.toString(),
        issuer.publicKey.y.toString(),
      ],
      jws: jws,
    },
    circuitInputs: {
      vcId: vcIdField.toString(),
      credentialSubjectId: subjectIdField.toString(),
      credentialSubjectName: nameField.toString(),
      credentialSubjectDob: dobField.toString(),
      credentialSubjectSex: sexField.toString(),
      credentialSubjectNationality: nationalityField.toString(),
      validFrom: validFromField.toString(),
      validUntil: validUntilField.toString(),
      issuer: issuerField.toString(),
      sketchHash: sketchHashField.toString(),
      biometricVk: [vkFields[0].toString(), vkFields[1].toString()],
    },
  };

  return credential;
}
