import { v4 as uuidv4 } from "uuid";
import {
  toHex,
  stringToField,
  dateToField,
  sexToField,
  createVCSignature,
  encodeProofValue,
  hashBytes,
  vkToFieldElements,
} from "./did";
import type { DIDKeyPair } from "./did";

export interface CredentialSubject {
  id: string;
  name: string;
  dateOfBirth: string;
  placeOfBirth: string;
  nationality: string;
  sex: string;
  permanentAddressHash: {
    type: string;
    value: string;
  };
  biometricTemplate: {
    type: string;
    template: string;
  };
  biometricVerificationKey: {
    type: string;
    value: string;
  };
  holderBindingSignature: {
    type: string;
    r8x: string;
    r8y: string;
    s: string;
  };
}

export interface DataIntegrityProof {
  type: "DataIntegrityProof";
  cryptosuite: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
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
  proof: DataIntegrityProof;
}

export interface FormData {
  name: string;
  dateOfBirth: string;
  placeOfBirth: string;
  permanentAddress: string;
  nationality: string;
  sex: string;
}

export function generatePersonId(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 18; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `urn:person:${result}`;
}

export const CRYPTOSUITE_ID = "eddsa-babyjubjub-poseidon-2024";

export function createVerifiableCredential(
  formData: FormData,
  issuer: DIDKeyPair,
  issuerName: string,
  sketch: Uint8Array,
  verificationKey: Uint8Array,
  holderBindingSignature: {
    r8x: bigint;
    r8y: bigint;
    s: bigint;
  },
  credentialSubjectId?: string,
): VerifiableCredential {
  const now = new Date();
  const validUntil = new Date(now);
  validUntil.setFullYear(validUntil.getFullYear() + 5);

  const credentialId = `urn:uuid:${uuidv4()}`;
  const personId = credentialSubjectId ?? generatePersonId();

  const vcIdField = stringToField(credentialId);
  const subjectIdField = stringToField(personId);
  const nameField = stringToField(formData.name);
  const dobField = dateToField(formData.dateOfBirth);
  const placeOfBirthField = stringToField(formData.placeOfBirth);
  const sexField = sexToField(formData.sex);
  const nationalityField = stringToField(formData.nationality);
  const permanentAddressHashField = hashBytes(
    new TextEncoder().encode(formData.permanentAddress)
  );
  const validFromField = dateToField(now.toISOString());
  const validUntilField = dateToField(validUntil.toISOString());
  const issuerField = stringToField(issuer.did);
  const sketchHashField = hashBytes(sketch);
  const vkFields = vkToFieldElements(verificationKey);

  const signatureData = createVCSignature(issuer.privateKey, issuer.publicKey, {
    vcId: vcIdField,
    credentialSubjectId: subjectIdField,
    name: nameField,
    dob: dobField,
    placeOfBirth: placeOfBirthField,
    sex: sexField,
    nationality: nationalityField,
    permanentAddressHash: permanentAddressHashField,
    validFrom: validFromField,
    issuer: issuerField,
    validUntil: validUntilField,
    sketchHash: sketchHashField,
    verificationKey: vkFields,
  });

  const proofValue = encodeProofValue(
    signatureData.signature.R8,
    signatureData.signature.S
  );

  return {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/security/data-integrity/v2",
    ],
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
      placeOfBirth: formData.placeOfBirth,
      nationality: formData.nationality,
      sex: formData.sex,
      permanentAddressHash: {
        type: "PoseidonHash",
        value: permanentAddressHashField.toString(),
      },
      biometricTemplate: {
        type: "FuzzySignatureTemplate",
        template: toHex(sketch),
      },
      biometricVerificationKey: {
        type: "FuzzyVerificationKey",
        value: toHex(verificationKey),
      },
      holderBindingSignature: {
        type: "BabyJubJubEdDSA-Poseidon",
        r8x: holderBindingSignature.r8x.toString(),
        r8y: holderBindingSignature.r8y.toString(),
        s: holderBindingSignature.s.toString(),
      },
    },
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: CRYPTOSUITE_ID,
      created: now.toISOString(),
      verificationMethod: issuer.verificationMethod,
      proofPurpose: "assertionMethod",
      proofValue: proofValue,
    },
  };
}
