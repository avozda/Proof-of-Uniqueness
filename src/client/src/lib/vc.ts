import { v4 as uuidv4 } from "uuid";
import {
  stringToField,
  dateToField,
  sexToField,
  createVCSignature,
  encodeProofValue,
} from "./did";
import type { DIDKeyPair, EdDSAPublicKey } from "./did";

export interface CredentialSubject {
  id: string;
  name: string;
  dateOfBirth: string;
  placeOfBirth: string;
  nationality: string;
  sex: string;
  holderPublicKey: {
    type: string;
    x: string;
    y: string;
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
  nationality: string;
  sex: string;
}

function generatePersonId(): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 18; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `urn:person:${result}`;
}

const CRYPTOSUITE_ID = "eddsa-babyjubjub-poseidon-2024";

function isIsoDateTime(value: string): boolean {
  if (typeof value !== "string") return false;
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return false;
  return new Date(time).toISOString() === value;
}

function assertDemoVcShape(vc: VerifiableCredential): void {
  if (!Array.isArray(vc["@context"]) || vc["@context"].length === 0) {
    throw new Error("VC must include a non-empty @context array");
  }
  if (!Array.isArray(vc.type) || !vc.type.includes("VerifiableCredential")) {
    throw new Error("VC type must include VerifiableCredential");
  }
  if (!vc.issuer?.id || !vc.credentialSubject?.id) {
    throw new Error("VC must include issuer.id and credentialSubject.id");
  }
  if (!isIsoDateTime(vc.validFrom) || !isIsoDateTime(vc.validUntil)) {
    throw new Error("VC validFrom/validUntil must be ISO 8601 date-time strings");
  }
  if (Date.parse(vc.validUntil) <= Date.parse(vc.validFrom)) {
    throw new Error("VC validUntil must be later than validFrom");
  }
  if (!vc.proof?.type || !vc.proof?.proofValue || !isIsoDateTime(vc.proof.created)) {
    throw new Error("VC proof must include type, proofValue, and ISO created timestamp");
  }
}

export function createVerifiableCredential(
  formData: FormData,
  issuer: DIDKeyPair,
  issuerName: string,
  holderPublicKey: EdDSAPublicKey,
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
  const validFromField = dateToField(now.toISOString());
  const validUntilField = dateToField(validUntil.toISOString());
  const issuerField = stringToField(issuer.did);
  const holderPubKeyFields: [bigint, bigint] = [
    holderPublicKey.x,
    holderPublicKey.y,
  ];

  const signatureData = createVCSignature(issuer.privateKey, issuer.publicKey, {
    vcId: vcIdField,
    credentialSubjectId: subjectIdField,
    name: nameField,
    dob: dobField,
    placeOfBirth: placeOfBirthField,
    sex: sexField,
    nationality: nationalityField,
    validFrom: validFromField,
    issuer: issuerField,
    validUntil: validUntilField,
    holderPublicKey: holderPubKeyFields,
  });

  const proofValue = encodeProofValue(
    signatureData.signature.R8,
    signatureData.signature.S
  );

  const vc: VerifiableCredential = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://w3id.org/security/data-integrity/v2",
    ],
    id: credentialId,
    type: ["VerifiableCredential", "UniquenessIdentityCredential"],
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
      holderPublicKey: {
        type: "BabyJubJubPublicKey",
        x: holderPublicKey.x.toString(),
        y: holderPublicKey.y.toString(),
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

  assertDemoVcShape(vc);
  return vc;
}
