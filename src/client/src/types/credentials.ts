export interface CredentialSubject {
  givenName: string;
  familyName: string;
  dateOfBirth: string;
  nationality: string;
  [key: string]: string | number | boolean | null;
}

export interface VerifiableCredential {
  "@context": string[];
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: CredentialSubject;
  proof?: {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: {
      id: string;
      type: string;
      controller: string;
      publicKeyMultibase: string;
    };
    proofValue: string;
  };
}

export interface SignedVerifiableCredential extends VerifiableCredential {
  proof: {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: {
      id: string;
      type: string;
      controller: string;
      publicKeyMultibase: string;
    };
    proofValue: string;
  };
}

export interface CircuitInputs {
  publicKey: [string, string];
  signature_R8: [string, string];
  signature_S: string;
  signature_M: string;
  firstName: string;
  secondName: string;
  dob: string;
  nationality: string;
  [key: string]: string | [string, string];
}

export interface FormData {
  givenName: string;
  familyName: string;
  dateOfBirth: string;
  nationality: string;
  issuer?: string;
}
