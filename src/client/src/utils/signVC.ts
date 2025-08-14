import { buildEddsa } from "circomlibjs";
import { poseidon1 } from "poseidon-lite";
import { base58btc } from "multiformats/bases/base58";
import type { VerifiableCredential, FormData } from "../types/credentials";

function stringToBigInt(str: string): bigint {
  return BigInt("0x" + Buffer.from(str).toString("hex"));
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const canonicalize = (obj: any): string =>
  JSON.stringify(obj, Object.keys(obj).sort(), 0);

export async function signVerifiableCredential(
  vcObject: VerifiableCredential,
  privateKeyHex?: string
): Promise<VerifiableCredential> {
  const eddsa = await buildEddsa();
  const F = eddsa.babyJub.F;

  // Generate EdDSA key pair
  const privateKey = Buffer.from(
    privateKeyHex ||
      "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "hex"
  );
  const publicKey = eddsa.prv2pub(privateKey);

  // Hash the credential data
  const canonicalPayload = canonicalize(vcObject);
  const messageHash = poseidon1([stringToBigInt(canonicalPayload)]);
  const messageHashField = F.e(messageHash);

  // Sign the hash
  const signature = eddsa.signPoseidon(privateKey, messageHashField);

  // Verify signature
  const isValid = eddsa.verifyPoseidon(messageHashField, signature, publicKey);
  if (!isValid) {
    throw new Error("Signature verification failed");
  }

  // Create public key multibase encoding
  const packedPublicKey = eddsa.babyJub.packPoint(publicKey);
  const prefixedPublicKey = new Uint8Array(packedPublicKey.length + 1);
  prefixedPublicKey.set([0xed]);
  prefixedPublicKey.set(packedPublicKey, 1);

  const publicKeyMultibase = base58btc.encode(prefixedPublicKey);
  const didKey = `did:key:${publicKeyMultibase}`;

  // Verify encoding/decoding cycle
  const decodedBytes = base58btc.decode(publicKeyMultibase);
  const extractedKeyBytes = decodedBytes.slice(1);
  const unpackedTestKey = eddsa.babyJub.unpackPoint(extractedKeyBytes);

  if (!unpackedTestKey) {
    throw new Error("Public key encoding/decoding verification failed");
  }

  // Create a copy of the VC object and add proof
  const signedVC = JSON.parse(JSON.stringify(vcObject)) as VerifiableCredential;
  signedVC.proof = {
    type: "Ed25519Signature2020",
    created: new Date().toISOString(),
    proofPurpose: "assertionMethod",
    verificationMethod: {
      id: didKey,
      type: "Ed25519VerificationKey2020",
      controller: vcObject.issuer,
      publicKeyMultibase: publicKeyMultibase,
    },
    proofValue: Buffer.from(eddsa.packSignature(signature)).toString("base64"),
  };

  // Final verification
  const vcWithoutProof = JSON.parse(JSON.stringify(signedVC));
  delete vcWithoutProof.proof;
  const finalCanonical = canonicalize(vcWithoutProof);
  const finalHash = poseidon1([stringToBigInt(finalCanonical)]);
  const finalHashField = F.e(finalHash);

  const packedSig = eddsa.packSignature(signature);
  const unpackedSig = eddsa.unpackSignature(packedSig);

  const finalVerification = eddsa.verifyPoseidon(
    finalHashField,
    unpackedSig,
    publicKey
  );

  if (!finalVerification) {
    throw new Error("Final verification failed");
  }

  return signedVC;
}

// Utility function to create a credential from form data
export function createCredentialFromData(
  formData: FormData
): VerifiableCredential {
  return {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1",
    ],
    type: ["VerifiableCredential", "IdentityCredential"],
    issuer: formData.issuer || "https://example.edu",
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      givenName: formData.givenName,
      familyName: formData.familyName,
      dateOfBirth: formData.dateOfBirth,
      nationality: formData.nationality,
    },
  };
}
