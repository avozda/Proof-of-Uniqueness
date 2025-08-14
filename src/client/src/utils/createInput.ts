import { buildEddsa } from "circomlibjs";
import { poseidon1 } from "poseidon-lite";
import { base58btc } from "multiformats/bases/base58";
import type {
  SignedVerifiableCredential,
  CircuitInputs,
} from "../types/credentials";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const canonicalize = (obj: any): string =>
  JSON.stringify(obj, Object.keys(obj).sort(), 0);

function stringToBigInt(str: string): bigint {
  return BigInt("0x" + Buffer.from(str).toString("hex"));
}

export async function createCircuitInputs(
  signedVc: SignedVerifiableCredential
): Promise<CircuitInputs> {
  const eddsa = await buildEddsa();
  const F = eddsa.babyJub.F;

  // Unpack signature and public key
  const signatureB64 = signedVc.proof.proofValue;
  const signatureBuffer = Buffer.from(signatureB64, "base64");
  const unpackedSignature = eddsa.unpackSignature(signatureBuffer);

  const publicKeyMultibase =
    signedVc.proof.verificationMethod.publicKeyMultibase;
  const decodedBytes = base58btc.decode(publicKeyMultibase);
  const publicKeyBytes = decodedBytes.slice(1);
  const unpackedPublicKey = eddsa.babyJub.unpackPoint(publicKeyBytes);

  if (unpackedPublicKey === null) {
    throw new Error("Failed to unpack public key");
  }

  // Recreate the message hash
  const vcWithoutProof = JSON.parse(JSON.stringify(signedVc));
  delete vcWithoutProof.proof;
  const canonicalPayload = canonicalize(vcWithoutProof);
  const messageHash = poseidon1([stringToBigInt(canonicalPayload)]);
  const messageHashBytes = F.e(messageHash);

  // Verify signature
  const isValid = eddsa.verifyPoseidon(
    messageHashBytes,
    unpackedSignature,
    unpackedPublicKey
  );

  if (!isValid) {
    throw new Error("Signature verification failed");
  }

  // Create circuit inputs
  const circuitInputs: CircuitInputs = {
    publicKey: [
      F.toObject(unpackedPublicKey[0]).toString(),
      F.toObject(unpackedPublicKey[1]).toString(),
    ],
    signature_R8: [
      F.toObject(unpackedSignature.R8[0]).toString(),
      F.toObject(unpackedSignature.R8[1]).toString(),
    ],
    signature_S: unpackedSignature.S.toString(),
    signature_M: messageHash.toString(),
    firstName: stringToBigInt(signedVc.credentialSubject.givenName).toString(),
    secondName: stringToBigInt(
      signedVc.credentialSubject.familyName
    ).toString(),
    dob: BigInt(Date.parse(signedVc.credentialSubject.dateOfBirth)).toString(),
    nationality: stringToBigInt(
      signedVc.credentialSubject.nationality
    ).toString(),
  };

  return circuitInputs;
}

// Helper function to download circuit inputs as JSON
export function downloadCircuitInputs(
  circuitInputs: CircuitInputs,
  filename: string = "circuit_inputs.json"
): void {
  const dataStr = JSON.stringify(circuitInputs, null, 2);
  const dataBlob = new Blob([dataStr], { type: "application/json" });
  const url = URL.createObjectURL(dataBlob);

  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
