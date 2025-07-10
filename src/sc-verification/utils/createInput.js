import fs from "fs/promises";
import { buildEddsa } from "circomlibjs";
import pkg from "poseidon-lite";
const { poseidon1 } = pkg;
import { base58btc } from "multiformats/bases/base58";

const canonicalize = (obj) => JSON.stringify(obj, Object.keys(obj).sort(), 0);

function stringToBigInt(str) {
  return BigInt("0x" + Buffer.from(str).toString("hex"));
}

async function main() {
  const eddsa = await buildEddsa();
  const F = eddsa.babyJub.F;

  const rawVc = await fs.readFile("../inputs/signedVC.json", "utf-8");
  const signedVc = JSON.parse(rawVc);

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
  const circuitInputs = {
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

  await fs.writeFile(
    "../inputs/input.json",
    JSON.stringify(circuitInputs, null, 2)
  );

  console.log("✅ Circuit inputs saved to input.json");
}

main().catch(console.error);
