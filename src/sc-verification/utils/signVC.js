import fs from "fs/promises";
import { buildEddsa } from "circomlibjs";
import pkg from "poseidon-lite";
const { poseidon1 } = pkg;
import { base58btc } from "multiformats/bases/base58";

function stringToBigInt(str) {
  return BigInt("0x" + Buffer.from(str).toString("hex"));
}

const canonicalize = (obj) => JSON.stringify(obj, Object.keys(obj).sort(), 0);

async function main() {
  const eddsa = await buildEddsa();
  const F = eddsa.babyJub.F;

  const inputFilePath = "../inputs/credential.json";
  const outputFilePath = "../inputs/signedVC.json";

  const vcFile = await fs.readFile(inputFilePath, "utf8");
  const vcObject = JSON.parse(vcFile);

  // Generate EdDSA key pair
  const privateKey = Buffer.from(
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

  // Add proof to VC
  vcObject.proof = {
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

  await fs.writeFile(outputFilePath, JSON.stringify(vcObject, null, 2));
  console.log(`✅ Signed VC saved to ${outputFilePath}`);

  // Final verification
  const vcWithoutProof = JSON.parse(JSON.stringify(vcObject));
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
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
