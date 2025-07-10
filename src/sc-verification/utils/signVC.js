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
  console.log("EdDSA object built successfully.");

  const inputFilePath = "../inputs/credential.json";
  const outputFilePath = "../inputs/signedVC.json";

  console.log(`Loading credential from ${inputFilePath}...`);

  const vcFile = await fs.readFile(inputFilePath, "utf8");
  const vcObject = JSON.parse(vcFile);

  // Use a proper private key (32 bytes of random-ish data, but deterministic for testing)
  const privateKey = Buffer.from(
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "hex"
  );
  const publicKey = eddsa.prv2pub(privateKey);
  console.log("Generated EdDSA key pair.");
  console.log("Private key:", privateKey.toString("hex"));
  console.log(
    "Public key coords:",
    publicKey.map((coord) => F.toObject(coord).toString())
  );

  // Hash the credential data
  const canonicalPayload = canonicalize(vcObject);
  console.log("Canonical payload:", canonicalPayload);

  const messageHash = poseidon1([stringToBigInt(canonicalPayload)]);
  console.log("Message hash:", messageHash.toString());

  const messageHashField = F.e(messageHash);
  console.log("Message hash (field):", F.toObject(messageHashField).toString());

  // Sign the hash
  const signature = eddsa.signPoseidon(privateKey, messageHashField);
  console.log("Signature created:");
  console.log(
    "  R8:",
    signature.R8.map((coord) => F.toObject(coord).toString())
  );

  // Verify immediately
  const immediateVerification = eddsa.verifyPoseidon(
    messageHashField,
    signature,
    publicKey
  );
  console.log("Immediate verification:", immediateVerification);

  if (!immediateVerification) {
    console.error("❌ Immediate signature verification failed!");
    return;
  }

  // FIXED: Create public key multibase encoding correctly
  console.log("\n🔍 Debugging public key encoding:");

  // Pack the public key point to bytes
  const packedPublicKey = eddsa.babyJub.packPoint(publicKey);
  console.log("Packed public key length:", packedPublicKey.length);
  console.log(
    "Packed public key hex:",
    Buffer.from(packedPublicKey).toString("hex")
  );

  // Create the multibase encoding with proper prefix - FIXED: only use 0xed prefix
  const prefixedPublicKey = new Uint8Array(packedPublicKey.length + 1);
  prefixedPublicKey.set([0xed]); // Only ed prefix, not ed01
  prefixedPublicKey.set(packedPublicKey, 1);

  console.log("Prefixed public key length:", prefixedPublicKey.length);
  console.log(
    "Prefixed public key hex:",
    Buffer.from(prefixedPublicKey).toString("hex")
  );

  const publicKeyMultibase = base58btc.encode(prefixedPublicKey);
  const didKey = `did:key:${publicKeyMultibase}`;

  console.log("Public key multibase:", publicKeyMultibase);

  // Test the encoding/decoding cycle
  console.log("\n🔧 Testing encoding/decoding cycle:");
  const decodedBytes = base58btc.decode(publicKeyMultibase);
  console.log("Decoded bytes length:", decodedBytes.length);
  console.log("Decoded bytes hex:", Buffer.from(decodedBytes).toString("hex"));

  const extractedKeyBytes = decodedBytes.slice(1); // Skip only the ed prefix
  console.log("Extracted key bytes length:", extractedKeyBytes.length);
  console.log(
    "Extracted key bytes hex:",
    Buffer.from(extractedKeyBytes).toString("hex")
  );

  const unpackedTestKey = eddsa.babyJub.unpackPoint(extractedKeyBytes);
  console.log("Test unpacking successful:", unpackedTestKey !== null);

  if (unpackedTestKey) {
    console.log(
      "Test unpacked coords:",
      unpackedTestKey.map((coord) => F.toObject(coord).toString())
    );

    // Verify they match
    const coordsMatch = unpackedTestKey.every(
      (coord, i) =>
        F.toObject(coord).toString() === F.toObject(publicKey[i]).toString()
    );
    console.log("Coordinates match:", coordsMatch);
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
  console.log(`\n✅ Success! Signed VC saved to ${outputFilePath}`);

  // Final verification test
  console.log("\n🔍 Final verification test:");
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
  console.log("Final verification:", finalVerification);
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
