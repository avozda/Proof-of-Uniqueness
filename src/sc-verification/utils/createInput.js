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

  console.log("🔍 Testing the FIXED signed VC...\n");

  // Read the FIXED signed VC (not the old one)
  const rawVc = await fs.readFile("../inputs/signedVC.json", "utf-8");
  const signedVc = JSON.parse(rawVc);

  console.log("1️⃣ Reading signed VC:");
  console.log("Proof type:", signedVc.proof.type);
  console.log(
    "Public key multibase:",
    signedVc.proof.verificationMethod.publicKeyMultibase
  );

  // Unpack signature and public key with debugging
  const signatureB64 = signedVc.proof.proofValue;
  const signatureBuffer = Buffer.from(signatureB64, "base64");

  console.log("\n🔍 Debugging signature unpacking:");
  console.log("Signature B64:", signatureB64);
  console.log("Signature buffer length:", signatureBuffer.length);
  console.log("Signature buffer hex:", signatureBuffer.toString("hex"));

  const unpackedSignature = eddsa.unpackSignature(signatureBuffer);
  console.log("Unpacked signature success:", unpackedSignature !== null);

  console.log("\n🔍 Debugging public key unpacking:");
  const publicKeyMultibase =
    signedVc.proof.verificationMethod.publicKeyMultibase;
  console.log("Public key multibase:", publicKeyMultibase);

  const decodedBytes = base58btc.decode(publicKeyMultibase);
  console.log("Decoded bytes length:", decodedBytes.length);
  console.log("Decoded bytes hex:", Buffer.from(decodedBytes).toString("hex"));
  console.log(
    "First few bytes:",
    Array.from(decodedBytes.slice(0, 5)).map(
      (b) => `0x${b.toString(16).padStart(2, "0")}`
    )
  );

  // FIX: Use slice(1) instead of slice(2) based on the debugging output
  const publicKeyBytes = decodedBytes.slice(1);
  console.log("Public key bytes after slice(1):");
  console.log("  Length:", publicKeyBytes.length);
  console.log("  Hex:", Buffer.from(publicKeyBytes).toString("hex"));

  const unpackedPublicKey = eddsa.babyJub.unpackPoint(publicKeyBytes);
  console.log("Unpacked public key result:", unpackedPublicKey !== null);

  if (unpackedPublicKey === null) {
    console.log("❌ Public key unpacking still failed!");
    return;
  }

  console.log("\n2️⃣ Unpacked components:");
  console.log(
    "Public Key:",
    unpackedPublicKey.map((coord) => F.toObject(coord).toString())
  );
  console.log(
    "Signature R8:",
    unpackedSignature.R8.map((coord) => F.toObject(coord).toString())
  );

  // Recreate the message EXACTLY as in signVCFixed.js
  const vcWithoutProof = JSON.parse(JSON.stringify(signedVc));
  delete vcWithoutProof.proof;
  const canonicalPayload = canonicalize(vcWithoutProof);
  console.log("\n3️⃣ Message reconstruction:");
  console.log("Canonical payload:", canonicalPayload);
  console.log("Canonical payload length:", canonicalPayload.length);

  const messageHash = poseidon1([stringToBigInt(canonicalPayload)]);
  const messageHashBytes = F.e(messageHash);

  console.log("Message hash (BigInt):", messageHash.toString());
  console.log("Message hash (Field):", messageHashBytes);

  // Verify signature
  console.log("\n4️⃣ Verification:");
  const isValid = eddsa.verifyPoseidon(
    messageHashBytes,
    unpackedSignature,
    unpackedPublicKey
  );
  console.log("Signature is valid:", isValid);

  if (!isValid) {
    console.log("❌ Signature verification failed!");
    console.log("This should not happen if signVCFixed.js worked correctly");
  } else {
    console.log("✅ Signature verification passed!");
    console.log("The fixed signature works correctly!");

    console.log("\n🎯 Creating circuit inputs:");
    // Create the circuit inputs - FIXED: Use original BigInt values and F.toObject correctly
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
      signature_M: messageHash.toString(), // FIXED: Use original BigInt messageHash, not field element
      firstName: stringToBigInt(
        signedVc.credentialSubject.givenName
      ).toString(),
      secondName: stringToBigInt(
        signedVc.credentialSubject.familyName
      ).toString(),
      dob: BigInt(
        Date.parse(signedVc.credentialSubject.dateOfBirth)
      ).toString(),
      nationality: stringToBigInt(
        signedVc.credentialSubject.nationality
      ).toString(),
    };

    console.log("\n🔍 Final inputs preview:");
    console.log("signature_M:", circuitInputs.signature_M);
    console.log("signature_S:", circuitInputs.signature_S);

    await fs.writeFile(
      "../inputs/input.json",
      JSON.stringify(circuitInputs, null, 2)
    );
    console.log("✅ Circuit inputs saved to input.json");
  }
}

main().catch(console.error);
