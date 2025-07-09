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
  console.log("EdDSA object built successfully.");

  const inputFilePath = "../inputs/credential.json";
  const outputFilePath = "../inputs/signedVC.json";

  console.log(`Loading credential from ${inputFilePath}...`);

  const vcFile = await fs.readFile(inputFilePath, "utf8");
  const vcObject = JSON.parse(vcFile);

  const privateKey = Buffer.from("00".repeat(31) + "01", "hex");
  const publicKey = eddsa.prv2pub(privateKey);
  console.log("Generated EdDSA key pair.");

  const dataToHash = JSON.parse(JSON.stringify(vcObject));
  const canonicalPayload = canonicalize(dataToHash);
  const messageHash = poseidon1([stringToBigInt(canonicalPayload)]);
  console.log("Hashed credential data with Poseidon.");

  const messageHashBytes = eddsa.babyJub.F.e(messageHash);
  const signature = eddsa.signPoseidon(privateKey, messageHashBytes);
  console.log("Signed hash with EdDSA private key.");

  const prefixedPublicKey = new Uint8Array(publicKey[0].length + 2);
  prefixedPublicKey.set([0xed, 0x01]);
  prefixedPublicKey.set(publicKey[0], 2);
  const publicKeyMultibase = base58btc.encode(prefixedPublicKey);
  const didKey = `did:key:${publicKeyMultibase}`;

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
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
