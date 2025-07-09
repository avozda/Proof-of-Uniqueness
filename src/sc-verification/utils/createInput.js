import fs from "fs/promises";
import pkg from "poseidon-lite";
const { poseidon1 } = pkg;

const canonicalize = (obj) => JSON.stringify(obj, Object.keys(obj).sort(), 0);

function stringToBigInt(str) {
  return BigInt("0x" + Buffer.from(str).toString("hex"));
}

async function main() {
  const vcFilePath = "../inputs/signedVC.json";
  const outputFilePath = "../inputs/input.json";

  console.log(`Reading signed VC from ${vcFilePath}...`);

  const rawVc = await fs.readFile(vcFilePath, "utf-8");
  const signedVc = JSON.parse(rawVc);

  const { givenName, familyName, nationality, dateOfBirth } =
    signedVc.credentialSubject;

  const signatureB64 = signedVc.proof.proofValue;
  const publicKeyMultibase =
    signedVc.proof.verificationMethod.publicKeyMultibase;

  const vcWithoutProof = JSON.parse(JSON.stringify(signedVc));
  delete vcWithoutProof.proof;

  const canonicalPayload = canonicalize(vcWithoutProof);
  console.log(canonicalPayload);
  const payloadHash = poseidon1([stringToBigInt(canonicalPayload)]);
  console.log("Payload hash created successfully.");

  const circuitInputs = {
    firstname: givenName,
    lastname: familyName,
    nationality: nationality,
    dob: dateOfBirth,
    sig: signatureB64,
    pub: publicKeyMultibase,
    payload: payloadHash.toString(),
  };

  await fs.writeFile(outputFilePath, JSON.stringify(circuitInputs, null, 2));
  console.log(`\n✅ Success! Circuit inputs saved to ${outputFilePath}`);
}

main().catch((err) => {
  console.error("An error occurred:", err);
});
