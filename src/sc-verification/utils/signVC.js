import fs from "fs/promises";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

// 💥 Patch hash function (this is required in ESM!)
ed.etc.sha512Sync = sha512;

const canonicalize = (obj) => JSON.stringify(obj, Object.keys(obj).sort(), 0);

const toBase64Url = (buf) =>
  Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

const main = async () => {
  const raw = await fs.readFile("../inputs/credential.json", "utf-8");
  const vc = JSON.parse(raw);
  delete vc.proof;

  const message = new TextEncoder().encode(canonicalize(vc));

  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKey(privateKey);

  const signature = await ed.sign(message, privateKey);
  const signatureB64 = Buffer.from(signature).toString("base64");

  const jwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: toBase64Url(publicKey),
  };

  vc.proof = {
    type: "JsonWebSignature2020",
    created: new Date().toISOString(),
    proofPurpose: "assertionMethod",
    verificationMethod: "did:key:z6Mk...#key-1",
    jws: signatureB64,
    publicKeyJwk: jwk,
  };

  await fs.writeFile("signedVC.json", JSON.stringify(vc, null, 2));
  console.log("✅ Signed VC written to signedVC.json");
};

main().catch(console.error);
