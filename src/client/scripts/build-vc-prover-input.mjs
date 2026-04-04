import fs from "node:fs/promises";
import bs58 from "bs58";
import { buildPoseidon } from "circomlibjs";

const VC_FIELD_LABELS = [
  "holderPubKey.0",
  "holderPubKey.1",
  "credentialSubjectId",
  "dob",
  "issuer",
  "name",
  "nationality",
  "permanentAddressHash",
  "placeOfBirth",
  "sex",
  "validFrom",
  "validUntil",
  "vcId",
];

const SIGNATURE_DOMAIN = "eddsa-bjj-poseidon-2024:v1";

function parseArgs(argv) {
  const args = new Map();
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key.startsWith("--") || value === undefined) {
      throw new Error("Expected arguments in format: --vc-path <path> --out <path>");
    }
    args.set(key.slice(2), value);
    i += 1;
  }
  const vcPath = args.get("vc-path");
  const outPath = args.get("out");
  if (!vcPath || !outPath) {
    throw new Error("Missing required args: --vc-path and --out");
  }
  return { vcPath, outPath };
}

function bytesToBigint(bytes) {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

function stringToFieldSimple(str) {
  const bytes = new TextEncoder().encode(str);
  if (bytes.length > 31) {
    throw new Error(`Label too long for single field: ${str}`);
  }
  return bytesToBigint(bytes);
}

function decodeProofValue(proofValue) {
  if (!proofValue.startsWith("z")) {
    throw new Error("Expected multibase base58-btc proofValue with z prefix");
  }
  const bytes = bs58.decode(proofValue.slice(1));
  if (bytes.length !== 96) {
    throw new Error(`Invalid proofValue length: ${bytes.length}`);
  }
  const r8x = bytesToBigint(bytes.slice(0, 32));
  const r8y = bytesToBigint(bytes.slice(32, 64));
  const s = bytesToBigint(bytes.slice(64, 96));
  return { signatureR8: [r8x, r8y], signatureS: s };
}

function decodeDidKey(verificationMethod) {
  const did = verificationMethod.split("#")[0];
  const prefix = "did:babyjubjub:";
  if (!did.startsWith(prefix)) {
    throw new Error(`Invalid verificationMethod DID: ${did}`);
  }
  const multibase = did.slice(prefix.length);
  if (!multibase.startsWith("z")) {
    throw new Error("Expected did:babyjubjub multibase value with z prefix");
  }
  const bytes = bs58.decode(multibase.slice(1));
  if (bytes.length !== 64) {
    throw new Error(`Invalid did key length: ${bytes.length}`);
  }
  return [bytesToBigint(bytes.slice(0, 32)), bytesToBigint(bytes.slice(32, 64))];
}

function sexToField(sex) {
  switch (String(sex).toLowerCase()) {
    case "male":
      return 0n;
    case "female":
      return 1n;
    case "other":
      return 2n;
    default:
      return 3n;
  }
}

function dateToField(dateStr) {
  return BigInt(Math.floor(new Date(dateStr).getTime() / 1000));
}

function stringToField(str, poseidon) {
  const bytes = new TextEncoder().encode(str);
  const chunks = [];
  for (let i = 0; i < bytes.length; i += 31) {
    chunks.push(bytesToBigint(bytes.slice(i, Math.min(i + 31, bytes.length))));
  }
  if (chunks.length === 1) {
    return chunks[0];
  }
  const hash = poseidon(chunks);
  return poseidon.F.toObject(hash);
}

function poseidonHash(inputs, poseidon) {
  return poseidon.F.toObject(poseidon(inputs));
}

function computeLeaves(fieldValuesOrdered, poseidon) {
  const leaves = VC_FIELD_LABELS.map((label, i) => {
    const labelField = stringToFieldSimple(label);
    return poseidonHash([labelField, fieldValuesOrdered[i]], poseidon);
  });
  while (leaves.length < 16) {
    leaves.push(0n);
  }
  return leaves;
}

function toTomlArray(values) {
  return `[${values.map((v) => `"${v.toString()}"`).join(", ")}]`;
}

function toToml(content) {
  return Object.entries(content)
    .map(([k, v]) => `${k} = ${v}`)
    .join("\n");
}

async function main() {
  const { vcPath, outPath } = parseArgs(process.argv.slice(2));
  const vcRaw = await fs.readFile(vcPath, "utf8");
  const vc = JSON.parse(vcRaw);
  const poseidon = await buildPoseidon();

  const subject = vc.credentialSubject;
  const holderSig = subject.holderBindingSignature;
  const issuerSig = decodeProofValue(vc.proof.proofValue);
  const signerPubKey = decodeDidKey(vc.proof.verificationMethod);

  const fieldValuesOrdered = [
    BigInt(subject.holderPublicKey.x),
    BigInt(subject.holderPublicKey.y),
    stringToField(subject.id, poseidon),
    dateToField(subject.dateOfBirth),
    stringToField(vc.issuer.id, poseidon),
    stringToField(subject.name, poseidon),
    stringToField(subject.nationality, poseidon),
    BigInt(subject.permanentAddressHash.value),
    stringToField(subject.placeOfBirth, poseidon),
    sexToField(subject.sex),
    dateToField(vc.validFrom),
    dateToField(vc.validUntil),
    stringToField(vc.id, poseidon),
  ];

  const content = {
    domain_separator: `"${stringToFieldSimple(SIGNATURE_DOMAIN).toString()}"`,
    merkle_leaves: toTomlArray(computeLeaves(fieldValuesOrdered, poseidon)),
    field_values: toTomlArray(fieldValuesOrdered),
    signer_pub_key: toTomlArray(signerPubKey),
    signature_r8: toTomlArray(issuerSig.signatureR8),
    signature_s: `"${issuerSig.signatureS.toString()}"`,
    holder_signature_r8: toTomlArray([BigInt(holderSig.r8x), BigInt(holderSig.r8y)]),
    holder_signature_s: `"${BigInt(holderSig.s).toString()}"`,
  };

  await fs.writeFile(outPath, `${toToml(content)}\n`, "utf8");
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
