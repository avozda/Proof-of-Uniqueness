import fs from "node:fs/promises";
import path from "node:path";
import { Noir } from "@noir-lang/noir_js";
import { BarretenbergBackend } from "@noir-lang/backend_barretenberg";
import { buildEddsa, buildPoseidon } from "circomlibjs";

function parseKeyValueArgs(argv) {
  const out = new Map();
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i];
    const v = argv[i + 1];
    if (!k?.startsWith("--") || v == null) {
      throw new Error("Expected arguments: --circuit <path> --proof <path> --public-inputs <path>");
    }
    out.set(k.slice(2), v);
  }

  return out;
}

function chunk32ToBigintBE(bytes) {
  let v = 0n;
  for (let i = 0; i < bytes.length; i += 1) {
    v = (v << 8n) | BigInt(bytes[i]);
  }
  return v;
}

function chunk32ToBigintLE(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    v = (v << 8n) | BigInt(bytes[i]);
  }
  return v;
}

function decodePublicInputs(raw, mode) {
  if (raw.length % 32 !== 0) {
    throw new Error(`public inputs file length must be multiple of 32, got ${raw.length}`);
  }
  const out = [];
  for (let i = 0; i < raw.length; i += 32) {
    const chunk = raw.subarray(i, i + 32);
    const v = mode === "le" ? chunk32ToBigintLE(chunk) : chunk32ToBigintBE(chunk);
    out.push(v.toString());
  }
  return out;
}

async function verifyWithMode(circuit, proofBytes, publicBytes, mode) {
  const backend = new BarretenbergBackend(circuit, { threads: 1 });
  try {
    const publicInputs = decodePublicInputs(publicBytes, mode);
    const verified = await backend.verifyProof({
      proof: new Uint8Array(proofBytes),
      publicInputs,
    });
    return { verified, publicInputsCount: publicInputs.length };
  } finally {
    await backend.destroy();
  }
}

async function main() {
  const [mode, ...rest] = process.argv.slice(2);
  if (!mode) {
    throw new Error("Expected subcommand: verify-proof or verify-holder-sig");
  }

  if (mode === "verify-proof") {
    const args = parseKeyValueArgs(rest);
    const circuit = args.get("circuit");
    const proof = args.get("proof");
    const publicInputs = args.get("public-inputs");
    if (!circuit || !proof || !publicInputs) {
      throw new Error("Missing required args --circuit, --proof, --public-inputs");
    }

    const [circuitRaw, proofBytes, publicBytes] = await Promise.all([
      fs.readFile(path.resolve(circuit), "utf8"),
      fs.readFile(path.resolve(proof)),
      fs.readFile(path.resolve(publicInputs)),
    ]);
    const circuitJson = JSON.parse(circuitRaw);
    void new Noir(circuitJson);

    const le = await verifyWithMode(circuitJson, proofBytes, publicBytes, "le");
    if (le.verified) {
      process.stdout.write(`ok mode=le public_inputs=${le.publicInputsCount}\n`);
      return;
    }

    const be = await verifyWithMode(circuitJson, proofBytes, publicBytes, "be");
    if (be.verified) {
      process.stdout.write(`ok mode=be public_inputs=${be.publicInputsCount}\n`);
      return;
    }

    throw new Error("verification failed for both le and be public input decoding");
  }

  if (mode === "verify-holder-sig") {
    const args = parseKeyValueArgs(rest);
    const requestId = args.get("request-id");
    const blindedX = args.get("blinded-x");
    const blindedY = args.get("blinded-y");
    const holderPubX = args.get("holder-pub-x");
    const holderPubY = args.get("holder-pub-y");
    const sigR8x = args.get("sig-r8x");
    const sigR8y = args.get("sig-r8y");
    const sigS = args.get("sig-s");
    if (!requestId || !blindedX || !blindedY || !holderPubX || !holderPubY || !sigR8x || !sigR8y || !sigS) {
      throw new Error("Missing required holder signature arguments");
    }

    const eddsa = await buildEddsa();
    const poseidon = await buildPoseidon();

    const stringToField = (str) => {
      const bytes = new TextEncoder().encode(str);
      const chunks = [];
      for (let i = 0; i < bytes.length; i += 31) {
        const chunk = bytes.slice(i, Math.min(i + 31, bytes.length));
        let value = 0n;
        for (let j = 0; j < chunk.length; j += 1) {
          value = (value << 8n) | BigInt(chunk[j]);
        }
        chunks.push(value);
      }
      if (chunks.length === 1) return chunks[0];
      return poseidon.F.toObject(poseidon(chunks));
    };

    const domain = stringToField("holder-bjj-oprf-auth:v1");
    const requestField = stringToField(requestId);
    const msg = poseidon.F.toObject(
      poseidon([domain, requestField, BigInt(blindedX), BigInt(blindedY)]),
    );

    const inFieldRange = (v) => {
      const x = BigInt(v);
      const FIELD_MODULUS = BigInt(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
      );
      return x > 0n && x < FIELD_MODULUS;
    };

    if (!inFieldRange(holderPubX) || !inFieldRange(holderPubY)) {
      throw new Error("holder public key coordinates are out of field range");
    }

    const ok = eddsa.verifyPoseidon(
      eddsa.F.e(msg),
      {
        R8: [eddsa.F.e(BigInt(sigR8x)), eddsa.F.e(BigInt(sigR8y))],
        S: BigInt(sigS),
      },
      [eddsa.F.e(BigInt(holderPubX)), eddsa.F.e(BigInt(holderPubY))],
    );

    if (!ok) {
      throw new Error("holder request signature invalid");
    }
    process.stdout.write("ok holder-signature\n");
    return;
  }

  throw new Error(`Unknown subcommand: ${mode}`);
}

main().catch((err) => {
  const msg = err instanceof Error ? err.stack ?? err.message : String(err);
  process.stderr.write(`${msg}\n`);
  process.exit(1);
});
