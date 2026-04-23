import fs from "node:fs/promises";
import path from "node:path";
import { Noir } from "@noir-lang/noir_js";
import { BarretenbergBackend } from "@noir-lang/backend_barretenberg";
import { buildPoseidon } from "circomlibjs";

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
    throw new Error("Expected subcommand: verify-proof or string-to-field");
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

  if (mode === "string-to-field") {
    const args = parseKeyValueArgs(rest);
    const value = args.get("value");
    if (!value) {
      throw new Error("Missing required arg --value");
    }

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

    process.stdout.write(`${stringToField(value).toString()}\n`);
    return;
  }

  throw new Error(`Unknown subcommand: ${mode}`);
}

main().catch((err) => {
  const msg = err instanceof Error ? err.stack ?? err.message : String(err);
  process.stderr.write(`${msg}\n`);
  process.exit(1);
});
