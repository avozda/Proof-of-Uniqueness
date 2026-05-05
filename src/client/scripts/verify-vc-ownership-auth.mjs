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

async function main() {
  const [mode, ...rest] = process.argv.slice(2);
  if (!mode) {
    throw new Error("Expected subcommand: string-to-field");
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
