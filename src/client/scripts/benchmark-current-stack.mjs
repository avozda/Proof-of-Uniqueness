import fs from "node:fs";
import { performance } from "node:perf_hooks";

import { buildEddsa, buildPoseidon } from "circomlibjs";
import { Noir } from "@noir-lang/noir_js";
import { BarretenbergBackend } from "@noir-lang/backend_barretenberg";

const SIGNATURE_DOMAIN = "eddsa-bjj-poseidon-2024:v1";

const FIELD_LABELS = [
  2118198470571567473536145588563504n,
  2118198470571567473536145588563505n,
  2217739077219273223255122644505107646662330724n,
  6582114n,
  115944579229042n,
  1851878757n,
  133442057126172576218444921n,
  641669309618204160221840285997001192639266124648n,
  34793344991585695257288930408n,
  7562616n,
  2183735902496290402157n,
  559036391039114700679532n,
  1986218340n,
];

const BB_BACKEND_OPTIONS = {
  threads: 1,
  memory: {
    initial: 4096,
    maximum: 65536,
  },
};

function bytesToField(bytes) {
  let v = 0n;
  for (const b of bytes) {
    v = (v << 8n) | BigInt(b);
  }
  return v;
}

function stringToFieldSimple(value) {
  const bytes = new TextEncoder().encode(value);
  if (bytes.length > 31) {
    throw new Error(`string too long for simple field encoding: ${value}`);
  }
  return bytesToField(bytes);
}

function stringToField(value, poseidon) {
  const bytes = new TextEncoder().encode(value);
  const chunks = [];
  for (let i = 0; i < bytes.length; i += 31) {
    chunks.push(bytesToField(bytes.slice(i, Math.min(i + 31, bytes.length))));
  }
  if (chunks.length === 1) {
    return chunks[0];
  }
  return poseidon.F.toObject(poseidon(chunks));
}

function dateToField(iso) {
  return BigInt(Math.floor(new Date(iso).getTime() / 1000));
}

function hash2(left, right, poseidon) {
  return poseidon.F.toObject(poseidon([left, right]));
}

function hashN(values, poseidon) {
  return poseidon.F.toObject(poseidon(values));
}

function merkleRoot16(leaves, poseidon) {
  const level0 = new Array(8);
  for (let i = 0; i < 8; i += 1) {
    level0[i] = hash2(leaves[2 * i], leaves[(2 * i) + 1], poseidon);
  }
  const level1 = new Array(4);
  for (let i = 0; i < 4; i += 1) {
    level1[i] = hash2(level0[2 * i], level0[(2 * i) + 1], poseidon);
  }
  const level2 = new Array(2);
  for (let i = 0; i < 2; i += 1) {
    level2[i] = hash2(level1[2 * i], level1[(2 * i) + 1], poseidon);
  }
  return hash2(level2[0], level2[1], poseidon);
}

function signPoseidon(privateKey, messageField, eddsa) {
  const sig = eddsa.signPoseidon(privateKey, eddsa.F.e(messageField));
  return {
    R8: [eddsa.F.toObject(sig.R8[0]), eddsa.F.toObject(sig.R8[1])],
    S: BigInt(sig.S),
  };
}

function toStringArray(values) {
  return values.map((x) => x.toString());
}

function average(values) {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function buildAuthInputs(eddsa, poseidon) {
  const issuerPrivateKey = Uint8Array.from(
    Array.from({ length: 32 }, (_, i) => ((i + 11) * 7) % 256),
  );
  const holderPrivateKey = Uint8Array.from(
    Array.from({ length: 32 }, (_, i) => ((i + 19) * 13) % 256),
  );

  const issuerPubPoint = eddsa.prv2pub(issuerPrivateKey);
  const holderPubPoint = eddsa.prv2pub(holderPrivateKey);

  const issuerPubKey = [
    eddsa.F.toObject(issuerPubPoint[0]),
    eddsa.F.toObject(issuerPubPoint[1]),
  ];
  const holderPubKey = [
    eddsa.F.toObject(holderPubPoint[0]),
    eddsa.F.toObject(holderPubPoint[1]),
  ];

  const validFromIso = "2026-04-09T12:00:00.000Z";
  const validUntilIso = "2031-04-09T12:00:00.000Z";

  const fieldValues = [
    holderPubKey[0],
    holderPubKey[1],
    stringToField("urn:person:testperson123456", poseidon),
    dateToField("1990-06-15"),
    stringToField("did:babyjubjub:test-issuer", poseidon),
    stringToField("Jan Novak", poseidon),
    stringToField("Czech", poseidon),
    hashN([stringToField("Mala Strana 1, Prague", poseidon)], poseidon),
    stringToField("Prague", poseidon),
    0n,
    dateToField(validFromIso),
    dateToField(validUntilIso),
    stringToField("urn:uuid:f656befd-ba14-4b17-a5e2-002c52bba66a", poseidon),
  ];

  const leaves = new Array(16).fill(0n);
  for (let i = 0; i < 13; i += 1) {
    leaves[i] = hash2(FIELD_LABELS[i], fieldValues[i], poseidon);
  }

  const root = merkleRoot16(leaves, poseidon);
  const domainSeparator = stringToFieldSimple(SIGNATURE_DOMAIN);
  const signedMessage = hash2(domainSeparator, root, poseidon);

  const issuerSig = signPoseidon(issuerPrivateKey, signedMessage, eddsa);

  const hashId = hashN(
    [
      fieldValues[12],
      fieldValues[2],
      fieldValues[5],
      fieldValues[3],
      fieldValues[8],
      fieldValues[9],
      fieldValues[6],
      fieldValues[7],
      fieldValues[10],
    ],
    poseidon,
  );

  const holderSig = signPoseidon(holderPrivateKey, hashId, eddsa);

  return {
    domain_separator: domainSeparator.toString(),
    merkle_leaves: toStringArray(leaves),
    field_values: toStringArray(fieldValues),
    signer_pub_key: toStringArray(issuerPubKey),
    signature_r8: toStringArray(issuerSig.R8),
    signature_s: issuerSig.S.toString(),
    holder_signature_r8: toStringArray(holderSig.R8),
    holder_signature_s: holderSig.S.toString(),
    beta: "123456789",
  };
}

function buildMicroBenchContext(eddsa, poseidon) {
  const signerPrivateKey = Uint8Array.from(
    Array.from({ length: 32 }, (_, i) => ((i + 31) * 5) % 256),
  );
  const holderPrivateKey = Uint8Array.from(
    Array.from({ length: 32 }, (_, i) => ((i + 17) * 11) % 256),
  );

  const holderPubPoint = eddsa.prv2pub(holderPrivateKey);
  const holderPubKey = [
    eddsa.F.toObject(holderPubPoint[0]),
    eddsa.F.toObject(holderPubPoint[1]),
  ];

  const fieldValues = [
    holderPubKey[0],
    holderPubKey[1],
    stringToField("urn:person:testperson123456", poseidon),
    dateToField("1990-06-15"),
    stringToField("did:babyjubjub:test-issuer", poseidon),
    stringToField("Jan Novak", poseidon),
    stringToField("Czech", poseidon),
    hashN([stringToField("Mala Strana 1, Prague", poseidon)], poseidon),
    stringToField("Prague", poseidon),
    0n,
    dateToField("2026-04-09T12:00:00.000Z"),
    dateToField("2031-04-09T12:00:00.000Z"),
    stringToField("urn:uuid:f656befd-ba14-4b17-a5e2-002c52bba66a", poseidon),
  ];

  const hashIdInputs = [
    fieldValues[12],
    fieldValues[2],
    fieldValues[5],
    fieldValues[3],
    fieldValues[8],
    fieldValues[9],
    fieldValues[6],
    fieldValues[7],
    fieldValues[10],
  ];

  const signMessage = hashN(hashIdInputs, poseidon);

  return {
    signerPrivateKey,
    signMessage,
    hashIdInputs,
    fieldValues,
  };
}

function preprocessVcCommitment(fieldValues, poseidon) {
  const leaves = new Array(16).fill(0n);
  for (let i = 0; i < 13; i += 1) {
    leaves[i] = hash2(FIELD_LABELS[i], fieldValues[i], poseidon);
  }
  return merkleRoot16(leaves, poseidon);
}

function benchmarkMicroOperations(eddsa, poseidon, runs = 3, iterations = 200) {
  const context = buildMicroBenchContext(eddsa, poseidon);
  const rows = [];

  for (let run = 0; run < runs; run += 1) {
    for (let i = 0; i < 20; i += 1) {
      hashN(context.hashIdInputs, poseidon);
      signPoseidon(context.signerPrivateKey, context.signMessage, eddsa);
      preprocessVcCommitment(context.fieldValues, poseidon);
    }

    let sink = 0n;

    let t0 = performance.now();
    for (let i = 0; i < iterations; i += 1) {
      sink ^= hashN(context.hashIdInputs, poseidon);
    }
    let t1 = performance.now();
    const poseidonHashMs = (t1 - t0) / iterations;

    t0 = performance.now();
    for (let i = 0; i < iterations; i += 1) {
      const sig = signPoseidon(
        context.signerPrivateKey,
        context.signMessage + BigInt(i + run),
        eddsa,
      );
      sink ^= sig.S;
    }
    t1 = performance.now();
    const eddsaSignMs = (t1 - t0) / iterations;

    t0 = performance.now();
    for (let i = 0; i < iterations; i += 1) {
      sink ^= preprocessVcCommitment(context.fieldValues, poseidon);
    }
    t1 = performance.now();
    const vcPreprocessMs = (t1 - t0) / iterations;

    rows.push({
      run: run + 1,
      poseidonHashMs,
      eddsaSignMs,
      vcPreprocessMs,
      sink: sink.toString(),
    });
  }

  return {
    runs,
    iterationsPerRun: iterations,
    perRun: rows,
    averages: {
      poseidonHashMs: average(rows.map((r) => r.poseidonHashMs)),
      eddsaSignMs: average(rows.map((r) => r.eddsaSignMs)),
      vcPreprocessMs: average(rows.map((r) => r.vcPreprocessMs)),
    },
  };
}

async function benchmarkCircuit(circuitPath, inputs, iterations) {
  const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf8"));
  const noir = new Noir(circuit);
  const backend = new BarretenbergBackend(circuit, BB_BACKEND_OPTIONS);

  const rows = [];

  try {
    for (let i = 0; i < iterations; i += 1) {
      const t0 = performance.now();
      const { witness } = await noir.execute(inputs);
      const t1 = performance.now();

      const proofData = await backend.generateProof(witness);
      const t2 = performance.now();

      const verified = await backend.verifyProof(proofData);
      const t3 = performance.now();

      rows.push({
        witnessMs: t1 - t0,
        proveMs: t2 - t1,
        verifyMs: t3 - t2,
        proofBytes: proofData.proof.length,
        publicInputsCount: proofData.publicInputs.length,
        verified,
      });
    }
  } finally {
    await backend.destroy();
  }

  const avg = (k) => rows.reduce((s, r) => s + r[k], 0) / rows.length;

  return {
    iterations,
    runs: rows,
    averages: {
      witnessMs: avg("witnessMs"),
      proveMs: avg("proveMs"),
      verifyMs: avg("verifyMs"),
    },
  };
}

async function main() {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();

  const microBenchmarks = benchmarkMicroOperations(eddsa, poseidon, 3, 200);

  const authInputs = buildAuthInputs(eddsa, poseidon);

  const authResult = await benchmarkCircuit(
    "./public/circuits/vc_blinded_query_auth_proof.json",
    authInputs,
    3,
  );

  console.log(
    JSON.stringify(
      {
        nodeVersion: process.version,
        microBenchmarks,
        authProof: authResult,
      },
      null,
      2,
    ),
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
