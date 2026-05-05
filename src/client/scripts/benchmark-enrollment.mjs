// Benchmark the vc_oprf_enrollment_proof circuit (witness gen and proving).
// The OPRF transcript is synthesised locally so the script is fully self-contained
// (no network, no node operator needed).

import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";

import { buildEddsa, buildPoseidon } from "circomlibjs";
import { Noir } from "@noir-lang/noir_js";
import { BarretenbergBackend } from "@noir-lang/backend_barretenberg";
import {
  BABYJUBJUB_SUBGROUP_GENERATOR_AFFINE,
  babyjubjub,
  blindQuery,
  dlogEqualityProof,
  dlogEqualityVerify,
  prepareBlindingFactor,
  randomBlindingFactor,
  unblindResponse,
} from "@taceo/oprf-core";

const FIELD_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const FIELD_LABELS = [
  2118198470571567473536145588563504n,
  2118198470571567473536145588563505n,
  2217739077219273223255122644505107646662330724n,
  6582114n,
  115944579229042n,
  1851878757n,
  133442057126172576218444921n,
  34793344991585695257288930408n,
  7562616n,
  2183735902496290402157n,
  559036391039114700679532n,
  1986218340n,
];

const BB_BACKEND_OPTIONS = {
  threads: 1,
  memory: { initial: 4096, maximum: 65536 },
};
const BENCH_WALLET_PRIVATE_KEY = 0xa11cen;
// vm.addr(0xA11CE), so Foundry can sign the enrollment authorization.
const BENCH_WALLET_ADDRESS = 0xe05fcc23807536bee418f142d19fa0d21bb0cff7n;

function bytesToField(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function stringToField(value, poseidon) {
  const bytes = new TextEncoder().encode(value);
  const chunks = [];
  for (let i = 0; i < bytes.length; i += 31) {
    chunks.push(bytesToField(bytes.slice(i, Math.min(i + 31, bytes.length))));
  }
  if (chunks.length === 1) return chunks[0];
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
  const l0 = new Array(8);
  for (let i = 0; i < 8; i += 1) {
    l0[i] = hash2(leaves[2 * i], leaves[2 * i + 1], poseidon);
  }
  const l1 = new Array(4);
  for (let i = 0; i < 4; i += 1) {
    l1[i] = hash2(l0[2 * i], l0[2 * i + 1], poseidon);
  }
  const l2 = new Array(2);
  for (let i = 0; i < 2; i += 1) {
    l2[i] = hash2(l1[2 * i], l1[2 * i + 1], poseidon);
  }
  return hash2(l2[0], l2[1], poseidon);
}

function signPoseidon(privateKey, messageField, eddsa) {
  const sig = eddsa.signPoseidon(privateKey, eddsa.F.e(messageField));
  return {
    R8: [eddsa.F.toObject(sig.R8[0]), eddsa.F.toObject(sig.R8[1])],
    S: BigInt(sig.S),
  };
}

function average(values) {
  return values.reduce((s, v) => s + v, 0) / values.length;
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const m = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[m] : (sorted[m - 1] + sorted[m]) / 2;
}

function toHex(value, bytes = 32) {
  return `0x${BigInt(value).toString(16).padStart(bytes * 2, "0")}`;
}

function bytesToHex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function buildVcContext(eddsa, poseidon) {
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
    stringToField("Prague", poseidon),
    0n,
    dateToField(validFromIso),
    dateToField(validUntilIso),
    stringToField("urn:uuid:f656befd-ba14-4b17-a5e2-002c52bba66a", poseidon),
  ];

  const leaves = new Array(16).fill(0n);
  for (let i = 0; i < 12; i += 1) {
    leaves[i] = hash2(FIELD_LABELS[i], fieldValues[i], poseidon);
  }

  const root = merkleRoot16(leaves, poseidon);
  const signedMessage = hashN([root], poseidon);

  const issuerSig = signPoseidon(issuerPrivateKey, signedMessage, eddsa);

  const hashId = hashN(
    [
      fieldValues[2],
      fieldValues[5],
      fieldValues[3],
      fieldValues[7],
      fieldValues[8],
      fieldValues[6],
      fieldValues[9],
    ],
    poseidon,
  );
  const holderAuthorizationMessage = hashN(
    [hashId, BENCH_WALLET_ADDRESS],
    poseidon,
  );
  const holderSig = signPoseidon(
    holderPrivateKey,
    holderAuthorizationMessage,
    eddsa,
  );

  return {
    fieldValues,
    leaves,
    issuerPubKey,
    holderPubKey,
    issuerSig,
    holderSig,
    hashId,
  };
}

// Synthesise a valid OPRF transcript locally for the given hashId.
// Picks K at random, computes blindedResponse = K * blindedQuery, builds DLEQ.
function synthesiseOprfTranscript(hashId) {
  const beta = randomBlindingFactor();
  const blinded = blindQuery(hashId, beta);

  // K is just any random non-zero scalar in Fr; randomBlindingFactor() fits the bill.
  const K = randomBlindingFactor();

  const G = BABYJUBJUB_SUBGROUP_GENERATOR_AFFINE;
  const oprfPk = babyjubjub.Point.fromAffine(G).multiply(K).toAffine();
  const blindedResponse = babyjubjub.Point.fromAffine(blinded)
    .multiply(K)
    .toAffine();
  const unblinded = unblindResponse(blindedResponse, prepareBlindingFactor(beta));

  // Sanity-check the DLEQ before returning.
  const dlog = dlogEqualityProof(blinded, K);
  dlogEqualityVerify(dlog, oprfPk, blinded, blindedResponse, G);

  return {
    beta,
    oprfPk,
    blinded,
    blindedResponse,
    unblinded,
    dlog,
  };
}

function buildEnrollmentInputs(ctx, transcript) {
  const norm = (x) => {
    const r = x % FIELD_MODULUS;
    return (r < 0n ? r + FIELD_MODULUS : r).toString();
  };

  return {
    merkle_leaves: ctx.leaves.map((x) => x.toString()),
    field_values: ctx.fieldValues.map((x) => x.toString()),
    signer_pub_key: ctx.issuerPubKey.map((x) => x.toString()),
    signature_r8: ctx.issuerSig.R8.map((x) => x.toString()),
    signature_s: ctx.issuerSig.S.toString(),
    holder_signature_r8: ctx.holderSig.R8.map((x) => x.toString()),
    holder_signature_s: ctx.holderSig.S.toString(),
    beta: norm(transcript.beta),
    oprf_pk: { x: norm(transcript.oprfPk.x), y: norm(transcript.oprfPk.y) },
    dlog_e: norm(transcript.dlog.e),
    dlog_s: norm(transcript.dlog.s),
    oprf_response_blinded: {
      x: norm(transcript.blindedResponse.x),
      y: norm(transcript.blindedResponse.y),
    },
    oprf_response: {
      x: norm(transcript.unblinded.x),
      y: norm(transcript.unblinded.y),
    },
    valid_until: ctx.fieldValues[10].toString(),
    issuer_pub_key_x: ctx.issuerPubKey[0].toString(),
    issuer_pub_key_y: ctx.issuerPubKey[1].toString(),
    wallet_address: BENCH_WALLET_ADDRESS.toString(),
  };
}

async function benchmarkCircuit(circuitPath, inputs, iterations) {
  const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf8"));
  const noir = new Noir(circuit);
  const backend = new BarretenbergBackend(circuit, BB_BACKEND_OPTIONS);

  const witnessRows = [];
  const proveRows = [];
  let proofData;

  try {
    // Warm up Noir execution and Barretenberg proving before timed samples.
    {
      const { witness } = await noir.execute(inputs);
      await backend.generateProof(witness);
    }

    for (let i = 0; i < iterations; i += 1) {
      const t0 = performance.now();
      await noir.execute(inputs);
      const t1 = performance.now();
      witnessRows.push({ witnessMs: t1 - t0 });
    }

    const { witness } = await noir.execute(inputs);
    for (let i = 0; i < iterations; i += 1) {
      const t0 = performance.now();
      proofData = await backend.generateProof(witness);
      const t1 = performance.now();
      proveRows.push({ proveMs: t1 - t0 });
    }
  } finally {
    await backend.destroy();
  }

  return {
    iterations,
    witness: {
      runs: witnessRows,
      averageMs: average(witnessRows.map((r) => r.witnessMs)),
      medianMs: median(witnessRows.map((r) => r.witnessMs)),
    },
    proving: {
      runs: proveRows,
      averageMs: average(proveRows.map((r) => r.proveMs)),
      medianMs: median(proveRows.map((r) => r.proveMs)),
    },
    averages: {
      witnessMs: average(witnessRows.map((r) => r.witnessMs)),
      proveMs: average(proveRows.map((r) => r.proveMs)),
      proofBytes: proofData.proof.length,
      publicInputs: proofData.publicInputs.length,
    },
    medians: {
      witnessMs: median(witnessRows.map((r) => r.witnessMs)),
      proveMs: median(proveRows.map((r) => r.proveMs)),
    },
    proofData,
  };
}

async function main() {
  const eddsa = await buildEddsa();
  const poseidon = await buildPoseidon();

  console.error("Building VC context and synthesising OPRF transcript...");
  const ctx = buildVcContext(eddsa, poseidon);
  const transcript = synthesiseOprfTranscript(ctx.hashId);
  const enrollmentInputs = buildEnrollmentInputs(ctx, transcript);

  const iterations = parseInt(process.env.ITER || "3", 10);
  console.error(
    `Running enrollment circuit benchmark (${iterations} iterations + 1 warm-up)...`,
  );
  const enrollmentResult = await benchmarkCircuit(
    "./public/circuits/vc_oprf_enrollment_proof.json",
    enrollmentInputs,
    iterations,
  );

  if (process.env.FOUNDRY_FIXTURE) {
    const fixture = {
      proof: bytesToHex(enrollmentResult.proofData.proof),
      publicSignals: enrollmentResult.proofData.publicInputs.map((x) =>
        toHex(x),
      ),
      walletPrivateKey: toHex(BENCH_WALLET_PRIVATE_KEY),
      walletAddress: toHex(BENCH_WALLET_ADDRESS, 20),
      circuit: "vc_oprf_enrollment_proof",
    };
    fs.mkdirSync(path.dirname(process.env.FOUNDRY_FIXTURE), {
      recursive: true,
    });
    fs.writeFileSync(
      process.env.FOUNDRY_FIXTURE,
      `${JSON.stringify(fixture, null, 2)}\n`,
    );
  }
  delete enrollmentResult.proofData;

  console.log(
    JSON.stringify(
      {
        nodeVersion: process.version,
        circuit: "vc_oprf_enrollment_proof",
        enrollmentProof: enrollmentResult,
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
