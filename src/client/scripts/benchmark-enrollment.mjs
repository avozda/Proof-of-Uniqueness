// Benchmark the vc_oprf_enrollment_proof circuit (witness gen, prove, verify).
// The OPRF transcript is synthesised locally so the script is fully self-contained
// (no network, no node operator needed).

import fs from "node:fs";
import { performance } from "node:perf_hooks";

import { buildEddsa, buildPoseidon } from "circomlibjs";
import { Noir } from "@noir-lang/noir_js";
import { BarretenbergBackend } from "@noir-lang/backend_barretenberg";
import {
  BABYJUBJUB_SUBGROUP_GENERATOR_AFFINE,
  Fr,
  babyjubjub,
  blindQuery,
  dlogEqualityProof,
  dlogEqualityVerify,
  prepareBlindingFactor,
  randomBlindingFactor,
  unblindResponse,
} from "@taceo/oprf-core";

const SIGNATURE_DOMAIN = "eddsa-bjj-poseidon-2024:v1";
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
  641669309618204160221840285997001192639266124648n,
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

function bytesToField(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function stringToFieldSimple(value) {
  const bytes = new TextEncoder().encode(value);
  if (bytes.length > 31) throw new Error(`string too long: ${value}`);
  return bytesToField(bytes);
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
    domainSeparator,
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
    domain_separator: ctx.domainSeparator.toString(),
    merkle_leaves: ctx.leaves.map((x) => x.toString()),
    field_values: ctx.fieldValues.map((x) => x.toString()),
    signer_pub_key: ctx.issuerPubKey.map((x) => x.toString()),
    signature_r8: ctx.issuerSig.R8.map((x) => x.toString()),
    signature_s: ctx.issuerSig.S.toString(),
    holder_signature_r8: ctx.holderSig.R8.map((x) => norm(x)),
    holder_signature_s: norm(ctx.holderSig.S),
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
    valid_until: ctx.fieldValues[11].toString(),
    holder_pub_key_x: ctx.fieldValues[0].toString(),
    holder_pub_key_y: ctx.fieldValues[1].toString(),
    issuer_pub_key_x: ctx.issuerPubKey[0].toString(),
    issuer_pub_key_y: ctx.issuerPubKey[1].toString(),
    oprf_key_id: "3",
    oprf_epoch: "1",
  };
}

async function benchmarkCircuit(circuitPath, inputs, iterations) {
  const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf8"));
  const noir = new Noir(circuit);
  const backend = new BarretenbergBackend(circuit, BB_BACKEND_OPTIONS);

  const rows = [];

  try {
    // One warm-up iteration, not counted.
    {
      const { witness } = await noir.execute(inputs);
      const proofData = await backend.generateProof(witness);
      const ok = await backend.verifyProof(proofData);
      if (!ok) throw new Error("warm-up self-check failed");
    }

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
        publicInputs: proofData.publicInputs.length,
        verified,
      });
    }
  } finally {
    await backend.destroy();
  }

  return {
    iterations,
    runs: rows,
    averages: {
      witnessMs: average(rows.map((r) => r.witnessMs)),
      proveMs: average(rows.map((r) => r.proveMs)),
      verifyMs: average(rows.map((r) => r.verifyMs)),
      proofBytes: rows[0].proofBytes,
      publicInputs: rows[0].publicInputs,
    },
    medians: {
      witnessMs: median(rows.map((r) => r.witnessMs)),
      proveMs: median(rows.map((r) => r.proveMs)),
      verifyMs: median(rows.map((r) => r.verifyMs)),
    },
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
