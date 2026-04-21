import { Noir } from "@noir-lang/noir_js";
import { BarretenbergBackend } from "@noir-lang/backend_barretenberg";
import {
  aggregateError,
  finishSessions,
  generateChallengeRequest,
  initSessions,
  isNodeError,
  toOprfUri,
  verifyDlogEquality,
} from "@taceo/oprf-client";
import {
  BABYJUBJUB_SUBGROUP_GENERATOR_AFFINE,
  blindQuery,
  dlogEqualityVerify,
  finalizeOutput,
  prepareBlindingFactor,
  randomBlindingFactor,
  unblindResponse,
} from "@taceo/oprf-core";

import type { VerifiableCredential } from "./vc";
import type { HolderKeyPair } from "./holderKey";
import {
  buildHolderOprfAuthMessage,
  buildRevokeChallengeMessage,
  signMessageWithHolderKey,
} from "./holderKey";
import {
  VC_FIELD_LABELS,
  computeFieldLeaf,
  dateToField,
  decodeProofValue,
  extractPublicKeyFromVerificationMethod,
  getDomainSeparator,
  poseidonHash,
  sexToField,
  stringToField,
} from "./did";

const FIELD_MODULUS = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);
const OPRF_DS_N = 24546418369108709687614662004n;
const BACKEND_BARRETENBERG_VERSION = "0.36.0";
const BB_BACKEND_OPTIONS = {
  threads: 1,
  memory: {
    // Larger initial memory avoids wasm traps in browser proving for bigger circuits.
    initial: 4096,
    maximum: 65536,
  },
} as const;

type CompiledCircuit = {
  bytecode: string;
  hash?: string;
  noir_version?: string;
  abi: {
    parameters: Array<{
      name: string;
      visibility: "public" | "private";
    }>;
  };
};

function isCircuitVersionCompatibleWithBackend(noirVersion?: string): boolean {
  if (!noirVersion) return true;
  return noirVersion.startsWith("0.36.");
}

function assertCircuitCompatibility(circuit: CompiledCircuit): void {
  if (isCircuitVersionCompatibleWithBackend(circuit.noir_version)) return;
  throw new Error(
    `Incompatible Noir/Barretenberg toolchain: circuit noir_version=${
      circuit.noir_version ?? "<unknown>"
    } but @noir-lang/backend_barretenberg is ${BACKEND_BARRETENBERG_VERSION}. Recompile the circuit with Noir 0.36.x, or use a backend package that matches the circuit's noir_version.`,
  );
}

interface RawProofData {
  proof: Uint8Array;
  publicInputs: string[];
}

interface BackendSelfCheckResult {
  verified: boolean;
  vkHash?: string;
}

export interface VcOprfEnrollmentProofPackage {
  proof: `0x${string}`;
  publicSignals: `0x${string}`[];
  decoded: {
    oprfPkX: string;
    oprfPkY: string;
    validUntil: string;
    holderPubKeyX: string;
    holderPubKeyY: string;
    issuerPubKeyX: string;
    issuerPubKeyY: string;
    oprfKeyId: string;
    oprfEpoch: string;
    nullifier: string;
  };
}

export interface VcRevocationProofPackage {
  proof: `0x${string}`;
  publicSignals: `0x${string}`[];
  challengeBlockNumber: bigint;
  decoded: {
    nullifier: string;
    holderPubKeyX: string;
    holderPubKeyY: string;
    challengeBlockHash: string;
  };
}

export interface OprfNetworkConfig {
  nodeBases: string[];
  threshold: number;
  apiKey: string;
  authModule: "vc-ownership";
}

type ProgressReporter = (message: string) => void;

type OprfTranscriptInput = {
  beta: bigint;
  oprfPkX: bigint;
  oprfPkY: bigint;
  dlogE: bigint;
  dlogS: bigint;
  oprfResponseBlindedX: bigint;
  oprfResponseBlindedY: bigint;
  oprfResponseX: bigint;
  oprfResponseY: bigint;
  oprfKeyId: bigint;
  oprfEpoch: bigint;
};

function toHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}`;
}

function toBytes32Hex(value: bigint): `0x${string}` {
  if (value < 0n) throw new Error("Negative values are not allowed");
  if (value >= FIELD_MODULUS) throw new Error("Signal value exceeds field modulus");
  return `0x${value.toString(16).padStart(64, "0")}`;
}

function normalizeField(value: bigint): bigint {
  const x = value % FIELD_MODULUS;
  return x < 0n ? x + FIELD_MODULUS : x;
}

function fieldToBytes32BE(x: bigint): Uint8Array {
  let v = normalizeField(x);
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function fieldToBytes32LE(x: bigint): Uint8Array {
  let v = normalizeField(x);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function publicInputsToBytes(
  publicInputs: string[],
  endianness: "be" | "le" = "be",
): Uint8Array {
  const out = new Uint8Array(publicInputs.length * 32);
  for (let i = 0; i < publicInputs.length; i += 1) {
    const asBytes =
      endianness === "le"
        ? fieldToBytes32LE(BigInt(publicInputs[i]))
        : fieldToBytes32BE(BigInt(publicInputs[i]));
    out.set(asBytes, i * 32);
  }
  return out;
}

function padMerkleLeaves(leaves: bigint[]): bigint[] {
  const out = [...leaves];
  while (out.length < 16) out.push(0n);
  return out;
}

function buildFieldValuesOrdered(vc: VerifiableCredential): bigint[] {
  const s = vc.credentialSubject;
  return [
    BigInt(s.holderPublicKey.x),
    BigInt(s.holderPublicKey.y),
    stringToField(s.id),
    dateToField(s.dateOfBirth),
    stringToField(vc.issuer.id),
    stringToField(s.name),
    stringToField(s.nationality),
    BigInt(s.permanentAddressHash.value),
    stringToField(s.placeOfBirth),
    sexToField(s.sex),
    dateToField(vc.validFrom),
    dateToField(vc.validUntil),
    stringToField(vc.id),
  ];
}

function buildMerkleLeaves(fieldValuesOrdered: bigint[]): bigint[] {
  const leaves = VC_FIELD_LABELS.map((label, i) =>
    computeFieldLeaf(label, fieldValuesOrdered[i]),
  );
  return padMerkleLeaves(leaves);
}

function decodeIssuerSig(vc: VerifiableCredential): {
  signerPubKey: [bigint, bigint];
  signatureR8: [bigint, bigint];
  signatureS: bigint;
} {
  const sig = decodeProofValue(vc.proof.proofValue);
  const pk = extractPublicKeyFromVerificationMethod(vc.proof.verificationMethod);
  return {
    signerPubKey: [BigInt(pk.x), BigInt(pk.y)],
    signatureR8: [BigInt(sig.signatureR8[0]), BigInt(sig.signatureR8[1])],
    signatureS: BigInt(sig.signatureS),
  };
}

async function loadCircuitArtifact(): Promise<CompiledCircuit> {
  const res = await fetch("/circuits/vc_oprf_enrollment_proof.json");
  if (!res.ok) {
    throw new Error(
      "Missing /circuits/vc_oprf_enrollment_proof.json. Copy it from src/circuits/vc_oprf_enrollment_proof/target/",
    );
  }
  return (await res.json()) as CompiledCircuit;
}

async function loadVcBlindedQueryAuthCircuitArtifact(): Promise<CompiledCircuit> {
  const res = await fetch("/circuits/vc_blinded_query_auth_proof.json");
  if (!res.ok) {
    throw new Error(
      "Missing /circuits/vc_blinded_query_auth_proof.json. Copy it from src/circuits/vc_blinded_query_auth_proof/target/",
    );
  }
  return (await res.json()) as CompiledCircuit;
}

async function loadVcRevocationCircuitArtifact(): Promise<CompiledCircuit> {
  const res = await fetch("/circuits/vc_revocation_proof.json");
  if (!res.ok) {
    throw new Error(
      "Missing /circuits/vc_revocation_proof.json. Copy it from src/circuits/vc_revocation_proof/target/",
    );
  }
  return (await res.json()) as CompiledCircuit;
}

function computeHashIdFromVc(vc: VerifiableCredential): bigint {
  const fieldValues = buildFieldValuesOrdered(vc);
  return normalizeField(
    poseidonHash([
      fieldValues[12],
      fieldValues[2],
      fieldValues[5],
      fieldValues[3],
      fieldValues[8],
      fieldValues[9],
      fieldValues[6],
      fieldValues[7],
      fieldValues[10],
    ]),
  );
}

function buildNoirInputs(
  vc: VerifiableCredential,
  issuerPublicKey: { x: bigint; y: bigint },
  holderKeyPair: HolderKeyPair,
  transcript: OprfTranscriptInput,
) {
  const fieldValues = buildFieldValuesOrdered(vc);
  const merkleLeaves = buildMerkleLeaves(fieldValues);
  const issuerSig = decodeIssuerSig(vc);
  const hashId = computeHashIdFromVc(vc);
  const holderBindSig = signMessageWithHolderKey(holderKeyPair.privateKey, hashId);

  const holderX = BigInt(vc.credentialSubject.holderPublicKey.x);
  const holderY = BigInt(vc.credentialSubject.holderPublicKey.y);
  if (holderX !== holderKeyPair.publicKey.x || holderY !== holderKeyPair.publicKey.y) {
    throw new Error("Holder key in VC does not match active holder keypair");
  }
  if (issuerSig.signerPubKey[0] !== issuerPublicKey.x || issuerSig.signerPubKey[1] !== issuerPublicKey.y) {
    throw new Error("Issuer key in VC proof does not match active issuer key");
  }

  if (fieldValues[11] <= 0n) {
    throw new Error("validUntil field is not a positive unix timestamp");
  }

  const debugInputs = {
    domain_separator: getDomainSeparator().toString(),
    merkle_leaves: merkleLeaves.map((x) => x.toString()),
    field_values: fieldValues.map((x) => x.toString()),
    signer_pub_key: issuerSig.signerPubKey.map((x) => x.toString()),
    signature_r8: issuerSig.signatureR8.map((x) => x.toString()),
    signature_s: issuerSig.signatureS.toString(),
    holder_signature_r8: holderBindSig.R8.map((x) => normalizeField(x).toString()),
    holder_signature_s: normalizeField(holderBindSig.S).toString(),
    beta: transcript.beta.toString(),
    oprf_pk: {
      x: transcript.oprfPkX.toString(),
      y: transcript.oprfPkY.toString(),
    },
    dlog_e: transcript.dlogE.toString(),
    dlog_s: transcript.dlogS.toString(),
    oprf_response_blinded: {
      x: transcript.oprfResponseBlindedX.toString(),
      y: transcript.oprfResponseBlindedY.toString(),
    },
    oprf_response: {
      x: transcript.oprfResponseX.toString(),
      y: transcript.oprfResponseY.toString(),
    },
    valid_until: fieldValues[11].toString(),
    holder_pub_key_x: holderX.toString(),
    holder_pub_key_y: holderY.toString(),
    issuer_pub_key_x: issuerPublicKey.x.toString(),
    issuer_pub_key_y: issuerPublicKey.y.toString(),
    oprf_key_id: transcript.oprfKeyId.toString(),
    oprf_epoch: transcript.oprfEpoch.toString(),
  };
  return debugInputs;
}

async function generateWithNoir(
  circuit: CompiledCircuit,
  inputs: Record<string, unknown>,
): Promise<RawProofData> {
  // Ensure browser fetch of bb.js runtime WASM resolves to real wasm binaries.
  // bb.js expects these at root-relative URLs in browser bundles.
  await Promise.all([
    fetch("/barretenberg.wasm"),
    fetch("/barretenberg-threads.wasm"),
    fetch("/acvm_js_bg.wasm"),
    fetch("/noirc_abi_wasm_bg.wasm"),
  ]).then((responses) => {
    for (const res of responses) {
      if (!res.ok) {
        throw new Error(`Required WASM asset missing: ${res.url}`);
      }
    }
  });

  const inspectWasmResponse = async (response: Response): Promise<void> => {
    try {
      const bytes = new Uint8Array(await response.clone().arrayBuffer());
      const magic = Array.from(bytes.slice(0, 4))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
      const prefixText = new TextDecoder()
        .decode(bytes.slice(0, 16))
        .replace(/\s+/g, " ");
      const contentType = response.headers.get("content-type") ?? "<none>";
      const isWasmMagic = bytes[0] === 0x00 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d;

      void magic;
      void prefixText;
      void contentType;
      void isWasmMagic;
    } catch (err) {
      void err;
    }
  };

  const realBbFetch = globalThis.fetch;
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const requested =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;

    let response: Response;

    if (requested.includes("barretenberg-threads.wasm")) {
      response = await realBbFetch("/barretenberg-threads.wasm", init);
      await inspectWasmResponse(response);
      return response;
    }
    if (requested.includes("barretenberg.wasm")) {
      response = await realBbFetch("/barretenberg.wasm", init);
      await inspectWasmResponse(response);
      return response;
    }
    if (requested.includes("noirc_abi_wasm_bg.wasm")) {
      response = await realBbFetch("/noirc_abi_wasm_bg.wasm", init);
      await inspectWasmResponse(response);
      return response;
    }
    if (requested.includes("acvm_js_bg.wasm")) {
      response = await realBbFetch("/acvm_js_bg.wasm", init);
      await inspectWasmResponse(response);
      return response;
    }
    if (requested.includes(".wasm")) {
      response = await realBbFetch(input, init);
      await inspectWasmResponse(response);
      return response;
    }

    return realBbFetch(input, init);
  };

  const wrapNoirError = (err: unknown): never => {
    void err;

    if (!(err instanceof Error)) throw err;

    const m = err.message || String(err);
    if (m.includes("Cannot satisfy constraint")) {
      throw new Error(
        "Constraint unsatisfied while generating proof. This usually means the live OPRF transcript values are inconsistent with the enrollment circuit relations.",
      );
    }
    if (m.includes("expected magic word") || m.includes("Incorrect response MIME type")) {
      throw new Error(
        "WASM asset loading failed for Noir runtime. Ensure /noirc_abi_wasm_bg.wasm and /acvm_js_bg.wasm are reachable and not rewritten by dev server.",
      );
    }
    if (m.includes("unreachable")) {
      throw new Error(
        "Barretenberg runtime trapped (unreachable) during proof generation. This is typically a browser wasm memory/runtime issue or a Noir/backend ACIR compatibility mismatch.",
      );
    }
    throw err;
  };

  const verifyInBackend = async (
    backend: BarretenbergBackend,
    proofData: RawProofData,
  ): Promise<BackendSelfCheckResult> => {
    const verified = await backend.verifyProof(proofData as never);
    let vkHash: string | undefined;
    try {
      const recursiveArtifacts = await backend.generateRecursiveProofArtifacts(
        proofData as never,
        proofData.publicInputs.length,
      );
      vkHash = recursiveArtifacts.vkHash;
    } catch {
      // Optional diagnostic only.
    }
    return { verified, vkHash };
  };

  const withTimeout = async <T>(label: string, ms: number, p: Promise<T>): Promise<T> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        p,
        new Promise<T>((_, reject) => {
          timer = globalThis.setTimeout(() => {
            reject(new Error(`${label} timed out after ${ms}ms`));
          }, ms);
        }),
      ]);
    } finally {
      if (timer != null) {
        globalThis.clearTimeout(timer);
      }
    }
  };

  try {
    const noir = new Noir(circuit as never);
    const { witness } = await withTimeout(
      "noir.execute",
      120_000,
      noir.execute(inputs as never),
    ).catch(wrapNoirError);
    void witness;

    const backend = new BarretenbergBackend(circuit as never, BB_BACKEND_OPTIONS);
    try {
      const proofData =
        (await withTimeout(
          "backend.generateProof",
          180_000,
          backend.generateProof(witness),
        ).catch(wrapNoirError)) as RawProofData;
      const selfCheck = await withTimeout(
        "backend.verifyProof",
        60_000,
        verifyInBackend(backend, proofData as RawProofData),
      ).catch(wrapNoirError);
      if (!selfCheck.verified) {
        throw new Error("Local backend rejected the generated proof during self-check");
      }

      return proofData;
    } finally {
      await backend.destroy();
    }
  } catch (err) {
    throw err;
  } finally {
    globalThis.fetch = realBbFetch;
  }
}

function buildVcBlindedQueryAuthNoirInputs(
  vc: VerifiableCredential,
  issuerPublicKey: { x: bigint; y: bigint },
  holderKeyPair: HolderKeyPair,
  beta: bigint,
) {
  const fieldValues = buildFieldValuesOrdered(vc);
  const merkleLeaves = buildMerkleLeaves(fieldValues);
  const issuerSig = decodeIssuerSig(vc);
  const hashId = computeHashIdFromVc(vc);
  const holderBindSig = signMessageWithHolderKey(holderKeyPair.privateKey, hashId);

  const holderX = BigInt(vc.credentialSubject.holderPublicKey.x);
  const holderY = BigInt(vc.credentialSubject.holderPublicKey.y);
  if (holderX !== holderKeyPair.publicKey.x || holderY !== holderKeyPair.publicKey.y) {
    throw new Error("Holder key in VC does not match active holder keypair");
  }
  if (issuerSig.signerPubKey[0] !== issuerPublicKey.x || issuerSig.signerPubKey[1] !== issuerPublicKey.y) {
    throw new Error("Issuer key in VC proof does not match active issuer key");
  }

  return {
    domain_separator: getDomainSeparator().toString(),
    merkle_leaves: merkleLeaves.map((x) => x.toString()),
    field_values: fieldValues.map((x) => x.toString()),
    signer_pub_key: issuerSig.signerPubKey.map((x) => x.toString()),
    signature_r8: issuerSig.signatureR8.map((x) => x.toString()),
    signature_s: issuerSig.signatureS.toString(),
    holder_signature_r8: holderBindSig.R8.map((x) => normalizeField(x).toString()),
    holder_signature_s: normalizeField(holderBindSig.S).toString(),
    beta: beta.toString(),
  };
}

async function fetchLiveOprfTranscript(
  vc: VerifiableCredential,
  issuerPublicKey: { x: bigint; y: bigint },
  holderKeyPair: HolderKeyPair,
  network: OprfNetworkConfig,
  onProgress?: ProgressReporter,
): Promise<OprfTranscriptInput> {
  onProgress?.("Computing VC-derived private hash ID...");
  const hashId = computeHashIdFromVc(vc);
  const services = network.nodeBases.map((base) => toOprfUri(base, network.authModule));
  const beta = randomBlindingFactor();
  const blindedRequest = blindQuery(hashId, beta);
  const requestId = crypto.randomUUID();

  onProgress?.("Building blinded-query auth proof witness...");
  const vcCircuit = await loadVcBlindedQueryAuthCircuitArtifact();
  const vcInputs = buildVcBlindedQueryAuthNoirInputs(
    vc,
    issuerPublicKey,
    holderKeyPair,
    beta,
  );

  const authPayload = await (async () => {
    onProgress?.("Generating blinded-query auth proof for node authentication...");
    const vcProofData = await generateWithNoir(vcCircuit, vcInputs);
    const publicInputsBytes = publicInputsToBytes(vcProofData.publicInputs, "le");
    const holderAuthMessage = buildHolderOprfAuthMessage(
      requestId,
      blindedRequest.x,
      blindedRequest.y,
    );
    const holderSig = signMessageWithHolderKey(
      holderKeyPair.privateKey,
      holderAuthMessage,
    );
    return {
      api_key: network.apiKey,
      public_inputs: Array.from(publicInputsBytes),
      proof: Array.from(vcProofData.proof),
      holder_sig_r8x: holderSig.R8[0].toString(),
      holder_sig_r8y: holderSig.R8[1].toString(),
      holder_sig_s: holderSig.S.toString(),
    };
  })();

  const wrapOprfNodeErrors = (phase: string, err: unknown): never => {
    if (Array.isArray(err) && err.every((x) => isNodeError(x))) {
      const aggregated = aggregateError(network.threshold, err);
      const nodeSummary = err
        .map((e) => {
          const serviceCode = e.serviceError?.errorCode;
          const serviceMsg = e.serviceError?.msg;
          return `${e.code}${serviceCode != null ? `/${serviceCode}` : ""}${
            serviceMsg ? `:${serviceMsg}` : ""
          }`;
        })
        .join(", ");
      throw new Error(
        `OPRF ${phase} failed: ${aggregated.code} (${aggregated.message}) [${nodeSummary}]`,
      );
    }
    throw err instanceof Error ? err : new Error(String(err));
  };

  onProgress?.("Opening OPRF sessions with nodes...");
  const sessions = await initSessions(services, network.threshold, {
    request_id: requestId,
    blinded_query: blindedRequest,
    auth: authPayload,
  }).catch((err) => wrapOprfNodeErrors("session init", err));

  onProgress?.("Collecting threshold OPRF responses...");
  const challenge = generateChallengeRequest(sessions);
  const proofShares = await finishSessions(sessions, challenge).catch((err) =>
    wrapOprfNodeErrors("session finish", err),
  );
  const dlogProof = verifyDlogEquality(
    requestId,
    sessions.oprfPublicKeys[0],
    blindedRequest,
    proofShares,
    challenge,
  );

  const blindedResponse = challenge.blindedResponse();
  const unblindedResponse = unblindResponse(
    blindedResponse,
    prepareBlindingFactor(beta),
  );
  const output = finalizeOutput(OPRF_DS_N, hashId, unblindedResponse);

  try {
    dlogEqualityVerify(
      dlogProof,
      sessions.oprfPublicKeys[0],
      blindedRequest,
      blindedResponse,
      BABYJUBJUB_SUBGROUP_GENERATOR_AFFINE,
    );
  } catch (err) {
    throw new Error(
      `Live OPRF transcript verification failed before proving: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  if (
    unblindedResponse.x === 0n ||
    unblindedResponse.y === 0n ||
    output === 0n
  ) {
    throw new Error("Live OPRF transcript produced invalid zero value");
  }

  return {
    beta: normalizeField(beta),
    oprfPkX: normalizeField(sessions.oprfPublicKeys[0].x),
    oprfPkY: normalizeField(sessions.oprfPublicKeys[0].y),
    dlogE: normalizeField(dlogProof.e),
    dlogS: normalizeField(dlogProof.s),
    oprfResponseBlindedX: normalizeField(blindedResponse.x),
    oprfResponseBlindedY: normalizeField(blindedResponse.y),
    oprfResponseX: normalizeField(unblindedResponse.x),
    oprfResponseY: normalizeField(unblindedResponse.y),
    oprfKeyId: 3n,
    // Circuit and contract currently require non-zero metadata fields.
    // Local OPRF sessions can report epoch=0, so clamp to 1 for now.
    oprfEpoch: BigInt(Math.max(1, sessions.epoch)),
  };
}

export async function validateOprfNetworkConfig(
  network: OprfNetworkConfig,
): Promise<void> {
  if (network.nodeBases.length < 1) {
    throw new Error("At least one OPRF node URL is required");
  }
  if (!Number.isFinite(network.threshold) || network.threshold < 1) {
    throw new Error("Threshold must be a positive integer");
  }
}

function decodeFromPublicSignals(signals: bigint[]) {
  if (signals.length !== 10) {
    throw new Error(`Expected 10 public signals, got ${signals.length}`);
  }
  return {
    oprfPkX: signals[0].toString(),
    oprfPkY: signals[1].toString(),
    validUntil: signals[2].toString(),
    holderPubKeyX: signals[3].toString(),
    holderPubKeyY: signals[4].toString(),
    issuerPubKeyX: signals[5].toString(),
    issuerPubKeyY: signals[6].toString(),
    oprfKeyId: signals[7].toString(),
    oprfEpoch: signals[8].toString(),
    nullifier: signals[9].toString(),
  };
}

export async function buildVcOprfEnrollmentProofPackage(
  credential: VerifiableCredential,
  issuerPublicKey: { x: bigint; y: bigint },
  holderKeyPair: HolderKeyPair,
  network: OprfNetworkConfig,
  onProgress?: ProgressReporter,
): Promise<VcOprfEnrollmentProofPackage> {
  onProgress?.("Validating OPRF configuration...");
  await validateOprfNetworkConfig(network);
  onProgress?.("Fetching live OPRF transcript...");
  const transcript = await fetchLiveOprfTranscript(
    credential,
    issuerPublicKey,
    holderKeyPair,
    network,
    onProgress,
  );
  try {
    onProgress?.("Building enrollment witness and generating proof...");
    const circuit = await loadCircuitArtifact();
    assertCircuitCompatibility(circuit);
    const noirInputs = buildNoirInputs(
      credential,
      issuerPublicKey,
      holderKeyPair,
      transcript,
    );

    const proofData = await generateWithNoir(circuit, noirInputs);

    const publicSignalsBig = proofData.publicInputs.map((x) => normalizeField(BigInt(x)));
    onProgress?.("Finalizing proof package...");
    return {
      proof: toHex(proofData.proof),
      publicSignals: publicSignalsBig.map(toBytes32Hex),
      decoded: decodeFromPublicSignals(publicSignalsBig),
    };
  } catch (err) {
    if (err instanceof Error) {
      throw new Error(`OPRF package generation failed: ${err.message}`);
    }
    throw new Error("OPRF package generation failed");
  }
}

function decodeRevocationSignals(signals: bigint[]) {
  if (signals.length !== 4) {
    throw new Error("Revocation proof must expose exactly 4 public signals");
  }
  return {
    nullifier: signals[0].toString(),
    holderPubKeyX: signals[1].toString(),
    holderPubKeyY: signals[2].toString(),
    challengeBlockHash: signals[3].toString(),
  };
}

export async function buildVcRevocationProofPackage(
  nullifier: bigint,
  holderKeyPair: HolderKeyPair,
  challengeBlockHash: bigint,
  challengeBlockNumber: bigint,
  onProgress?: ProgressReporter,
): Promise<VcRevocationProofPackage> {
  onProgress?.("Loading revocation circuit...");
  const circuit = await loadVcRevocationCircuitArtifact();
  assertCircuitCompatibility(circuit);

  const revokeMessage = buildRevokeChallengeMessage(
    normalizeField(nullifier),
    normalizeField(challengeBlockHash),
  );
  const revokeSig = signMessageWithHolderKey(holderKeyPair.privateKey, revokeMessage);

  const inputs = {
    nullifier: normalizeField(nullifier).toString(),
    holder_pub_key_x: normalizeField(holderKeyPair.publicKey.x).toString(),
    holder_pub_key_y: normalizeField(holderKeyPair.publicKey.y).toString(),
    challenge_block_hash: normalizeField(challengeBlockHash).toString(),
    holder_sig_r8: [
      normalizeField(revokeSig.R8[0]).toString(),
      normalizeField(revokeSig.R8[1]).toString(),
    ],
    holder_sig_s: normalizeField(revokeSig.S).toString(),
  };

  onProgress?.("Generating revocation proof...");
  const proofData = await generateWithNoir(circuit, inputs);
  const publicSignalsBig = proofData.publicInputs.map((x) => normalizeField(BigInt(x)));

  onProgress?.("Finalizing revocation package...");
  return {
    proof: toHex(proofData.proof),
    publicSignals: publicSignalsBig.map(toBytes32Hex),
    challengeBlockNumber,
    decoded: decodeRevocationSignals(publicSignalsBig),
  };
}
