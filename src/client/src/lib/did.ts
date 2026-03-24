import { buildEddsa, buildPoseidon } from "circomlibjs";
import { bytesToHex } from "@noble/hashes/utils.js";
import bs58 from "bs58";

let eddsa: Awaited<ReturnType<typeof buildEddsa>> | null = null;
let poseidon: Awaited<ReturnType<typeof buildPoseidon>> | null = null;

export async function initCrypto(): Promise<void> {
  if (!eddsa) {
    eddsa = await buildEddsa();
  }
  if (!poseidon) {
    poseidon = await buildPoseidon();
  }
}

function getEddsa() {
  if (!eddsa)
    throw new Error("Crypto not initialized. Call initCrypto() first.");
  return eddsa;
}

export function getPoseidon() {
  if (!poseidon)
    throw new Error("Crypto not initialized. Call initCrypto() first.");
  return poseidon;
}

export interface EdDSAPublicKey {
  x: bigint;
  y: bigint;
}

export interface EdDSASignature {
  R8: [bigint, bigint];
  S: bigint;
}

export interface DIDKeyPair {
  did: string;
  publicKey: EdDSAPublicKey;
  privateKey: Uint8Array;
  verificationMethod: string;
}

export function multibaseEncode(bytes: Uint8Array): string {
  return "z" + bs58.encode(bytes);
}

export function multibaseDecode(encoded: string): Uint8Array {
  if (!encoded.startsWith("z")) {
    throw new Error("Expected Multibase base58-btc encoding (z prefix)");
  }
  return bs58.decode(encoded.slice(1));
}

export function bigintToBytes(n: bigint, byteLength: number): Uint8Array {
  const bytes = new Uint8Array(byteLength);
  let val = n;
  for (let i = byteLength - 1; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

export function bytesToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/** Encode EdDSA signature as multibase base58-btc: R8x(32) || R8y(32) || S(32) */
export function encodeProofValue(R8: [bigint, bigint], S: bigint): string {
  const r8xBytes = bigintToBytes(R8[0], 32);
  const r8yBytes = bigintToBytes(R8[1], 32);
  const sBytes = bigintToBytes(S, 32);

  const combined = new Uint8Array(96);
  combined.set(r8xBytes, 0);
  combined.set(r8yBytes, 32);
  combined.set(sBytes, 64);

  return multibaseEncode(combined);
}

/** Decode proofValue back into signature components as decimal strings */
export function decodeProofValue(proofValue: string): {
  signatureR8: [string, string];
  signatureS: string;
} {
  const bytes = multibaseDecode(proofValue);
  if (bytes.length !== 96) {
    throw new Error(
      `Invalid proofValue: expected 96 bytes, got ${bytes.length}`,
    );
  }

  const r8x = bytesToBigint(bytes.slice(0, 32));
  const r8y = bytesToBigint(bytes.slice(32, 64));
  const s = bytesToBigint(bytes.slice(64, 96));

  return {
    signatureR8: [r8x.toString(), r8y.toString()],
    signatureS: s.toString(),
  };
}

/** Encode public key as did:babyjubjub:z<base58btc(X_32bytes || Y_32bytes)> */
function encodeBabyJubJubDID(publicKey: EdDSAPublicKey): string {
  const xBytes = bigintToBytes(publicKey.x, 32);
  const yBytes = bigintToBytes(publicKey.y, 32);

  const combined = new Uint8Array(64);
  combined.set(xBytes, 0);
  combined.set(yBytes, 32);

  return `did:babyjubjub:${multibaseEncode(combined)}`;
}

/** Extract public key coordinates from a verificationMethod DID URL */
export function extractPublicKeyFromVerificationMethod(
  verificationMethod: string,
): {
  x: string;
  y: string;
} {
  const didPart = verificationMethod.split("#")[0];
  const prefix = "did:babyjubjub:";
  if (!didPart.startsWith(prefix)) {
    throw new Error(
      `Invalid DID method: expected did:babyjubjub:, got ${didPart}`,
    );
  }

  const bytes = multibaseDecode(didPart.slice(prefix.length));
  if (bytes.length !== 64) {
    throw new Error(
      `Invalid DID public key: expected 64 bytes, got ${bytes.length}`,
    );
  }

  return {
    x: bytesToBigint(bytes.slice(0, 32)).toString(),
    y: bytesToBigint(bytes.slice(32, 64)).toString(),
  };
}

export function generateDID(): DIDKeyPair {
  const eddsaInstance = getEddsa();

  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);

  const publicKeyPoint = eddsaInstance.prv2pub(privateKey);
  const publicKey: EdDSAPublicKey = {
    x: eddsaInstance.F.toObject(publicKeyPoint[0]),
    y: eddsaInstance.F.toObject(publicKeyPoint[1]),
  };

  const did = encodeBabyJubJubDID(publicKey);

  return {
    did,
    publicKey,
    privateKey,
    verificationMethod: `${did}#key-1`,
  };
}

export function signMessage(
  privateKey: Uint8Array,
  message: bigint,
): EdDSASignature {
  const eddsaInstance = getEddsa();
  const signature = eddsaInstance.signPoseidon(
    privateKey,
    eddsaInstance.F.e(message),
  );

  return {
    R8: [
      eddsaInstance.F.toObject(signature.R8[0]),
      eddsaInstance.F.toObject(signature.R8[1]),
    ],
    S: signature.S,
  };
}

export function verifySignature(
  publicKey: EdDSAPublicKey,
  message: bigint,
  signature: EdDSASignature,
): boolean {
  const eddsaInstance = getEddsa();

  const pubKeyPoint = [
    eddsaInstance.F.e(publicKey.x),
    eddsaInstance.F.e(publicKey.y),
  ];

  const sig = {
    R8: [
      eddsaInstance.F.e(signature.R8[0]),
      eddsaInstance.F.e(signature.R8[1]),
    ],
    S: signature.S,
  };

  return eddsaInstance.verifyPoseidon(
    eddsaInstance.F.e(message),
    sig,
    pubKeyPoint,
  );
}

export function poseidonHash(inputs: bigint[]): bigint {
  const poseidonInstance = getPoseidon();
  const hash = poseidonInstance(inputs);
  return poseidonInstance.F.toObject(hash);
}

// Domain separator for VC signatures (prevents cross-protocol attacks)
// ≤31 UTF-8 bytes: stringToFieldSimple packs into one field element for Poseidon(domain, root).
export const SIGNATURE_DOMAIN = "eddsa-bjj-poseidon-2024:v1";

// Field labels for Merkle tree (alphabetically sorted for determinism)
export const VC_FIELD_LABELS = [
  "biometricVk.0",
  "biometricVk.1",
  "credentialSubjectId",
  "dob",
  "issuer",
  "name",
  "nationality",
  "permanentAddressHash",
  "placeOfBirth",
  "sex",
  "sketchHash",
  "validFrom",
  "validUntil",
  "vcId",
] as const;

export type VCFieldLabel = (typeof VC_FIELD_LABELS)[number];

export interface MerkleTree {
  root: bigint;
  leaves: bigint[];
  layers: bigint[][];
}

export interface MerklePath {
  siblings: bigint[];
  pathIndices: number[];
}

/** Compute a labeled leaf: Poseidon(label, value) */
export function computeFieldLeaf(label: string, value: bigint): bigint {
  const labelField = stringToFieldSimple(label);
  return poseidonHash([labelField, value]);
}

/** Simple string to field (no recursive hashing, for short labels only) */
function stringToFieldSimple(str: string): bigint {
  const bytes = new TextEncoder().encode(str);
  if (bytes.length > 31) {
    throw new Error(`Label too long for single field element: ${str}`);
  }
  let value = BigInt(0);
  for (let j = 0; j < bytes.length; j++) {
    value = (value << BigInt(8)) | BigInt(bytes[j]);
  }
  return value;
}

/** Build a binary Poseidon Merkle tree from leaves, padding to power of 2 */
export function buildMerkleTree(leaves: bigint[]): MerkleTree {
  if (leaves.length === 0) {
    throw new Error("Cannot build Merkle tree from empty leaves");
  }

  // Pad to next power of 2
  const targetSize = Math.pow(2, Math.ceil(Math.log2(leaves.length)));
  const paddedLeaves = [...leaves];
  while (paddedLeaves.length < targetSize) {
    paddedLeaves.push(BigInt(0));
  }

  const layers: bigint[][] = [paddedLeaves];
  let currentLayer = paddedLeaves;

  while (currentLayer.length > 1) {
    const nextLayer: bigint[] = [];
    for (let i = 0; i < currentLayer.length; i += 2) {
      const left = currentLayer[i];
      const right = currentLayer[i + 1];
      nextLayer.push(poseidonHash([left, right]));
    }
    layers.push(nextLayer);
    currentLayer = nextLayer;
  }

  return {
    root: currentLayer[0],
    leaves: paddedLeaves,
    layers,
  };
}

/** Get Merkle proof path for a leaf at given index */
export function getMerklePath(tree: MerkleTree, leafIndex: number): MerklePath {
  if (leafIndex < 0 || leafIndex >= tree.leaves.length) {
    throw new Error(`Invalid leaf index: ${leafIndex}`);
  }

  const siblings: bigint[] = [];
  const pathIndices: number[] = [];
  let currentIndex = leafIndex;

  for (let i = 0; i < tree.layers.length - 1; i++) {
    const layer = tree.layers[i];
    const isRight = currentIndex % 2 === 1;
    const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;

    siblings.push(layer[siblingIndex]);
    pathIndices.push(isRight ? 1 : 0);
    currentIndex = Math.floor(currentIndex / 2);
  }

  return { siblings, pathIndices };
}

/** Verify a Merkle proof */
export function verifyMerklePath(
  leaf: bigint,
  path: MerklePath,
  root: bigint,
): boolean {
  let current = leaf;
  for (let i = 0; i < path.siblings.length; i++) {
    const sibling = path.siblings[i];
    if (path.pathIndices[i] === 0) {
      current = poseidonHash([current, sibling]);
    } else {
      current = poseidonHash([sibling, current]);
    }
  }
  return current === root;
}

/** Compute domain separator field element */
export function getDomainSeparator(): bigint {
  return stringToFieldSimple(SIGNATURE_DOMAIN);
}

/** Convert string to field element (31-byte chunks, Poseidon-hashed if multiple) */
export function stringToField(str: string): bigint {
  const poseidonInstance = getPoseidon();
  const bytes = new TextEncoder().encode(str);

  const chunks: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 31) {
    const chunk = bytes.slice(i, Math.min(i + 31, bytes.length));
    let value = BigInt(0);
    for (let j = 0; j < chunk.length; j++) {
      value = (value << BigInt(8)) | BigInt(chunk[j]);
    }
    chunks.push(value);
  }

  if (chunks.length === 1) return chunks[0];

  const hash = poseidonInstance(chunks);
  return poseidonInstance.F.toObject(hash);
}

/** Convert ISO date string to Unix timestamp field element */
export function dateToField(dateStr: string): bigint {
  return BigInt(Math.floor(new Date(dateStr).getTime() / 1000));
}

/** Encode sex as field element: male=0, female=1, other=2, unknown=3 */
export function sexToField(sex: string): bigint {
  switch (sex.toLowerCase()) {
    case "male":
      return BigInt(0);
    case "female":
      return BigInt(1);
    case "other":
      return BigInt(2);
    default:
      return BigInt(3);
  }
}

export interface VCSignatureData {
  message: bigint;
  signature: EdDSASignature;
  publicKey: EdDSAPublicKey;
  merkleTree: MerkleTree;
  fieldValues: Map<VCFieldLabel, bigint>;
}

export interface VCFields {
  vcId: bigint;
  credentialSubjectId: bigint;
  name: bigint;
  dob: bigint;
  placeOfBirth: bigint;
  sex: bigint;
  nationality: bigint;
  permanentAddressHash: bigint;
  validFrom: bigint;
  issuer: bigint;
  validUntil: bigint;
  sketchHash: bigint;
  verificationKey: [bigint, bigint];
}

/** Build labeled field map from VC fields (sorted alphabetically by label) */
export function buildFieldMap(vcFields: VCFields): Map<VCFieldLabel, bigint> {
  const fieldMap = new Map<VCFieldLabel, bigint>();
  fieldMap.set("biometricVk.0", vcFields.verificationKey[0]);
  fieldMap.set("biometricVk.1", vcFields.verificationKey[1]);
  fieldMap.set("credentialSubjectId", vcFields.credentialSubjectId);
  fieldMap.set("dob", vcFields.dob);
  fieldMap.set("issuer", vcFields.issuer);
  fieldMap.set("name", vcFields.name);
  fieldMap.set("nationality", vcFields.nationality);
  fieldMap.set("permanentAddressHash", vcFields.permanentAddressHash);
  fieldMap.set("placeOfBirth", vcFields.placeOfBirth);
  fieldMap.set("sex", vcFields.sex);
  fieldMap.set("sketchHash", vcFields.sketchHash);
  fieldMap.set("validFrom", vcFields.validFrom);
  fieldMap.set("validUntil", vcFields.validUntil);
  fieldMap.set("vcId", vcFields.vcId);
  return fieldMap;
}

/** Compute Merkle tree leaves from labeled fields (in label order) */
export function computeMerkleLeaves(
  fieldMap: Map<VCFieldLabel, bigint>,
): bigint[] {
  return VC_FIELD_LABELS.map((label) => {
    const value = fieldMap.get(label);
    if (value === undefined) {
      throw new Error(`Missing field value for label: ${label}`);
    }
    return computeFieldLeaf(label, value);
  });
}

/** Sign VC fields with Merkle tree + domain separator */
export function createVCSignature(
  privateKey: Uint8Array,
  publicKey: EdDSAPublicKey,
  vcFields: VCFields,
): VCSignatureData {
  const fieldValues = buildFieldMap(vcFields);
  const leaves = computeMerkleLeaves(fieldValues);
  const merkleTree = buildMerkleTree(leaves);

  // Message = Poseidon(domainSeparator, merkleRoot)
  const domainSeparator = getDomainSeparator();
  const message = poseidonHash([domainSeparator, merkleTree.root]);

  return {
    message,
    signature: signMessage(privateKey, message),
    publicKey,
    merkleTree,
    fieldValues,
  };
}

export function toHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

export function fromHex(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bigintToHex(n: bigint): string {
  return n.toString(16).padStart(64, "0");
}

/** Poseidon hash of byte array (split into 31-byte chunks) */
export function hashBytes(bytes: Uint8Array): bigint {
  const chunks: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 31) {
    const chunk = bytes.slice(i, Math.min(i + 31, bytes.length));
    let value = BigInt(0);
    for (let j = 0; j < chunk.length; j++) {
      value = (value << BigInt(8)) | BigInt(chunk[j]);
    }
    chunks.push(value);
  }
  return poseidonHash(chunks);
}

/** Split verification key bytes into two field elements */
export function vkToFieldElements(vk: Uint8Array): [bigint, bigint] {
  const half = Math.ceil(vk.length / 2);
  const part1 = vk.slice(0, half);
  const part2 = vk.slice(half);

  let x = BigInt(0);
  for (let i = 0; i < part1.length; i++) {
    x = (x << BigInt(8)) | BigInt(part1[i]);
  }

  let y = BigInt(0);
  for (let i = 0; i < part2.length; i++) {
    y = (y << BigInt(8)) | BigInt(part2[i]);
  }

  return [x, y];
}
