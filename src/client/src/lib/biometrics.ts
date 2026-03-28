import {
  enroll,
  fuzzyRep,
  derivePrivateKey,
  FuzzyExtractionError,
  BIOMETRIC_LENGTH,
} from "ecdsa-fuzzy-signature";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { fromHex } from "./did";

export const BIOMETRIC_CONFIG = {
  dataLength: BIOMETRIC_LENGTH,
  blockSize: 4,
  errorThreshold: 8,
  repetitions: 3,
} as const;

export interface MockBiometricData {
  rawBiometric: Uint8Array;
  sketch: Uint8Array;
  verificationKey: Uint8Array;
}

export interface SignatureParts {
  v: number;
  r: `0x${string}`;
  s: `0x${string}`;
}

const AUTHORIZE_DOMAIN = "IdentityRegistry::AuthorizeMock:v1";
const REVOKE_DOMAIN = "IdentityRegistry::Revoke:v1";

function bytesToHexPrefixed(bytes: Uint8Array): `0x${string}` {
  return `0x${bytesToHex(bytes)}`;
}

function bigintToBytes32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let value = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

function encodeBigIntWord(n: bigint): Uint8Array {
  return bigintToBytes32(n);
}

function encodeAddressWord(address: `0x${string}`): Uint8Array {
  const raw = fromHex(address);
  if (raw.length !== 20) {
    throw new Error("Address must be 20 bytes");
  }
  const out = new Uint8Array(32);
  out.set(raw, 12);
  return out;
}

function abiEncodeWords(words: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(words.length * 32);
  for (let i = 0; i < words.length; i++) {
    out.set(words[i], i * 32);
  }
  return out;
}

function hashDomainTag(tag: string): bigint {
  const digest = keccak_256(new TextEncoder().encode(tag));
  let out = 0n;
  for (let i = 0; i < digest.length; i++) {
    out = (out << 8n) | BigInt(digest[i]);
  }
  return out;
}

function digestToBytes(digestHex: `0x${string}`): Uint8Array {
  const bytes = fromHex(digestHex);
  if (bytes.length !== 32) {
    throw new Error("Expected 32-byte challenge digest");
  }
  return bytes;
}

function signatureToVRS(signature65: Uint8Array): SignatureParts {
  if (signature65.length !== 65) {
    throw new Error("Expected 65-byte recovered signature");
  }

  const recovery = signature65[0];
  const r = signature65.slice(1, 33);
  const s = signature65.slice(33, 65);

  return {
    v: 27 + (recovery & 1),
    r: bytesToHexPrefixed(r),
    s: bytesToHexPrefixed(s),
  };
}

function vkPointToBytes(vkX: bigint, vkY: bigint, compressed = true): Uint8Array {
  const point = secp256k1.Point.fromAffine({ x: vkX, y: vkY });
  return point.toBytes(compressed);
}

function addressFromCompressedPubkey(pubkey33: Uint8Array): bigint {
  const point = secp256k1.Point.fromHex(bytesToHex(pubkey33));
  const uncompressed = point.toBytes(false);
  const digest = keccak_256(uncompressed.slice(1));
  let value = 0n;
  for (let i = 12; i < 32; i++) {
    value = (value << 8n) | BigInt(digest[i]);
  }
  return value;
}

export function generateMockBiometric(): Uint8Array {
  const biometric = new Uint8Array(BIOMETRIC_LENGTH);
  crypto.getRandomValues(biometric);
  return biometric;
}

export function enrollBiometric(biometric?: Uint8Array): MockBiometricData {
  const rawBiometric = biometric ?? generateMockBiometric();
  const { vk, sketch } = enroll(rawBiometric);

  return { rawBiometric, sketch, verificationKey: vk };
}

export function generateAuthorizeChallenge(): Uint8Array {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  return challenge;
}

export function buildAuthorizeChallengeDigest(
  hashID: bigint,
  challenge: Uint8Array,
): `0x${string}` {
  if (challenge.length === 0) {
    throw new Error("Challenge cannot be empty");
  }

  const challengeHash = keccak_256(challenge);
  const words = abiEncodeWords([
    encodeBigIntWord(hashDomainTag(AUTHORIZE_DOMAIN)),
    encodeBigIntWord(hashID),
    new Uint8Array(challengeHash),
  ]);
  return bytesToHexPrefixed(keccak_256(words));
}

export function buildRevokeChallengeDigest(
  contractAddress: `0x${string}`,
  chainId: bigint,
  hashID: bigint,
  challengeBlock: bigint,
): `0x${string}` {
  const payload = abiEncodeWords([
    encodeBigIntWord(hashDomainTag(REVOKE_DOMAIN)),
    encodeAddressWord(contractAddress),
    encodeBigIntWord(chainId),
    encodeBigIntWord(hashID),
    encodeBigIntWord(challengeBlock),
  ]);
  return bytesToHexPrefixed(keccak_256(payload));
}

export function signChallengeWithBiometric(
  biometric: Uint8Array,
  sketch: Uint8Array,
  challengeDigest: `0x${string}`,
): SignatureParts {
  const digestBytes = digestToBytes(challengeDigest);
  const key = fuzzyRep(biometric, sketch);
  if (key === null) {
    throw new FuzzyExtractionError(
      "Failed to unlock sketch. Biometric input does not match enrollment.",
    );
  }

  const privateKey = derivePrivateKey(key);
  const signature = secp256k1.sign(digestBytes, privateKey, {
    lowS: true,
    prehash: false,
    format: "recovered",
  });
  return signatureToVRS(signature);
}

export function verifyChallengeSignature(
  vkX: bigint,
  vkY: bigint,
  challengeDigest: `0x${string}`,
  signatureParts: SignatureParts,
): boolean {
  const digestBytes = digestToBytes(challengeDigest);
  const compact = new Uint8Array(64);
  compact.set(fromHex(signatureParts.r), 0);
  compact.set(fromHex(signatureParts.s), 32);

  if (vkY === 0n) {
    const rec = signatureParts.v >= 27 ? signatureParts.v - 27 : signatureParts.v;
    const recovered = new Uint8Array(65);
    recovered[0] = rec & 1;
    recovered.set(compact, 1);
    const recoveredPub = secp256k1.recoverPublicKey(recovered, digestBytes, {
      prehash: false,
    });
    return addressFromCompressedPubkey(recoveredPub) === vkX;
  }

  const vk = vkPointToBytes(vkX, vkY, true);
  return secp256k1.verify(compact, digestBytes, vk, {
    prehash: false,
    lowS: true,
  });
}
