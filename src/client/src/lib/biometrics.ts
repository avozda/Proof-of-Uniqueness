import {
  fuzzyGen,
  fuzzyRep,
} from "eddsa-fuzzy-signature/fuzzy";
import {
  BIOMETRIC_LENGTH,
  FuzzyExtractionError,
} from "eddsa-fuzzy-signature/types";
import {
  hashBytes,
  initCrypto,
  packBabyJubPublicKey,
  poseidonHash,
  publicKeyFromPrivateKey,
  signMessage,
  stringToField,
  verifySignature,
  type EdDSAPublicKey,
} from "./did";

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

export interface BabyJubSignatureParts {
  R8: [bigint, bigint];
  S: bigint;
}

const PRIVATE_KEY_INFO = "eddsa-babyjubjub-poseidon-key";
const HOLDER_BIND_DOMAIN = "holder-bjj-bind-subject:v1";
const REVOKE_DOMAIN = "IdentityRegistry::Revoke:v2";

function derivePrivateKey(
  entropy: Uint8Array,
  salt: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const input = new Uint8Array(
    entropy.length + salt.length + PRIVATE_KEY_INFO.length,
  );
  input.set(entropy, 0);
  input.set(salt, entropy.length);
  input.set(new TextEncoder().encode(PRIVATE_KEY_INFO), entropy.length + salt.length);
  const digestField = hashBytes(input);
  const out = new Uint8Array(32);
  let value = digestField;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

export function generateMockBiometric(): Uint8Array {
  const biometric = new Uint8Array(BIOMETRIC_LENGTH);
  crypto.getRandomValues(biometric);
  return biometric;
}

export async function enrollBiometric(
  biometric?: Uint8Array,
): Promise<MockBiometricData> {
  const rawBiometric = biometric ?? generateMockBiometric();
  const { key, sketch } = fuzzyGen(rawBiometric, {
    blockSize: BIOMETRIC_CONFIG.blockSize,
    errorThreshold: BIOMETRIC_CONFIG.errorThreshold,
  });
  const privateKey = derivePrivateKey(key);
  const publicKey = publicKeyFromPrivateKey(privateKey);
  const verificationKey = packBabyJubPublicKey(publicKey);
  return { rawBiometric, sketch, verificationKey };
}

export function buildHolderBindingMessage(credentialSubjectId: string): bigint {
  return poseidonHash([
    stringToField(HOLDER_BIND_DOMAIN),
    stringToField(credentialSubjectId),
  ]);
}

function addressToField(address: `0x${string}`): bigint {
  const clean = address.toLowerCase().replace("0x", "");
  if (!/^[0-9a-f]{40}$/.test(clean)) {
    throw new Error("Invalid address format for challenge message");
  }
  return BigInt(`0x${clean}`);
}

export function buildRevokeChallengeMessage(
  contractAddress: `0x${string}`,
  chainId: bigint,
  hashID: bigint,
  challengeBlock: bigint,
): bigint {
  return poseidonHash([
    stringToField(REVOKE_DOMAIN),
    addressToField(contractAddress),
    chainId,
    hashID,
    challengeBlock,
  ]);
}

function deriveHolderPrivateKey(
  biometric: Uint8Array,
  sketch: Uint8Array,
): Uint8Array {
  const key = fuzzyRep(biometric, sketch);
  if (key === null) {
    throw new FuzzyExtractionError(
      "Failed to unlock sketch. Biometric input does not match enrollment.",
    );
  }
  return derivePrivateKey(key);
}

export function deriveHolderPublicKeyFromBiometric(
  biometric: Uint8Array,
  sketch: Uint8Array,
): EdDSAPublicKey {
  const privateKey = deriveHolderPrivateKey(biometric, sketch);
  return publicKeyFromPrivateKey(privateKey);
}

export function signHolderMessageWithBiometric(
  biometric: Uint8Array,
  sketch: Uint8Array,
  message: bigint,
): BabyJubSignatureParts {
  const privateKey = deriveHolderPrivateKey(biometric, sketch);
  const signature = signMessage(privateKey, message);
  return {
    R8: signature.R8,
    S: signature.S,
  };
}

export function verifyHolderSignature(
  publicKey: EdDSAPublicKey,
  message: bigint,
  signature: BabyJubSignatureParts,
): boolean {
  return verifySignature(publicKey, message, signature);
}

void initCrypto();
