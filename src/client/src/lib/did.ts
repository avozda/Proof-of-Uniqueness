import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { bytesToHex } from '@noble/hashes/utils.js';

// Singleton instances for circomlibjs (they need async initialization)
let eddsa: Awaited<ReturnType<typeof buildEddsa>> | null = null;
let poseidon: Awaited<ReturnType<typeof buildPoseidon>> | null = null;

/**
 * Initialize the cryptographic primitives (must be called before using other functions)
 */
export async function initCrypto(): Promise<void> {
  if (!eddsa) {
    eddsa = await buildEddsa();
  }
  if (!poseidon) {
    poseidon = await buildPoseidon();
  }
}

/**
 * Get the initialized EdDSA instance
 */
function getEddsa() {
  if (!eddsa) {
    throw new Error('Crypto not initialized. Call initCrypto() first.');
  }
  return eddsa;
}

/**
 * Get the initialized Poseidon instance
 */
export function getPoseidon() {
  if (!poseidon) {
    throw new Error('Crypto not initialized. Call initCrypto() first.');
  }
  return poseidon;
}

export interface EdDSAPublicKey {
  x: bigint;
  y: bigint;
}

export interface EdDSASignature {
  R8: [bigint, bigint];  // R8 point (x, y)
  S: bigint;             // S scalar
}

export interface DIDKeyPair {
  did: string;
  publicKey: EdDSAPublicKey;
  privateKey: Uint8Array;
  verificationMethod: string;
}

/**
 * Generate a new DID based on BabyJubJub EdDSA key pair
 * Uses did:key method format
 */
export function generateDID(): DIDKeyPair {
  const eddsaInstance = getEddsa();
  
  // Generate a random 32-byte private key
  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);
  
  // Derive public key from private key
  const publicKeyPoint = eddsaInstance.prv2pub(privateKey);
  
  // Convert public key to bigints
  const publicKey: EdDSAPublicKey = {
    x: eddsaInstance.F.toObject(publicKeyPoint[0]),
    y: eddsaInstance.F.toObject(publicKeyPoint[1]),
  };
  
  // Create a deterministic DID from the public key
  const pubKeyHex = publicKey.x.toString(16).padStart(64, '0').slice(0, 30);
  const did = `did:babyjubjub:${pubKeyHex}`;
  const verificationMethod = `${did}#key-1`;
  
  return {
    did,
    publicKey,
    privateKey,
    verificationMethod,
  };
}

/**
 * Sign a message using EdDSA Poseidon
 * The message should be a field element (bigint)
 */
export function signMessage(privateKey: Uint8Array, message: bigint): EdDSASignature {
  const eddsaInstance = getEddsa();
  
  // Sign the message
  const signature = eddsaInstance.signPoseidon(privateKey, eddsaInstance.F.e(message));
  
  return {
    R8: [
      eddsaInstance.F.toObject(signature.R8[0]),
      eddsaInstance.F.toObject(signature.R8[1]),
    ],
    S: signature.S,
  };
}

/**
 * Verify an EdDSA Poseidon signature
 */
export function verifySignature(
  publicKey: EdDSAPublicKey,
  message: bigint,
  signature: EdDSASignature
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
  
  return eddsaInstance.verifyPoseidon(eddsaInstance.F.e(message), sig, pubKeyPoint);
}

/**
 * Compute Poseidon hash of multiple field elements
 */
export function poseidonHash(inputs: bigint[]): bigint {
  const poseidonInstance = getPoseidon();
  const hash = poseidonInstance(inputs);
  return poseidonInstance.F.toObject(hash);
}

/**
 * Convert a string to a field element using Poseidon hash
 * This ensures the string fits in the finite field
 */
export function stringToField(str: string): bigint {
  const poseidonInstance = getPoseidon();
  
  // Convert string to bytes
  const bytes = new TextEncoder().encode(str);
  
  // Split into chunks of 31 bytes (to fit in field) and hash
  const chunks: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 31) {
    const chunk = bytes.slice(i, Math.min(i + 31, bytes.length));
    // Convert chunk to bigint
    let value = BigInt(0);
    for (let j = 0; j < chunk.length; j++) {
      value = (value << BigInt(8)) | BigInt(chunk[j]);
    }
    chunks.push(value);
  }
  
  // If only one chunk, return it directly if it fits
  if (chunks.length === 1) {
    return chunks[0];
  }
  
  // Hash multiple chunks together
  const hash = poseidonInstance(chunks);
  return poseidonInstance.F.toObject(hash);
}

/**
 * Convert a date string (ISO format) to a field element (timestamp)
 */
export function dateToField(dateStr: string): bigint {
  const timestamp = new Date(dateStr).getTime();
  return BigInt(Math.floor(timestamp / 1000)); // Unix timestamp in seconds
}

/**
 * Encode sex to a field element
 */
export function sexToField(sex: string): bigint {
  switch (sex.toLowerCase()) {
    case 'male': return BigInt(0);
    case 'female': return BigInt(1);
    case 'other': return BigInt(2);
    default: return BigInt(3);
  }
}

export interface VCSignatureData {
  message: bigint;           // The Poseidon hash of VC fields
  signature: EdDSASignature; // The EdDSA signature
  publicKey: EdDSAPublicKey; // The signer's public key
}

/**
 * Create signature data for a Verifiable Credential
 * Returns the message hash and signature for circuit verification
 */
export function createVCSignature(
  privateKey: Uint8Array,
  publicKey: EdDSAPublicKey,
  vcFields: {
    vcId: bigint;
    credentialSubjectId: bigint;
    name: bigint;
    dob: bigint;
    sex: bigint;
    nationality: bigint;
    validFrom: bigint;
    issuer: bigint;
    validUntil: bigint;
    sketchHash: bigint;
    verificationKey: [bigint, bigint];
  }
): VCSignatureData {
  // Compute the message hash (what gets signed)
  // This should match what the circuit expects to verify
  const message = poseidonHash([
    vcFields.vcId,
    vcFields.credentialSubjectId,
    vcFields.name,
    vcFields.dob,
    vcFields.sex,
    vcFields.nationality,
    vcFields.validFrom,
    vcFields.issuer,
    vcFields.validUntil,
    vcFields.sketchHash,
    vcFields.verificationKey[0],
    vcFields.verificationKey[1],
  ]);
  
  const signature = signMessage(privateKey, message);
  
  return {
    message,
    signature,
    publicKey,
  };
}

/**
 * Convert Uint8Array to hex string for display
 */
export function toHex(bytes: Uint8Array): string {
  return bytesToHex(bytes);
}

/**
 * Convert bigint to hex string
 */
export function bigintToHex(n: bigint): string {
  return n.toString(16).padStart(64, '0');
}

/**
 * Encode bytes to base64url
 */
function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Encode a string to base64url (handles UTF-8 properly)
 */
function stringToBase64Url(str: string): string {
  const bytes = new TextEncoder().encode(str);
  return bytesToBase64Url(bytes);
}

/**
 * Create a JWS-like signature string for the VC proof
 * Uses EdDSA Poseidon signature format
 */
export function createJWSSignature(
  privateKey: Uint8Array,
  payload: object,
  message: bigint
): string {
  const signature = signMessage(privateKey, message);
  
  // Create a JWS-like structure with EdDSA Poseidon
  const header = { alg: 'EdDSA-Poseidon', typ: 'JWT' };
  const headerB64 = stringToBase64Url(JSON.stringify(header));
  const payloadB64 = stringToBase64Url(JSON.stringify(payload));
  
  // Encode signature components
  const sigData = {
    R8: [signature.R8[0].toString(), signature.R8[1].toString()],
    S: signature.S.toString(),
  };
  const signatureB64 = stringToBase64Url(JSON.stringify(sigData));
  
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}
