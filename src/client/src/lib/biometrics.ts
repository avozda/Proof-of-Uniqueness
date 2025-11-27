import { enroll, BIOMETRIC_LENGTH } from 'ecdsa-fuzzy-signature';

/**
 * Biometric configuration constants from the fuzzy signature library
 */
export const BIOMETRIC_CONFIG = {
  /** Length of biometric data in bytes */
  dataLength: BIOMETRIC_LENGTH,
  /** Size of each block in bytes for block-wise fuzzy extraction */
  blockSize: 4,
  /** Maximum Hamming distance (in bits) tolerated per block */
  errorThreshold: 8,
  /** Number of repetitions for error correction */
  repetitions: 3,
} as const;

export interface MockBiometricData {
  rawBiometric: Uint8Array;
  sketch: Uint8Array;
  verificationKey: Uint8Array;
}

/**
 * Generate mock biometric data (simulating fingerprint/face/iris scan)
 * In a real system, this would come from actual biometric sensors
 */
export function generateMockBiometric(): Uint8Array {
  const biometric = new Uint8Array(BIOMETRIC_LENGTH);
  crypto.getRandomValues(biometric);
  return biometric;
}

/**
 * Enroll mock biometric data and generate sketch + verification key
 */
export function enrollBiometric(biometric?: Uint8Array): MockBiometricData {
  const rawBiometric = biometric ?? generateMockBiometric();
  
  // Use the fuzzy signature library to generate sketch and verification key
  const { vk, sketch } = enroll(rawBiometric);
  
  return {
    rawBiometric,
    sketch,
    verificationKey: vk,
  };
}

