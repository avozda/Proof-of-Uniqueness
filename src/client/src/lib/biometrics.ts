import { enroll, BIOMETRIC_LENGTH } from 'ecdsa-fuzzy-signature';

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
