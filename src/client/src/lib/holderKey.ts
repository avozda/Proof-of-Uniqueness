import {
  poseidonHash,
  publicKeyFromPrivateKey,
  signMessage,
  stringToField,
  type EdDSAPublicKey,
  type EdDSASignature,
} from "./did";

const HOLDER_OPRF_AUTH_DOMAIN = "holder-bjj-oprf-auth:v1";

export interface HolderKeyPair {
  privateKey: Uint8Array;
  publicKey: EdDSAPublicKey;
}

export function generateHolderKeyPair(): HolderKeyPair {
  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);
  return {
    privateKey,
    publicKey: publicKeyFromPrivateKey(privateKey),
  };
}

export function signMessageWithHolderKey(
  privateKey: Uint8Array,
  message: bigint,
): EdDSASignature {
  return signMessage(privateKey, message);
}

export function buildHolderOprfAuthMessage(
  requestId: string,
  blindedX: bigint,
  blindedY: bigint,
): bigint {
  return poseidonHash([
    stringToField(HOLDER_OPRF_AUTH_DOMAIN),
    stringToField(requestId),
    blindedX,
    blindedY,
  ]);
}
