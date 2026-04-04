import {
  poseidonHash,
  publicKeyFromPrivateKey,
  signMessage,
  stringToField,
  type EdDSAPublicKey,
  type EdDSASignature,
} from "./did";

const HOLDER_BIND_DOMAIN = "holder-bjj-bind-subject:v1";
const HOLDER_OPRF_AUTH_DOMAIN = "holder-bjj-oprf-auth:v1";
const REVOKE_DOMAIN = "IdentityRegistry::Revoke:v2";

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

export function buildHolderBindingMessage(credentialSubjectId: string): bigint {
  return poseidonHash([
    stringToField(HOLDER_BIND_DOMAIN),
    stringToField(credentialSubjectId),
  ]);
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
