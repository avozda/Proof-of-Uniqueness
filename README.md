<p align="center">
  <strong>◈ Proof of Uniqueness</strong>
</p>

<p align="center">
  Privacy-preserving identity enrollment, revocation, and authorization on Ethereum using zero-knowledge proofs and biometric fuzzy signatures
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Solidity-0.8.x-363636?logo=solidity" alt="Solidity" />
  <img src="https://img.shields.io/badge/Circom-2.2.2-orange" alt="Circom" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?logo=react" alt="React" />
  <img src="https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript" alt="TypeScript" />
  <img src="https://img.shields.io/badge/License-GPL--3.0-green" alt="License" />
</p>

---

## Overview

**Proof of Uniqueness** lets a user enroll an identity on-chain from a Verifiable Credential (VC) without revealing personal data. A Groth16 proof proves credential validity and integrity; only minimal public outputs are written to chain.

The current implementation also supports:

- **User revocation**: user signs a contract-bound challenge with a private key reconstructed from biometric + sketch; contract verifies and deletes enrollment.
- **Authorization mock (client-side)**: client reads on-chain verification key, creates random challenge, signs with reconstructed key, and verifies locally.

## What Is Implemented Now

- **ZK enrollment** with Groth16 verifier and trusted issuer checks.
- **Issuer trust management** (add/remove trusted issuer pubkeys).
- **Identity validity checks** and admin purge of expired/untrusted records.
- **Signature-based user revocation** with freshness window.
- **Client authorization mock** using on-chain verification key.

## Architecture

```
Trusted Issuer
  -> issues VC containing biometric sketch + secp256k1 verification key

User Client
  -> generates ZK proof from VC
  -> enrolls identity on-chain

IdentityRegistry (Solidity)
  -> verifies proof
  -> stores hashID, validity, issuer pubkey, sketch hash, verification key fields
  -> current enrollment stores verification key as address-form: [ethAddressAsUint256, 0]

Revocation
  -> client signs challenge: domain + contract + chain + hashID + block
  -> contract ecrecover + compare with enrolled key-derived address
  -> delete record

Authorization Mock (off-chain)
  -> client fetches verification key for hashID from contract
  -> random challenge
  -> sign via biometric reconstruction
  -> local verify (full key verify if x/y present, otherwise recover signer and compare address)
```

## Repository Structure

```
src/
├── circuits/
│   └── build/                       # Circuit artifacts used by client
├── client/
│   ├── src/components/
│   │   └── ZKProofSection.tsx       # Enrollment + revoke + authorization mock UI
│   ├── src/lib/
│   │   ├── biometrics.ts            # Challenge build/sign/verify helpers
│   │   ├── proof.ts                 # Groth16 proof generation/verification
│   │   ├── contractAbi.ts           # IdentityRegistry ABI (includes revoke)
│   │   └── contractErrors.ts        # Friendly tx error decoding
│   └── public/circuits/             # wasm/zkey/vkey consumed in browser
├── ecdsa-fuzzy-signature/           # Biometric fuzzy extractor + secp256k1 utilities
└── smart-contracts/
    ├── src/
    │   ├── IdentityRegistry.sol
    │   └── Groth16Verifier.sol
    └── script/
        └── IdentityRegistry.s.sol
```

## Core Smart Contract: IdentityRegistry

`src/smart-contracts/src/IdentityRegistry.sol`

### Enrollment

`enroll(_pA, _pB, _pC, _pubSignals)`:

- Rejects duplicate `hashID`.
- Requires issuer key to be trusted.
- Verifies Groth16 proof.
- Stores `IdentityRecord`:
  - `validUntil`
  - `issuerPubKeyX/Y`
  - `verificationKeyX/Y` (currently address-form: `verificationKeyX = uint256(uint160(ethAddress))`, `verificationKeyY = 0`)
  - `sketchHash`
  - `exists`

### Revocation (User-driven)

`revokeIdentity(hashID, challengeBlock, v, r, s)`:

- Requires existing identity.
- Challenge freshness checks:
  - `challengeBlock <= block.number`
  - `block.number - challengeBlock <= MAX_REVOKE_BLOCK_AGE`
- Reconstructs challenge digest:
  - `keccak256(abi.encode(REVOKE_DOMAIN, address(this), block.chainid, hashID, challengeBlock))`
- Uses `ecrecover` and compares recovered signer against stored verification key:
  - if `verificationKeyY == 0`: treat `verificationKeyX` as enrolled Ethereum address
  - else: derive address from secp256k1 `(x,y)`
- Deletes identity and removes `hashID` from registry array.

### Admin

- `addTrustedIssuer(pubKeyX, pubKeyY)` / `removeTrustedIssuer(...)`
- `addOwner(...)` / `removeOwner(...)`
- `purgeInvalidRecords(maxIterations)`
- `purgeIdentity(hashID)`

## Client Flows

`src/client/src/components/ZKProofSection.tsx`

### 1) Enrollment Flow

- Generate proof from VC.
- Optionally register current issuer key on-chain.
- Submit proof to `enroll`.

### 2) Revoke Flow

- User enters/selects `hashID`.
- Client gets latest block number.
- Client builds revoke digest (domain + contract + chain + hashID + block).
- Client unlocks sketch (biometric reconstruction), signs digest, extracts `(v,r,s)`.
- Sends tx to `revokeIdentity`.

### 3) Authorization Mock Flow (Off-chain)

- Client calls `getVerificationKey(hashID)`.
- Generates random 32-byte challenge.
- Builds authorization digest and signs with reconstructed key.
- Verifies locally:
  - full secp256k1 verify when `(vkX, vkY)` is a real point
  - otherwise recovers signer pubkey from signature and compares recovered address to `vkX`
- Displays pass/fail in UI.

### UI Visibility

- Revoke and Authorization sections are hidden until enrollment transaction is confirmed successfully.

## Important Compatibility Note

This version intentionally uses **address-form verification key storage** for new enrollments:

- `outVerificationKey[0]` = Ethereum address derived from secp256k1 verification key, encoded as `uint256`
- `outVerificationKey[1]` = `0`

- Backward compatibility with older stored records that used split-byte key packing is **not provided**.

## Prerequisites

- Node.js >= 18
- Foundry (forge, cast, anvil)
- Circom/snarkjs artifacts already present in `src/client/public/circuits` (or regenerated externally)

## Installation

```bash
npm install

# Fuzzy signature package (build local dist used by client)
cd src/ecdsa-fuzzy-signature
npm install
npm run build
cd ../..

# Client
cd src/client
npm install
cd ../..

# Smart contracts
cd src/smart-contracts
forge install
cd ../..
```

## Running Locally

### 1) Start local chain

```bash
anvil
```

### 2) Deploy contracts

```bash
cd src/smart-contracts
forge script script/IdentityRegistry.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
```

### 3) Start client

```bash
cd src/client
npm run dev
```

Open `http://localhost:5173`.

## Build Commands

```bash
# Smart contracts
cd src/smart-contracts
forge build

# Fuzzy signature package
cd ../ecdsa-fuzzy-signature
npm run build

# Client
cd ../client
npm run build
```

## Contract Public Signals (Proof)

The enrollment circuit/contract expects:

1. `hashID`
2. `outIssuer`
3. `outValidUntil`
4. `outSketchHash`
5. `outVerificationKey[0]` (vkX)
6. `outVerificationKey[1]` (vkY, currently `0` for address-form enrollments)
7. `outSignerPubKey[0]`
8. `outSignerPubKey[1]`

## Security Notes

- Revocation challenge is bound to **contract address** and **chain id** to prevent cross-contract/cross-chain replay.
- Freshness window (`MAX_REVOKE_BLOCK_AGE`) limits stale signature replay.
- Sketch is helper data; biometric reconstruction must happen client-side in trusted UX context.
- Authorization flow is currently a **mock** (off-chain verification only).

## Known Limitations

- No production wallet/session hardening in demo client.
- No production-grade key custody or anti-automation controls around biometric input.
- Authorization is not yet enforced on-chain or by a backend service.

## License

GPL-3.0
