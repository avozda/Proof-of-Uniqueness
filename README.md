<p align="center">
  <strong>◈ Proof of Uniqueness</strong>
</p>

<p align="center">
  Privacy-preserving identity verification on Ethereum powered by zero-knowledge proofs and fuzzy extractors
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

**Proof of Uniqueness** allows users to enroll their identity on-chain using Verifiable Credentials issued by trusted authorities — without revealing any private information. The system verifies credentials using zero-knowledge proofs, ensuring only the validity of the credential is proven while personal data remains private.

### Key Concepts

- **Trusted Issuers** — Government agencies or identity providers issue W3C Verifiable Credentials with biometric data
- **Zero-Knowledge Proofs** — Users prove credential validity without revealing private fields
- **On-chain Enrollment** — Smart contracts store only a privacy-preserving hash (HashID) and verification metadata
- **Sybil Resistance** — Each identity can only enroll once, preventing duplicate registrations

### System Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PRODUCTION FLOW                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌──────────────────────┐                                               │
│   │   TRUSTED ISSUER     │                                               │
│   │  (Government, eID)   │                                               │
│   └──────────┬───────────┘                                               │
│              │                                                           │
│              ▼                                                           │
│   Verifiable Credential (VC)                                             │
│   • Identity fields (name, DOB, nationality)                             │
│   • Biometric sketch + verification key                                  │
│   • EdDSA Poseidon signature                                             │
│              │                                                           │
│              ▼                                                           │
│   ┌──────────────────────┐                                               │
│   │        USER          │                                               │
│   │  (with existing VC)  │                                               │
│   └──────────┬───────────┘                                               │
│              │                                                           │
│              ▼                                                           │
│   ZK Proof Generator (Groth16)  ──► Proves VC validity                   │
│              │                                                           │
│              ▼                                                           │
│   Smart Contract (enroll)                                                │
│              │                                                           │
│              ▼                                                           │
│   On-chain Identity Record                                               │
│   • HashID (privacy-preserving)                                          │
│   • Issuer public key                                                    │
│   • Expiration, sketch hash, verification key                            │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Features

- **Privacy-Preserving** — Personal data never leaves the client; only ZK proofs are submitted
- **Sybil Resistance** — Each identity can only enroll once (enforced by HashID)
- **Issuer Trust Model** — Smart contract maintains whitelist of trusted credential issuers
- **Expiration Support** — Credentials have validity periods enforced on-chain
- **Biometric Binding** — Fuzzy extractors bind credentials to biometric data for secure recovery

## Project Structure

```
src/
├── circuits/                 # Circom ZK circuits
│   ├── Enrollment.circom     # Main enrollment circuit
│   └── build/                # Compiled circuits (wasm, zkey, r1cs)
│
├── client/                   # Demo application (for testing)
│   ├── src/
│   │   ├── components/       # UI components
│   │   └── lib/              # Core libraries (DID, VC, proof, biometrics)
│   └── public/circuits/      # Circuit artifacts for browser
│
├── ecdsa-fuzzy-signature/    # Fuzzy extractor + ECDSA library
│   ├── src/
│   │   ├── api.ts            # High-level API (enroll, sign, verify)
│   │   ├── fuzzy.ts          # Fuzzy extractor implementation
│   │   └── crypto.ts         # ECDSA utilities (secp256k1)
│   └── tests/                # Unit tests
│
└── smart-contracts/          # Solidity contracts (Foundry)
    ├── src/
    │   ├── ProofOfUniqueness.sol    # Main contract
    │   └── Groth16Verifier.sol      # ZK proof verifier
    └── script/               # Deployment scripts
```

## Prerequisites

- **Node.js** ≥ 18.0.0
- **Circom** 2.2.2 ([installation guide](https://docs.circom.io/getting-started/installation/))
- **Foundry** ([installation guide](https://book.getfoundry.sh/getting-started/installation))
- **snarkjs** (installed via npm)

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/Proof-of-Uniqueness.git
cd Proof-of-Uniqueness

# Install root dependencies
npm install

# Install client dependencies
cd src/client && npm install && cd ../..

# Install fuzzy signature library
cd src/ecdsa-fuzzy-signature && npm install && npm run build && cd ../..

# Install smart contract dependencies
cd src/smart-contracts && forge install && cd ../..
```

## Demo Application

The client application includes a **mock credential generator** for testing and development purposes. In production, users would arrive with pre-issued Verifiable Credentials from trusted issuers.

### Running the Demo

```bash
# Start the demo client
cd src/client
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### Deploy Smart Contracts (Local)

```bash
# Start local Ethereum node
anvil

# In another terminal, deploy contracts
cd src/smart-contracts
forge script script/ProofOfUniqueness.s.sol --rpc-url http://localhost:8545 --broadcast
```

### Demo Flow

1. **Generate Mock Credential** — Fill in the identity form (simulates receiving a VC from a trusted issuer)
2. **Generate ZK Proof** — Creates a Groth16 proof of the credential
3. **Enroll On-Chain** — Connect MetaMask and submit the proof to the smart contract

> **Note:** In production, step 1 is replaced by the user presenting an existing VC issued by a trusted authority.

## Components

### ZK Circuit (`src/circuits/`)

The Enrollment circuit verifies:

1. **Signature Validity** — EdDSA Poseidon signature from a trusted issuer
2. **Data Integrity** — All credential fields match the signed message
3. **Privacy** — Only reveals: HashID, issuer, expiration, sketch hash, verification key, signer public key

**Public Outputs:**

| Signal                  | Description                                                     |
| ----------------------- | --------------------------------------------------------------- |
| `hashID`                | Poseidon hash of identity fields (privacy-preserving unique ID) |
| `outIssuer`             | Issuer identifier                                               |
| `outValidUntil`         | Credential expiration timestamp                                 |
| `outSketchHash`         | Hash of biometric sketch (for matching)                         |
| `outVerificationKey[2]` | Biometric verification key (x, y)                               |
| `outSignerPubKey[2]`    | Issuer's public key (for trust verification)                    |

### Smart Contract (`src/smart-contracts/`)

The `ProofOfUniqueness` contract:

- **Enrollment** — Verifies ZK proof and stores identity record
- **Issuer Management** — Add/remove trusted issuers by public key
- **Validity Checks** — Query if identity exists and hasn't expired
- **Purge Functions** — Remove expired or untrusted records

### Fuzzy Signature Library (`src/ecdsa-fuzzy-signature/`)

Enables biometric-based key derivation and signatures:

```typescript
import { enroll, sign, verify } from "ecdsa-fuzzy-signature";

// Enrollment: biometric → (sketch, verification key)
const { vk, sketch } = enroll(biometric);

// Signing: biometric + sketch → signature
const signature = sign(biometric, sketch, message);

// Verification: vk + message + signature → boolean
const isValid = verify(vk, message, signature);
```

This library is used by **trusted issuers** when creating Verifiable Credentials with biometric binding.

### Demo Client (`src/client/`)

React + TypeScript demo application for testing the system:

- **Mock Credential Generation** — Simulates issuer functionality for testing
- **ZK Proof Generation** — In-browser Groth16 proof generation via snarkjs
- **Web3 Integration** — MetaMask connection via Wagmi for on-chain enrollment

> **Production Note:** A production client would only need proof generation and Web3 integration, receiving VCs from external trusted issuers.

## Credential Format

Verifiable Credentials must follow this structure for circuit compatibility:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "BiometricIdentityCredential"],
  "issuer": { "id": "did:babyjubjub:..." },
  "validFrom": "2025-01-02T...",
  "validUntil": "2030-01-02T...",
  "credentialSubject": {
    "id": "urn:person:...",
    "name": "...",
    "dateOfBirth": "...",
    "nationality": "...",
    "sex": "...",
    "biometricTemplate": { "type": "FuzzySignatureTemplate", "template": "..." },
    "biometricVerificationKey": { "type": "FuzzyVerificationKey", "value": "..." }
  },
  "proof": {
    "type": "EdDSAPoseidonSignature2024",
    "signatureR8": ["...", "..."],
    "signatureS": "...",
    "signerPublicKey": ["...", "..."]
  },
  "circuitInputs": { ... }
}
```

## License

GPL-3.0
