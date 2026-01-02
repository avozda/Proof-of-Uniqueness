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
  <img src="https://img.shields.io/badge/License-ISC-green" alt="License" />
</p>

---

## Overview

**Proof of Uniqueness** enables users to create verifiable identity credentials from biometric data without revealing the biometric itself. The system combines:

- **Fuzzy Extractors** — Derive stable cryptographic keys from noisy biometric inputs
- **Zero-Knowledge Proofs** — Prove credential validity without revealing private data
- **W3C Verifiable Credentials** — Industry-standard credential format with EdDSA Poseidon signatures
- **On-chain Verification** — Ethereum smart contracts for decentralized identity enrollment

### How It Works

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           ENROLLMENT FLOW                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Biometric ──► Fuzzy Extractor ──► Sketch + Verification Key           │
│       │                                      │                           │
│       ▼                                      ▼                           │
│   Identity ──► VC Generator ──► Signed Credential (EdDSA Poseidon)      │
│     Data                              │                                  │
│                                       ▼                                  │
│                              ZK Proof Generator (Groth16)                │
│                                       │                                  │
│                                       ▼                                  │
│                              Smart Contract (enroll)                     │
│                                       │                                  │
│                                       ▼                                  │
│                              On-chain Identity Record                    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## Features

- **Privacy-Preserving** — Biometric data never leaves the client; only ZK proofs are submitted
- **Sybil Resistance** — Each identity can only enroll once (enforced by HashID)
- **Issuer Trust Model** — Smart contract maintains whitelist of trusted credential issuers
- **Expiration Support** — Credentials have validity periods enforced on-chain
- **Biometric Recovery** — Fuzzy extractors allow key recovery from slightly different biometric readings

## Project Structure

```
src/
├── circuits/                 # Circom ZK circuits
│   ├── Enrollment.circom     # Main enrollment circuit
│   └── build/                # Compiled circuits (wasm, zkey, r1cs)
│
├── client/                   # React web application
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

## Quick Start

### 1. Start the Client

```bash
cd src/client
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### 2. Deploy Smart Contracts (Local)

```bash
# Start local Ethereum node
anvil

# In another terminal, deploy contracts
cd src/smart-contracts
forge script script/ProofOfUniqueness.s.sol --rpc-url http://localhost:8545 --broadcast
```

### 3. Generate a Credential

1. Fill in the identity form in the web UI
2. Click "Generate Credential" — this creates a W3C Verifiable Credential signed with EdDSA Poseidon
3. Click "Generate ZK Proof" — creates a Groth16 proof of the credential
4. Connect MetaMask and click "Enroll Identity On-Chain"

## Components

### ZK Circuit (`src/circuits/`)

The Enrollment circuit verifies:

1. **Signature Validity** — EdDSA Poseidon signature from a trusted issuer
2. **Data Integrity** — All credential fields match the signed message
3. **Privacy** — Only reveals: HashID, issuer, expiration, sketch hash, verification key, signer public key

**Public Outputs:**
| Signal | Description |
|--------|-------------|
| `hashID` | Poseidon hash of identity fields (privacy-preserving unique ID) |
| `outIssuer` | Issuer identifier |
| `outValidUntil` | Credential expiration timestamp |
| `outSketchHash` | Hash of biometric sketch (for matching) |
| `outVerificationKey[2]` | Biometric verification key (x, y) |
| `outSignerPubKey[2]` | Issuer's public key (for trust verification) |

### Smart Contract (`src/smart-contracts/`)

The `ProofOfUniqueness` contract:

- **Enrollment** — Verifies ZK proof and stores identity record
- **Issuer Management** — Add/remove trusted issuers by public key
- **Validity Checks** — Query if identity exists and hasn't expired
- **Purge Functions** — Remove expired or untrusted records

### Fuzzy Signature Library (`src/ecdsa-fuzzy-signature/`)

Enables biometric-based signatures:

```typescript
import { enroll, sign, verify } from "ecdsa-fuzzy-signature";

// Enrollment: biometric → (sketch, verification key)
const { vk, sketch } = enroll(biometric);

// Signing: biometric + sketch → signature
const signature = sign(biometric, sketch, message);

// Verification: vk + message + signature → boolean
const isValid = verify(vk, message, signature);
```

### Client Application (`src/client/`)

React + TypeScript web app featuring:

- **DID Generation** — BabyJubJub EdDSA keypairs with `did:babyjubjub:` method
- **VC Creation** — W3C Verifiable Credentials 2.0 with biometric templates
- **ZK Proof Generation** — In-browser Groth16 proof generation via snarkjs
- **Web3 Integration** — MetaMask connection via Wagmi for on-chain enrollment

## License

GPL-3.0
