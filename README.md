# Proof of Uniqueness

Privacy-preserving identity enrollment and revocation on Ethereum using ZK proofs, verifiable credentials, and biometric fuzzy extraction.

## Current Crypto Suite

- Holder and issuer signatures: **BabyJubJub EdDSA + Poseidon**
- Enrollment verification: **Groth16 proof** (`IdentityEnrollment`)
- Revocation verification: **Groth16 proof** (`IdentityRevocation`)
- Biometric helper data: fuzzy sketch + deterministic key reconstruction

No legacy ECDSA/secp256k1 path is supported.

## End-to-End Flow

1. Client enrolls biometric input and produces `(sketch, holder keypair)`.
2. Client creates VC, issuer signs VC Merkle root, holder signs subject binding.
3. Client generates enrollment proof and submits to `IdentityRegistry.enroll(...)`.
4. Contract verifies proof + trusted issuer, stores identity record keyed by `hashID`.
5. For revocation, client generates revocation proof (fresh challenge bound to chain + contract + hashID) and submits `revokeIdentityWithProof(...)`.

## Repository Structure

```text
src/
├── circuits/
│   ├── IdentityEnrollment.circom
│   ├── IdentityRevocation.circom
│   └── build/
├── client/
│   ├── public/circuits/
│   └── src/
├── EdDSA-fuzzy-signature/
└── smart-contracts/
```

## Local Run

### 1) Start local chain

```bash
anvil
```

### 2) Build EdDSA fuzzy package

```bash
cd src/EdDSA-fuzzy-signature
npm install
npm run build
```

### 3) Deploy contracts

```bash
cd src/smart-contracts
forge build
forge script script/IdentityRegistry.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
```

### 4) Run client

```bash
cd src/client
npm install
npm run dev
```

Open `http://localhost:5173`.

## Notes

- Enrollment/revocation artifacts consumed by the client are in `src/client/public/circuits`.
- If you regenerate circuit artifacts, copy updated `.wasm`, `.zkey`, and verification keys into that folder.
- If you change public signals, regenerate Solidity verifiers and redeploy `IdentityRegistry`.
