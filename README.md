# Proof of Uniqueness

Privacy-preserving identity enrollment and revocation on Ethereum using Noir + Barretenberg proofs and holder/issuer BabyJubJub EdDSA signatures.

No legacy Circom/Groth16 path is supported.

## End-to-End Flow

1. Client generates holder keypair.
2. Client creates VC and issuer signs VC Merkle root.
3. Client generates enrollment proof and submits to `IdentityRegistry.enroll(...)`.
4. Contract verifies proof + trusted issuer + trusted OPRF key, then stores identity record keyed by nullifier.
5. For revocation, client generates revocation proof (fresh challenge block bound) and submits `IdentityRegistry.revoke(...)`.

## Repository Structure

```text
src/
├── client/
│   ├── public/circuits/
│   └── src/
├── circuits/
│   ├── vc_blinded_query_auth_proof/
│   ├── vc_oprf_enrollment_proof/
│   └── vc_revocation_proof/
├── oprf-testnet/
│   └── noir/
└── smart-contracts/
```

## Local Run

### 1) Start local chain

```bash
anvil
```

### 2) Deploy contracts

```bash
cd src/smart-contracts
forge build
forge script script/IdentityRegistry.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
```

### 3) Run client

```bash
cd src/client
npm install
npm run dev
```

Open `http://localhost:5173`.

## Notes

- Enrollment/revocation artifacts consumed by the client are in `src/client/public/circuits`.
- VC Noir circuit sources are in `src/circuits`.
- If circuits/public signals change, regenerate Noir artifacts, verifier contracts, and redeploy `IdentityRegistry`.
