# Client

React + TypeScript frontend for the local Proof of Uniqueness flow.

The app lets you:

- generate a demo verifiable credential
- build a VC + OPRF enrollment proof package in the browser
- register the issuer on-chain
- enroll or revoke an identity through `IdentityRegistry`

## Technical Flow

The client prepares the VC fields in the same order expected by the Noir circuits. For OPRF access, it builds a `vc_blinded_query_auth_proof` proof that binds the holder key to the blinded query and request id. The local OPRF nodes verify that proof before returning threshold responses.

After the browser verifies and unblinds the OPRF transcript, it builds the `vc_oprf_enrollment_proof` proof. That proof exposes the trusted OPRF public key, VC expiry, issuer key, wallet address, and nullifier. The connected wallet signs an EIP-712 enrollment message, then the client calls `IdentityRegistry.enroll`. Revocation is lighter: the wallet signs an EIP-712 revocation message and the client calls `revoke`.

## Run

```bash
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

Other useful commands:

```bash
npm run build
npm run lint
npm run preview
```

## Local Requirements

The current client is wired to local services only:

- Anvil at `http://127.0.0.1:8545`
- OPRF node 1 at `http://127.0.0.1:10000`
- OPRF node 2 at `http://127.0.0.1:10001`
- OPRF node 3 at `http://127.0.0.1:10002`
- OPRF threshold `2`
- OPRF auth module `vc-ownership`
- local API key `test`
- MetaMask or another injected wallet connected to the local chain

The `IdentityRegistry` contract address is hardcoded in [src/lib/wagmi.ts](src/lib/wagmi.ts). Issuer registration also uses the default local Anvil owner private key from this file, so the tester does not need to import that owner account into MetaMask. MetaMask is still used for enrollment and revocation.

## Required Assets

These files must exist in `public/`:

- `barretenberg.wasm`
- `barretenberg-threads.wasm`
- `acvm_js_bg.wasm`
- `noirc_abi_wasm_bg.wasm`
- `circuits/vc_blinded_query_auth_proof.json`
- `circuits/vc_oprf_enrollment_proof.json`

If a WASM file is missing or served as HTML, browser-side proving will fail.

## Core Files

- App shell: [src/App.tsx](src/App.tsx)
- Enrollment / revocation UI: [src/components/ZKProofSection.tsx](src/components/ZKProofSection.tsx)
- OPRF proof builder: [src/lib/oprfEnrollment.ts](src/lib/oprfEnrollment.ts)
- Contract ABI: [src/lib/contractAbi.ts](src/lib/contractAbi.ts)
- Chain + contract config: [src/lib/wagmi.ts](src/lib/wagmi.ts)
