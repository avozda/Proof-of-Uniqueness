# Client

React + TypeScript frontend for the local Proof of Uniqueness flow.

The app lets you:

- generate a demo verifiable credential
- build a VC + OPRF enrollment proof package in the browser
- register the issuer on-chain
- enroll or revoke an identity through `IdentityRegistry`

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
- MetaMask or another injected wallet connected to the local chain

The `IdentityRegistry` contract address is hardcoded in [src/lib/wagmi.ts](/Users/adamvozda/Documents/Proof-of-Uniqueness/src/client/src/lib/wagmi.ts:1).

## Required Assets

These files must exist in `public/`:

- `barretenberg.wasm`
- `barretenberg-threads.wasm`
- `acvm_js_bg.wasm`
- `noirc_abi_wasm_bg.wasm`
- `circuits/vc_blinded_query_auth_proof.json`
- `circuits/vc_oprf_enrollment_proof.json`

If a WASM file is missing or served as HTML, browser-side proving will fail.

## Main Files

- App shell: [src/App.tsx](/Users/adamvozda/Documents/Proof-of-Uniqueness/src/client/src/App.tsx:1)
- Enrollment / revocation UI: [src/components/ZKProofSection.tsx](/Users/adamvozda/Documents/Proof-of-Uniqueness/src/client/src/components/ZKProofSection.tsx:1)
- OPRF proof builder: [src/lib/oprfEnrollment.ts](/Users/adamvozda/Documents/Proof-of-Uniqueness/src/client/src/lib/oprfEnrollment.ts:1)
- Contract ABI: [src/lib/contractAbi.ts](/Users/adamvozda/Documents/Proof-of-Uniqueness/src/client/src/lib/contractAbi.ts:1)
- Chain + contract config: [src/lib/wagmi.ts](/Users/adamvozda/Documents/Proof-of-Uniqueness/src/client/src/lib/wagmi.ts:1)
