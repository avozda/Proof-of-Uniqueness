# Tech Stack

This repo has five main pieces:

- `src/client`: React + TypeScript app that prepares VC data, generates Noir proofs in the browser, talks to OPRF nodes, and submits on-chain transactions.
- `src/circuits`: Noir circuits for VC auth and VC + OPRF enrollment.
- `src/oprf-testnet`: Rust services and auth module for the local threshold OPRF network.
- `src/smart-contracts`: Solidity registry and generated verifier contract.
- `docs`: short notes like this one.

## Languages

- TypeScript: client UI, proving orchestration, wallet integration, small scripts.
- Noir: the two active VC circuits.
- Rust: OPRF nodes, auth module, and local service tooling.
- Solidity: on-chain verification and identity registry logic.

## Main libraries and tools

- React + Vite: client app.
- wagmi + viem: wallet connection, contract reads, contract writes.
- `@noir-lang/noir_js` + `@noir-lang/backend_barretenberg`: browser witness generation and proof generation.
- `@taceo/oprf-client` + `@taceo/oprf-core`: threshold OPRF client flow.
- Foundry (`forge`, `anvil`): contract build, test, deploy, local chain.
- Nargo + `bb`: compile Noir circuits and generate verifier artifacts.
- Cargo: build and run the Rust OPRF services.

## Cryptography in use

- BabyJubJub EdDSA: issuer signatures and holder signatures inside the Noir circuits.
- Poseidon: field-friendly hashing in the circuits and matching client preprocessing.
- BN254 field arithmetic: shared by Noir, Barretenberg, and the contract verifier path.
- EIP-712 wallet signatures: enrollment and revocation authorization on-chain.

## Why the split looks like this

- The client does the expensive proving work locally in the browser.
- The OPRF nodes only accept requests backed by the VC auth proof.
- The contract only verifies the final enrollment proof and stores minimal identity state.
- Revocation is no longer a zk proof. It is just a wallet signature checked by the contract.

## Important compatibility rule

Noir artifacts, Barretenberg tooling, the generated verifier, and the client circuit JSON need to stay in sync. If a circuit changes, rebuild the artifacts and copy them to the client / Rust / contract locations described in [src/circuits/README.md](/Users/adamvozda/Documents/Proof-of-Uniqueness/src/circuits/README.md).
