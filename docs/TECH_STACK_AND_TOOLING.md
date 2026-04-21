# Technology Stack and Tooling Rationale

This document summarizes the technologies used in this repository and why each is needed for the current VC + OPRF + on-chain verification architecture.

## 1) Languages

### TypeScript (Client + Node scripts)

- Used in browser app (`src/client/src/**`) for UI, proving orchestration, and wallet/contract integration.
- Needed because:
  - strong typing for proof payloads and public-signal structures,
  - easy integration with React, wagmi, viem, Noir JS, and OPRF JS SDKs,
  - same ecosystem supports small Node helper scripts.

### Rust (OPRF node/auth/client)

- Used in `src/oprf-testnet/**` for auth modules, node services, and CLI client.
- Needed because:
  - robust service implementation and concurrency via Tokio,
  - direct integration with `taceo-oprf` service/types/core crates,
  - strong correctness guarantees for auth-critical server code.

### Solidity (On-chain verification)

- Used in `src/smart-contracts/src/**` for registry and verifier integration.
- Needed because:
  - final trust boundary is EVM verification and state updates,
  - enforces strict public-signal checks and business policy (trusted issuer, expiry, key id).

### Noir (ZK circuits)

- Used for VC circuits in `src/circuits/**` and TACEO OPRF example circuits/vendor libraries in `src/oprf-testnet/noir/**`.
- Needed because:
  - expressive ZK circuit authoring for VC ownership and combined VC+OPRF constraints,
  - compatible with Barretenberg backend and generated EVM verifier flow.

## 2) ZK and Cryptographic Components

### Noir JS + Barretenberg backend

- Packages: `@noir-lang/noir_js`, `@noir-lang/backend_barretenberg` (client), plus Rust-side Noir tooling crates.
- Needed because:
  - browser-side witness/proof generation for both auth proof and enrollment proof,
  - local proof verification/self-check before submission,
  - compatibility with Ultra/Barretenberg-generated verifier artifacts.

### BabyJubJub EdDSA

- Used for issuer signatures, holder binding signatures, and holder live-request signature.
- Needed because:
  - circuit-friendly signature primitive on BN254 ecosystem,
  - efficient verification in Noir circuits and off-chain checks.

### Poseidon hash

- Used for domain-separated message hashing and field-friendly hashing.
- Needed because:
  - ZK-friendly hash function for circuit and off-chain consistency,
  - avoids expensive non-native hash constructions inside circuits.

### BN254 field constraints

- Field modulus checks exist in client and contract code.
- Needed because:
  - public signals must remain valid field elements,
  - prevents invalid scalar encodings entering verifier path.

## 3) OPRF Stack

### JavaScript OPRF SDK

- `@taceo/oprf-client`, `@taceo/oprf-core` in client.
- Needed because:
  - browser computes blinded queries, session orchestration, response unblinding, transcript validation,
  - implements threshold OPRF interaction from frontend flow.

### Rust OPRF crates

- `taceo-oprf` and related crates in `src/oprf-testnet` workspace.
- Needed because:
  - node-side service runtime and auth integration,
  - typed request/auth handling and protocol consistency.

### Auth module: `vc-ownership`

- Implemented in `src/oprf-testnet/oprf-testnet-authentication/src/vc_ownership.rs`.
- Needed because:
  - binds OPRF access to a valid VC ownership proof,
  - uses a blinded-query auth proof shape that does not expose `hashID` in public auth outputs,
  - additionally binds each request to holder key control via live signature,
  - enforces strict auth payload format.

## 4) Frontend and Web3

### React + Vite

- React for UI state flow; Vite for fast dev/build pipeline.
- Needed because:
  - interactive multi-step UX (generate, observe progress, submit),
  - build toolchain that supports wasm assets required by proving runtime.

### wagmi + viem

- Used for wallet connection, transaction submission, and contract reads/writes.
- Needed because:
  - typed EVM interactions,
  - robust transaction lifecycle handling in UI.

### TanStack Query

- Transitively used via wagmi/react-query integration.
- Needed because:
  - consistent async request caching and status management for contract reads.

## 5) Smart Contract Tooling

### Foundry (`forge`, `anvil`)

- Config: `src/smart-contracts/foundry.toml`.
- Needed because:
  - compile, test, and deploy Solidity contracts,
  - local EVM simulation for full E2E.

#### Why larger code size limit is configured

- Generated verifier contracts are large.
- `code_size_limit = 50000` (and matching local Anvil settings) is needed for local deployments of verifier-heavy contracts.

## 6) Rust Service Tooling

### Tokio + Axum + Reqwest + Serde ecosystem

- Present across OPRF node/auth crates.
- Needed because:
  - async network services and HTTP integrations,
  - secure API key validation path,
  - structured serialization/deserialization for auth payloads.

## 7) Node Helper Scripts

### `verify-vc-ownership-auth.mjs`

- Path: `src/client/scripts/verify-vc-ownership-auth.mjs`.
- Used by Rust auth module via `node` subprocess.
- Needed because:
  - verifies VC ownership proof with Noir JS + Barretenberg in a format compatible with browser-generated payloads,
  - verifies holder request signature with same domain/message rules as client,
  - provides a deterministic bridge between Rust auth path and JS proof format/runtime.

## 8) Circuit and Artifact Tooling

### Nargo / Noir toolchain

- VC circuits are defined with `Nargo.toml` in `src/circuits/**`; TACEO OPRF example circuits remain under `src/oprf-testnet/noir/**`.
- Needed because:
  - compile circuits to artifacts consumed by browser and verifier generation pipelines,
  - maintain reproducible circuit definitions and dependencies.

### Barretenberg CLI (`bb`)

- Used in parts of Rust-side proof workflows and historical verification flows.
- Needed because:
  - circuit proof tooling and compatibility checks for Noir ecosystem,
  - artifact generation/verification operations outside browser runtime.

## 9) Operational Constraints and Compatibility

### Noir/Barretenberg version alignment

- Critical requirement: circuit `noir_version` must match backend expectations.
- Why needed:
  - mismatches can produce invalid proofs, verifier rejections, or runtime failures.

### Endianness handling for public inputs

- Current auth flow uses LE byte parsing for browser-produced public inputs.
- Why needed:
  - prevents false proof/signature rejection from serialization mismatch.

### Strict vc-ownership-only mode

- Client and auth flow are constrained to `authModule: "vc-ownership"`.
- Contract enforces `oprfKeyId == 3`.
- Contract also anchors accepted enrollments to an owner-managed trusted OPRF public key (`oprfPkX/oprfPkY`).
- Why needed:
  - eliminates ambiguous/legacy auth paths,
  - ensures one consistent trust model from request auth to on-chain enrollment.

## 10) Main CLIs Used in Development

- `npm` / `node`: frontend build/run and JS helper scripts.
- `cargo`: build/test Rust OPRF services and CLI client.
- `forge`: build/test/deploy smart contracts.
- `anvil`: local EVM node.
- `nargo`: Noir circuit lifecycle.
- `bb`: Barretenberg proof tooling.

Each is necessary because this project spans browser proving, Rust network/auth services, and EVM verification; no single toolchain covers all layers safely.
