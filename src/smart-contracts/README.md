# Smart Contracts

Foundry project containing:

- `IdentityRegistry.sol`
- `VcOprfEnrollmentUltraVerifier.sol` (VC + OPRF enrollment)

## Registry Overview

`IdentityRegistry` is the on-chain acceptance layer for the browser-generated enrollment proof. It stores one active record per nullifier, checks issuer trust, checks that the proof uses the currently trusted OPRF public key, and binds each record to the wallet address exposed by the circuit.

Owners can add or remove trusted issuers, rotate the trusted OPRF public key, and manage other owners. Users enroll with a zk proof plus an EIP-712 wallet signature. Users revoke with an EIP-712 revocation signature; no zk proof is needed for revocation. Expired or untrusted records can be removed with `purgeInvalidRecords()`.

## Commands

```bash
forge build
forge test
forge fmt
```

## Gas Benchmarks

Run the real enrollment verifier benchmark from this directory:

```bash
forge test --match-contract IdentityRegistryEnrollmentVerifierGasTest --gas-report -vv
```

Current real-verifier gas:

- `VcOprfEnrollmentUltraVerifier.verify`: `376,502 gas`
- `IdentityRegistry.enroll`: `614,514 gas`

These are reusable execution-gas numbers after deployment. One-time deployment costs are separate:

- `VcOprfEnrollmentUltraVerifier`: `2,489,530 gas`
- `IdentityRegistry`: `1,535,752 gas`

Registry gas and scaling tests that use mock verifiers should not be read as zk verifier gas.

## Deploy

```bash
# required for local dev because generated verifier exceeds EIP-170 size
anvil --code-size-limit 50000

forge script script/IdentityRegistry.s.sol \
  --rpc-url http://127.0.0.1:8545 \
  --broadcast \
  --disable-code-size-limit \
  --non-interactive
```

### Recommended local deploy (dynamic OPRF key)

Use the helper script below to fetch the live OPRF key (`/oprf_pub/3`) from your node and deploy `IdentityRegistry` with that exact trusted key:

```bash
cd src/smart-contracts

PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
./script/deploy-identity-registry-dynamic-oprf.sh
```

Optional overrides:

```bash
RPC_URL=http://127.0.0.1:8545 \
OPRF_NODE_URL=http://127.0.0.1:10000 \
OPRF_KEY_ID=3 \
PRIVATE_KEY=0x... \
./script/deploy-identity-registry-dynamic-oprf.sh
```

The script exports `OPRF_PUB_KEY_X` / `OPRF_PUB_KEY_Y` for `script/IdentityRegistry.s.sol`, which reads these environment variables when present.

If your terminal is non-interactive and prompts still fail, add:

```bash
--skip-simulation
```

## IdentityRegistry Reference

- **Constructor**: takes the Ultra enrollment verifier address and the initial trusted OPRF public key `(oprfPkX, oprfPkY)` (non-zero, in-circuit field range).
- **Enrollment public signals** (length 7, each value `< SNARK_SCALAR_FIELD`):
  1. `oprfPkX`
  2. `oprfPkY`
  3. `validUntil`
  4. `issuerPubKeyX`
  5. `issuerPubKeyY`
  6. `walletAddress`
  7. `nullifier` (proof return value; must be non-zero on-chain)
- **Trusted OPRF key**: `oprfPkX` / `oprfPkY` in the signals must match `trustedOprfPkX` / `trustedOprfPkY`. Owners can rotate with `setTrustedOprfPublicKey(pkX, pkY)`.
- **Trusted issuers**: stored as `keccak256(abi.encodePacked(issuerPubKeyX, issuerPubKeyY))`. `addTrustedIssuer` rejects `(0, 0)`.
- **Enrollment authorization**: `enroll` stores `walletAddress`. The same address must appear in the proof public signals and must sign the EIP-712 `Enroll` struct:
  - `nullifier`, `publicSignalsHash` (`keccak256` of the packed `bytes32[]` public signals), `proofHash` (`keccak256` of proof bytes), `walletAddress`
  - Domain: `name` `"IdentityRegistry"`, `version` `"1"`, `chainId`, `verifyingContract` = this registry  
  `hashEnrollmentAuthorization` returns the digest to sign. Signature verification runs before the expensive verifier call.
- **Revocation**: `revoke(nullifier, deadline, signature)` checks an EIP-712 `Revoke` signature from the stored `walletAddress`.
- **Purge**: `purgeInvalidRecords()` scans the active nullifier list once per call and deletes records that are expired or whose issuer is no longer trusted. Revoked and purged records are removed from the active scan list with swap-and-pop.
- **Hardening**: signal length and field-range checks, verifier `try/catch`, low-**s** signature checks.

If circuits or public signal layout change, regenerate `VcOprfEnrollmentUltraVerifier.sol` from the circuit artifact and redeploy.

## Script env overrides

`script/IdentityRegistry.s.sol` supports:

- `OPRF_PUB_KEY_X`
- `OPRF_PUB_KEY_Y`

If unset, it uses defaults in the script.
