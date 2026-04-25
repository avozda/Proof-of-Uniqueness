# Smart Contracts

Foundry project containing:

- `IdentityRegistry.sol`
- `VcOprfEnrollmentUltraVerifier.sol` (VC + OPRF enrollment)

## Commands

```bash
forge build
forge test
forge fmt
```

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

## IdentityRegistry behavior

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
- **Trusted issuers**: `keccak256(abi.encodePacked(issuerPubKeyX, issuerPubKeyY))`. `addTrustedIssuer` rejects `(0, 0)`.
- **Wallet binding**: `enroll` stores `walletAddress`. The same address must now appear in the proof public signals and must provide an **EIP-712** signature (`signTypedData` / EIP-712 v4) over the `Enroll` struct:
  - `nullifier`, `publicSignalsHash` (`keccak256` of the packed `bytes32[]` public signals), `proofHash` (`keccak256` of proof bytes), `walletAddress`
  - Domain: `name` `"IdentityRegistry"`, `version` `"1"`, `chainId`, `verifyingContract` = this registry  
  On-chain, `hashEnrollmentAuthorization` returns the final digest; `domainSeparator()` matches that domain. Signature verification runs before the ZK verifier call, then the registry checks that the proof-bundled `walletAddress` matches the transaction payload.
- **Revocation**: `revoke(nullifier, deadline, signature)` — EIP-712 `Revoke` over `nullifier` and `deadline` with the same domain; signer must be the stored `walletAddress`. `hashRevocationAuthorization` returns the digest to sign.
- **Purge**: `purgeInvalidRecords()` scans the full historical nullifier list once per call and deletes records that are expired or whose issuer is no longer trusted.
- **Hardening**: signal length and field-range checks, verifier `try/catch`, low-**s** signature checks.

If circuits or public signal layout change, regenerate `VcOprfEnrollmentUltraVerifier.sol` from the circuit artifact and redeploy.

## Script env overrides

`script/IdentityRegistry.s.sol` supports:

- `OPRF_PUB_KEY_X`
- `OPRF_PUB_KEY_Y`

If unset, it uses defaults in the script.
