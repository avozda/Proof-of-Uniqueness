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

The script exports `OPRF_PUB_KEY_X` / `OPRF_PUB_KEY_Y` for `script/IdentityRegistry.s.sol`, which now reads these environment variables when present.

If your terminal is non-interactive and prompts still fail, add:

```bash
--skip-simulation
```

## Notes

- `IdentityRegistry` expects an Ultra enrollment verifier address and an initial trusted OPRF public key `(oprfPkX, oprfPkY)` in constructor.
- Enrollment public signals are expected as:
  1. `oprfPkX`
  2. `oprfPkY`
  3. `validUntil`
  4. `holderPubKeyX`
  5. `holderPubKeyY`
  6. `issuerPubKeyX`
  7. `issuerPubKeyY`
  8. `oprfKeyId`
  9. `oprfEpoch`
  10. `nullifier` (proof return value)
- Enrollment also stores a wallet `revocationAddress`; that wallet must sign the enrollment authorization.
- Revocation is authorized by an EIP-712 wallet signature over `nullifier` and `deadline`.
- Trusted issuers are stored as `keccak256(issuerPubKeyX, issuerPubKeyY)` hashes.
- Trusted OPRF public key is enforced on `enroll(...)` by matching signals `oprfPkX/oprfPkY` to contract state.
- Owners can rotate trusted OPRF key with `setTrustedOprfPublicKey(pkX, pkY)`.
- Revocation uses `revoke(nullifier, deadline, signature)` and checks the signature against the stored revocation address.
- `script/IdentityRegistry.s.sol` supports env overrides:
  - `OPRF_PUB_KEY_X`
  - `OPRF_PUB_KEY_Y`
  If unset, it falls back to defaults defined in the script.
- Contract hardening includes field-range checks, strict signal-length checks, and verifier revert handling.
- If circuits/public signals change, regenerate verifiers and redeploy.
