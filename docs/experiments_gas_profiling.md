# Gas Profiling Notes

This repo still uses an on-chain verifier for enrollment, so enrollment gas is mostly driven by proof verification.

Revocation is much simpler now: it is a wallet signature check plus a record delete.

Last refreshed: 2026-04-25 from:

- `forge test --gas-report`
- `forge test --match-test testEnrollmentScaling -vv`
- `forge build --sizes`

## Commands

Run from `src/smart-contracts`:

```bash
forge test --gas-report
forge test --match-test testEnrollmentScaling -vv
forge build --sizes
```

## What to look at

- `enroll(...)`
  - includes proof verification,
  - trusted OPRF public-key check,
  - issuer trust check,
  - expiry check,
  - wallet address binding check against the proof public signals,
  - duplicate nullifier check,
  - wallet authorization check,
  - storage write.

- `revoke(...)`
  - looks up the identity by nullifier,
  - checks the EIP-712 revocation signature,
  - deletes the stored record.

- admin operations
  - `addTrustedIssuer`
  - `removeTrustedIssuer`
  - `setTrustedOprfPublicKey`

## Current enrollment public signals

The contract expects exactly 7 public signals from `vc_oprf_enrollment_proof`:

1. `oprfPkX`
2. `oprfPkY`
3. `validUntil`
4. `issuerPubKeyX`
5. `issuerPubKeyY`
6. `walletAddress`
7. `nullifier`

## Latest measurements

- `IdentityRegistry` deployment cost: `1488087 gas`
- `IdentityRegistry` runtime size: `6262 bytes`
- `IdentityRegistry` initcode size: `6805 bytes`
- Generated `UltraVerifier` runtime size: `11053 bytes`
- `enroll(...)` average gas in the full gas report: `160780`
- `revoke(...)` average gas in the full gas report: `33837`
- Sequential enrollment scaling sample:
  - Enrollment `#1`: `167706 gas`
  - Enrollment `#100`: `130269 gas`
  - Enrollment `#1000`: `130443 gas`

## Practical takeaway

- Enrollment is the expensive path.
- Once the verifier is deployed, per-enrollment gas stays roughly flat even at higher historical nullifier counts in the scaling test.
- Revocation should be much cheaper than enrollment because it no longer verifies a zk proof.
- Contract size is still affected by the generated verifier contract, not just the registry itself.

## Refreshing measurements

This file is intentionally lightweight. If you need fresh numbers, rerun the commands above and treat those outputs as canonical.
