# Gas Profiling Notes

This repo still uses an on-chain verifier for enrollment, so enrollment gas is mostly driven by proof verification.

Revocation is much simpler now: it is a wallet signature check plus a record delete.

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

The contract expects exactly 6 public signals from `vc_oprf_enrollment_proof`:

1. `oprfPkX`
2. `oprfPkY`
3. `validUntil`
4. `issuerPubKeyX`
5. `issuerPubKeyY`
6. `nullifier`

## Practical takeaway

- Enrollment is the expensive path.
- Revocation should be much cheaper than enrollment because it no longer verifies a zk proof.
- Contract size is still affected by the generated verifier contract, not just the registry itself.

## Refreshing measurements

This file is intentionally lightweight. If you need fresh numbers, rerun the commands above and treat those outputs as canonical.
