# Gas Profiling Notes

This repo verifies the enrollment proof on-chain, so the important enrollment gas number is the reusable per-enrollment transaction cost after the verifier and registry are already deployed.

Last refreshed: 2026-05-05 from:

- `forge test --match-contract IdentityRegistryEnrollmentVerifierGasTest --gas-report -vv`
- `forge test --match-contract IdentityRegistryGasTest --gas-report -vv`
- `forge test --match-test testPurgeInvalidRecordsGasProfile -vv`
- `forge build --sizes`

## Commands

Run from `src/smart-contracts`:

```bash
forge test --match-contract IdentityRegistryEnrollmentVerifierGasTest --gas-report -vv
forge test --match-contract IdentityRegistryGasTest --gas-report -vv
forge test --match-test testPurgeInvalidRecordsGasProfile -vv
forge build --sizes
```

`IdentityRegistryEnrollmentVerifierGasTest` is the canonical enrollment verifier benchmark. It loads a generated `vc_oprf_enrollment_proof` fixture and calls the real generated `VcOprfEnrollmentUltraVerifier`.

`IdentityRegistryGasTest` and `IdentityRegistryScalingTest` use mock verifiers for registry behavior and scaling tests. Do not use their `enroll(...)` gas as zk verifier gas.

## What to look at

- `enroll(...)`
  - includes real proof verification in `IdentityRegistryEnrollmentVerifierGasTest`,
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

- `purgeInvalidRecords(start, maxScans)`
  - scans at most `maxScans` active records per call,
  - checks each live record for expiry and issuer trust,
  - deletes records that are expired or whose issuer is no longer trusted,
  - removes purged and revoked nullifiers from the active scan list with swap-and-pop.

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

Canonical real enrollment verifier gas:

- `VcOprfEnrollmentUltraVerifier.verify`: `376,502 gas`
- `IdentityRegistry.enroll` with the real verifier: `614,514 gas`

Deployment and code size are separate from reusable per-enrollment gas:

- `VcOprfEnrollmentUltraVerifier` deployment cost: `2,489,530 gas`
- `IdentityRegistry` deployment cost in the real-verifier benchmark: `1,535,752 gas`
- `VcOprfEnrollmentUltraVerifier` runtime size: `11,053 bytes`
- `VcOprfEnrollmentUltraVerifier` initcode size: `13,868 bytes`
- `IdentityRegistry` runtime size: `6,479 bytes`
- `IdentityRegistry` initcode size: `7,022 bytes`

Registry-only behavior tests with the mock verifier currently show:

- `revoke(...)` average gas: `42,162 gas`
- paginated purge gas depends on `maxScans` and the number of invalid records in that batch

Those mock-verifier registry numbers are useful for non-zk registry behavior only. They intentionally exclude real enrollment proof verification.

### Purge scaling profile

`purgeInvalidRecords(start, maxScans)` is linear in the number of records inspected in one batch and bounded by `maxScans`. Purged and revoked records are removed from the active list with swap-and-pop, so they do not add recurring scan cost to future purge calls. The table below is the pre-pagination full-pass baseline; rerun the focused profile before publishing updated measurements.

| Active records at start | Live valid scan gas | Live valid gas/record | Remove all gas | Remove all gas/record | Marginal remove gas/record | Next empty purge gas |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 2,045 | 2,045 | 5,561 | 5,561 | 3,516 | 815 |
| 10 | 13,117 | 1,311 | 55,126 | 5,512 | 4,200 | 815 |
| 100 | 123,996 | 1,239 | 550,936 | 5,509 | 4,269 | 920 |
| 500 | 620,238 | 1,240 | 2,757,983 | 5,515 | 4,275 | 949 |
| 1000 | 1,248,451 | 1,248 | 5,524,702 | 5,524 | 4,276 | 1,009 |

For larger lists, a practical estimate is:

```text
purge gas ~= 1,248 * active_records_scanned
          + 4,276 * invalid_active_records_removed
```

Equivalently, an invalid active record that is removed costs about `5,524 gas` total: about `1,248 gas` to scan/check it plus about `4,276 gas` for swap-and-pop removal, record deletion, and the purge event. Small lists have a bit more fixed overhead, so the formula is most useful once the scan is at least a few dozen records.

## Practical takeaway

- Enrollment is the expensive path: `614,514 gas` for the full transaction path with the real verifier.
- The verifier-only part of enrollment is `376,502 gas`.
- Deployment/setup is separate from the reusable per-user enrollment cost.
- Revocation is much cheaper than enrollment because it no longer verifies a zk proof, but it still pays for active-list removal.
- Purging grows linearly with active records only. Removed or revoked records no longer add recurring scan cost to later purge calls.
- Contract size is still affected by the generated verifier contract, not just the registry itself.

## Refreshing measurements

This file is intentionally lightweight. If you need fresh numbers, rerun the commands above and treat those outputs as canonical.
