# Gas Profiling Notes

This repo still uses an on-chain verifier for enrollment, so enrollment gas is mostly driven by proof verification.

Revocation is much simpler than enrollment: it is a wallet signature check plus record and active-list removal.

Last refreshed: 2026-04-30 from:

- `forge test --gas-report`
- `forge test --match-test testEnrollmentScaling -vv`
- `forge test --match-test testPurgeInvalidRecordsGasProfile -vv`
- `forge build --sizes`

## Commands

Run from `src/smart-contracts`:

```bash
forge test --gas-report
forge test --match-test testEnrollmentScaling -vv
forge test --match-test testPurgeInvalidRecordsGasProfile -vv
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

- `purgeInvalidRecords()`
  - scans the active nullifier list on every call,
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

- `IdentityRegistry` deployment cost: `1534996 gas`
- `IdentityRegistry` runtime size: `6479 bytes`
- `IdentityRegistry` initcode size: `7022 bytes`
- Generated `UltraVerifier` runtime size: `11053 bytes`
- `enroll(...)` average gas in the full gas report: `184194`
- `revoke(...)` average gas in the full gas report: `44183`
- `purgeInvalidRecords()` in the full gas report:
  - min: `23520`
  - avg: `2992170`
  - median: `56571`
  - max: `27561684`
  - calls: `20`
- Sequential enrollment scaling sample:
  - Enrollment `#1`: `189948 gas`
  - Enrollment `#100`: `152511 gas`
  - Enrollment `#1000`: `152685 gas`

### Purge scaling profile

`purgeInvalidRecords()` is linear in the active nullifier list. Purged and revoked records are removed from that active list with swap-and-pop, so they do not add recurring scan cost to future purge calls. The full gas report average is not a good standalone estimate because the profiling test intentionally exercises several list sizes. Use this focused profile for sizing:

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

- Enrollment is the expensive path.
- Once the verifier is deployed, per-enrollment gas stays roughly flat even at higher active nullifier counts in the scaling test.
- Revocation is still much cheaper than enrollment because it no longer verifies a zk proof, but it now pays for active-list removal.
- Purging grows linearly with active records only. Removed or revoked records no longer add recurring scan cost to later purge calls.
- Contract size is still affected by the generated verifier contract, not just the registry itself.

## Refreshing measurements

This file is intentionally lightweight. If you need fresh numbers, rerun the commands above and treat those outputs as canonical.
