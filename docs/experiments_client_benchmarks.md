# Client Benchmark Notes

This repo includes two benchmark scripts for the current browser-side cryptographic flow.

## Scripts

Run from `src/client`:

```bash
node scripts/benchmark-current-stack.mjs
ITER=3 node scripts/benchmark-enrollment.mjs
```

## What they measure

`benchmark-current-stack.mjs` covers:

- Poseidon hashing,
- BabyJubJub EdDSA signing,
- VC preprocessing,
- `vc_blinded_query_auth_proof` witness generation,
- `vc_blinded_query_auth_proof` proof generation,
- `vc_blinded_query_auth_proof` local verification.

`benchmark-enrollment.mjs` covers:

- `vc_oprf_enrollment_proof` witness generation,
- `vc_oprf_enrollment_proof` proof generation,
- `vc_oprf_enrollment_proof` local verification.

The enrollment benchmark synthesizes a valid OPRF transcript locally, so it does not need live OPRF nodes.

## What matters

- Proof generation is by far the slowest part of the client flow.
- The enrollment circuit is heavier than the auth circuit.
- VC preprocessing and Poseidon hashing are small compared to proving time.
- Revocation is not part of these benchmarks because revocation is now just an EIP-712 wallet signature.

## Current circuit shapes

- `vc_blinded_query_auth_proof`: 3 public outputs
  - `request_id_field`
  - `blinded_query_x`
  - `blinded_query_y`
- `vc_oprf_enrollment_proof`: 6 public outputs
  - `oprfPkX`
  - `oprfPkY`
  - `validUntil`
  - `issuerPubKeyX`
  - `issuerPubKeyY`
  - `nullifier`

## Refreshing the numbers

If you want exact numbers, rerun the scripts locally. The scripts are the source of truth; this file is just a guide to what they cover.
