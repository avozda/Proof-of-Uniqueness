# Client Benchmark Notes

This repo includes two benchmark scripts for the current browser-side cryptographic flow.

Last refreshed: 2026-04-25 on Node `v25.5.0`.

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

## Latest results

`benchmark-current-stack.mjs` average timings:

- Poseidon hash: `0.150 ms`
- BabyJubJub EdDSA sign: `14.153 ms`
- VC preprocessing (Merkle commitment rebuild): `1.305 ms`
- `vc_blinded_query_auth_proof` witness generation: `624.357 ms`
- `vc_blinded_query_auth_proof` proof generation: `10423.917 ms`
- `vc_blinded_query_auth_proof` local verification: `7356.735 ms`
- `vc_blinded_query_auth_proof` public outputs: `3`
- `vc_blinded_query_auth_proof` proof size: `2144 bytes`

`benchmark-enrollment.mjs` average timings:

- `vc_oprf_enrollment_proof` witness generation: `1315.658 ms`
- `vc_oprf_enrollment_proof` proof generation: `18880.291 ms`
- `vc_oprf_enrollment_proof` local verification: `13951.615 ms`
- `vc_oprf_enrollment_proof` public outputs: `7`
- `vc_oprf_enrollment_proof` proof size: `2144 bytes`

## What matters

- Proof generation is by far the slowest part of the client flow.
- The enrollment circuit is heavier than the auth circuit.
- Binding the proof to `walletAddress` adds one more public signal, but the dominant cost is still proving.
- VC preprocessing and Poseidon hashing are small compared to proving time.
- Revocation is not part of these benchmarks because revocation is now just an EIP-712 wallet signature.

## Current circuit shapes

- `vc_blinded_query_auth_proof`: 3 public outputs
  - `request_id_field`
  - `blinded_query_x`
  - `blinded_query_y`
- `vc_oprf_enrollment_proof`: 7 public outputs
  - `oprfPkX`
  - `oprfPkY`
  - `validUntil`
  - `issuerPubKeyX`
  - `issuerPubKeyY`
  - `walletAddress`
  - `nullifier`

## Refreshing the numbers

If you want exact numbers, rerun the scripts locally. The scripts are the source of truth; this file is just a guide to what they cover.
