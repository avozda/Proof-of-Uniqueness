# Client Benchmark Notes

This repo includes two benchmark scripts for the current client-side cryptographic flow.

Last refreshed: 2026-05-05 on Node `v25.5.0`.

## Scripts

Run from `src/client`:

```bash
node scripts/benchmark-current-stack.mjs
ITER=3 node scripts/benchmark-enrollment.mjs
```

Run from `src/smart-contracts`:

```bash
forge test --match-contract IdentityRegistryEnrollmentVerifierGasTest --gas-report -vv
```

## What they measure

`benchmark-current-stack.mjs` covers:

- Poseidon hashing,
- BabyJubJub EdDSA signing,
- VC preprocessing,
- `vc_blinded_query_auth_proof` witness generation,
- `vc_blinded_query_auth_proof` proof generation,
- `vc_blinded_query_auth_proof` verification via `bb verify`.

`benchmark-enrollment.mjs` covers:

- `vc_oprf_enrollment_proof` witness generation,
- `vc_oprf_enrollment_proof` proof generation.

The enrollment benchmark synthesizes a valid OPRF transcript locally, so it does not need live OPRF nodes.
Enrollment proof verification is intentionally not included here because enrollment proofs are verified by the smart contract.
`IdentityRegistryEnrollmentVerifierGasTest` covers real on-chain enrollment verifier gas using a generated proof fixture.

## Timing boundaries

- Witness generation times only `noir.execute(inputs)`.
- Proof generation times only `backend.generateProof(witness)` over a precomputed witness.
- VC auth verification writes the proof input once before timing, then times only the production-style `bb verify -p <proof> -k <vk>` command.
- Each circuit benchmark runs one warm-up proof before timed samples.

## Latest results

`benchmark-current-stack.mjs` average timings:

- Poseidon hash: `0.154 ms`
- BabyJubJub EdDSA sign: `14.021 ms`
- VC preprocessing (Merkle commitment rebuild): `1.305 ms`
- `vc_blinded_query_auth_proof` witness generation: `619.572 ms` average, `610.952 ms` median
- `vc_blinded_query_auth_proof` proof generation: `9601.688 ms` average, `9659.752 ms` median
- `vc_blinded_query_auth_proof` `bb verify`: `73.505 ms` average, `73.703 ms` median
- `vc_blinded_query_auth_proof` public outputs: `3`
- `vc_blinded_query_auth_proof` proof size: `2144 bytes`

`benchmark-enrollment.mjs` average timings:

- `vc_oprf_enrollment_proof` witness generation: `1254.659 ms` average, `1254.904 ms` median
- `vc_oprf_enrollment_proof` proof generation: `18146.380 ms` average, `18141.442 ms` median
- `vc_oprf_enrollment_proof` public outputs: `7`
- `vc_oprf_enrollment_proof` proof size: `2144 bytes`

Foundry enrollment verification gas:

- `VcOprfEnrollmentUltraVerifier.verify`: `376,502 gas`
- `IdentityRegistry.enroll` with the real verifier: `614,514 gas`

These are execution-gas numbers for already deployed contracts. Deployment is separate: the generated verifier currently costs `2,489,530 gas` to deploy, and the registry costs `1,535,752 gas` in the real-verifier benchmark.

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
