# Client-Side Cryptographic Benchmarks (Current Stack)

## Objective

This experiment evaluates the computational overhead of the **current** client cryptographic stack:

- BabyJubJub EdDSA + Poseidon preprocessing,
- Noir witness generation,
- Barretenberg proof generation and verification.

The previous biometric fuzzy-signature benchmark is no longer relevant because that module was removed from the active architecture.

## Methodology

### 1) Environment

- Node.js: `v25.5.0`
- Runtime timing API: `perf_hooks`
- Script used:
  - `src/client/scripts/benchmark-current-stack.mjs`

### 2) Inputs and Measurement Strategy

#### A. Crypto Micro-benchmarks (Poseidon / EdDSA / VC preprocessing)

The benchmark measures per-iteration CPU time for:

1. Poseidon hash over 9 field inputs (current HashID preimage arity)
2. EdDSA Poseidon signing on BabyJubJub
3. Deterministic VC preprocessing (13 labeled leaves + 16-leaf Merkle root)

Procedure:

- 3 independent runs
- 200 iterations per run
- warm-up performed before timing windows

#### B. Noir + Barretenberg Proof Pipeline

For proof-generation measurements, the script executes real circuits from `public/circuits`:

- `vc_blinded_query_auth_proof.json`
- `vc_oprf_enrollment_proof.json`
- `vc_revocation_proof.json`

For each iteration it records:

1. witness generation time (`noir.execute`)
2. proof generation time (`backend.generateProof`)
3. proof verification time (`backend.verifyProof`)

Input witnesses are deterministic and valid, generated in-script to satisfy all circuit constraints.

### 3) Circuit Complexity Snapshot

Complexity was also measured using Noir tooling (`nargo info`) and Barretenberg (`bb gates`).

## Results

### A) Crypto Micro-benchmarks

Average across 3 runs (200 iterations each):


| Operation                                  | Average Time    | Notes                     |
| ------------------------------------------ | --------------- | ------------------------- |
| Poseidon hash (9-field input)              | **0.17308 ms**  | Per hash                  |
| EdDSA sign (BabyJubJub, Poseidon)          | **13.47499 ms** | Per signature             |
| VC preprocessing (13 leaves + Merkle root) | **1.24071 ms**  | Per VC preprocessing pass |


Repeated execution produced similar values (about 1--2% variation), which is expected for JS/WASM timing on a general-purpose CPU.

### B) Noir + Barretenberg Proof Benchmarks

#### `vc_blinded_query_auth_proof` (3 iterations)

- Average witness generation: **593.99 ms**
- Average proof generation: **9,910.12 ms**
- Average local verification: **6,994.28 ms**
- Proof size: **2,144 bytes**
- Public input count: **4**

#### `vc_oprf_enrollment_proof` (3 iterations)

- Average witness generation: **1,407.44 ms**
- Average proof generation: **18,521.21 ms**
- Average local verification: **14,008.92 ms**
- Median proof generation: **18,525.68 ms**
- Median local verification: **14,012.16 ms**
- Proof size: **2,144 bytes**
- Public input count: **10**

#### `vc_revocation_proof` (5 iterations)

- Average witness generation: **165.08 ms**
- Average proof generation: **4,703.79 ms**
- Average local verification: **3,765.43 ms**

A follow-up run remained within sub-1% variance for witness/prove/verify timings in both circuits.

- Proof size: **2,144 bytes**
- Public input count: **4**

### C) Circuit Complexity

From `nargo info` and `bb gates`:


| Circuit                       | ACIR Opcodes | Circuit Size (gates) |
| ----------------------------- | ------------ | -------------------- |
| `vc_blinded_query_auth_proof` | **59,338**   | **61,794**           |
| `vc_oprf_enrollment_proof`    | **121,335**  | **120,673**          |
| `vc_revocation_proof`         | **18,427**   | **21,269**           |


## Interpretation

1. **Client proving is feasible but non-trivial**
  - Proof generation dominates latency, especially for auth and enrollment-class circuits.
2. **Enrollment is the dominant UX cost**
  - The `vc_oprf_enrollment_proof` circuit has roughly twice the gate count of the auth circuit and shows a correspondingly larger proving cost (~18.5 s vs ~9.9 s). It is the critical-path bottleneck for first-time onboarding.
3. **Revocation proving is significantly lighter**
  - Lower witness/prove times align with the smaller circuit size.
4. **Preprocessing overhead is small compared to proving**
  - VC hashing and leaf construction are sub-millisecond to low-millisecond operations, while proving is multi-second.
5. **Proofs stay succinct regardless of circuit size**
  - All three circuits produce 2,144-byte Barretenberg Ultra proofs; only the number of public inputs differs (4 for auth/revocation, 10 for enrollment).

These measurements match the architecture expectation: user experience is primarily constrained by Noir/Barretenberg proving, not by EdDSA/Poseidon preprocessing.

## Reproducibility

Run from `src/client`:

```bash
node scripts/benchmark-current-stack.mjs             # auth + revocation + micros
ITER=3 node scripts/benchmark-enrollment.mjs         # enrollment circuit (heavy)
```

For circuit complexity:

```bash
nargo info                              # inside each circuit directory
bb gates -b target/<circuit>.json
```

