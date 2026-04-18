# Smart Contract Gas Profiling Experiment (Noir + OPRF Stack)

## Objective

This experiment measures the gas consumption of the current `IdentityRegistry.sol` implementation that verifies Noir/Ultra-based enrollment and revocation proofs and enforces OPRF-specific policy checks. The goal is to quantify both:

1. storage/policy-path costs (isolated with mock verifiers), and
2. full-path costs when generated Ultra verifiers are included in execution.

## Methodology

### 1) Tooling and Environment

- Framework: **Foundry**
- Compiler: `solc 0.8.33`
- Main command: `forge test --gas-report`
- Additional commands:
  - `forge test --match-test testEnrollmentScaling -vv`
  - `forge build --sizes`

### 2) Test Contracts and Scenarios

- `src/smart-contracts/test/IdentityRegistryGas.t.sol`
  - Uses `MockUltraVerifier` and `MockRevocationVerifier` to isolate registry logic.
  - Covers success and revert paths for:
    - `enroll(...)`
    - `revoke(...)`
    - issuer trust management
    - trusted OPRF public-key rotation
- `src/smart-contracts/test/IdentityRegistryScaling.t.sol`
  - Enrolls 1,000 sequential nullifiers and logs gas for enrollments `#1`, `#100`, and `#1000`.
- `src/smart-contracts/test/IdentityRegistryE2E.t.sol`
  - Exercises paths that include generated Ultra verifier contracts, providing a reality check for full end-to-end cost.

### 3) Public Signal Model Used

The measured enrollment path uses the current canonical 10-signal layout:

1. `oprfPkX`
2. `oprfPkY`
3. `validUntil`
4. `holderPubKeyX`
5. `holderPubKeyY`
6. `issuerPubKeyX`
7. `issuerPubKeyY`
8. `oprfKeyId`
9. `oprfEpoch`
10. `nullifier`

## Results

### A) Gas Report (Current Contract)


| Metric                              | Measured Value           | Source/Notes                                 |
| ----------------------------------- | ------------------------ | -------------------------------------------- |
| `**IdentityRegistry` deployment**   | **1,510,960 gas**        | `forge test --gas-report`                    |
| `**addTrustedIssuer`**              | **47,414 gas (avg)**     | Owner operation                              |
| `**enroll` (global average)**       | **243,245 gas (avg)**    | Mixed call set (success + revert paths)      |
| `**enroll` min / max**              | **25,790 / 265,128 gas** | Mixed reverting/success paths in test corpus |
| `**revoke` (global average)**       | **42,168 gas (avg)**     | Mixed path average                           |
| `**revoke` min / max**              | **25,710 / 58,928 gas**  | Includes successful revocation path          |
| `**setTrustedOprfPublicKey`**       | **29,868 gas (avg)**     | OPRF trust anchor update                     |
| `**removeTrustedIssuer`**           | **25,416 gas (avg)**     | Owner operation                              |
| `**purgeInvalidRecords`**           | **53,166 gas (avg)**     | Permissionless maintenance path              |
| `**purgeInvalidRecords` min / max** | **37,588 / 67,815 gas**  | Depends on scan span and deletions           |


### B) Scaling Benchmark (`IdentityRegistryScaling.t.sol`)

Logged values from `forge test --match-test testEnrollmentScaling -vv`:

- **Enrollment #1:** `245,707` gas
- **Enrollment #100:** `210,760` gas
- **Enrollment #1000:** `210,760` gas

This confirms stable steady-state enrollment cost and supports the expected constant-time behavior of mapping-based deduplication.

### C) Verifier-Inclusive Reality Check (E2E)

The storage/policy gas above isolates registry logic using mocks. End-to-end tests that include generated Ultra verifier contracts show million-gas order in the test harness, for example:

- `testE2E_RealUltraVerifier_RejectsMalformedProof()`: **5,604,895 gas**

This demonstrates that proof verification dominates full enrollment economics on L1.

### D) Contract Size Measurements

From `forge build --sizes`:

- `IdentityRegistry` runtime size: **6,345 bytes**
- `UltraVerifier (VcOprfEnrollmentUltraVerifier.sol)` runtime size: **16,906 bytes**
- `UltraVerifier (VcRevocationUltraVerifier.sol)` runtime size: **11,052 bytes**

The repository keeps `code_size_limit = 50000` in Foundry config to avoid local deployment issues when verifier-heavy contracts are used in dev/test workflows.

## Interpretation

1. **Registry logic is efficient and predictable**: mapping-based duplicate checks and state writes remain stable at scale.
2. **Economic bottleneck is verifier execution**: full-path on-chain proof verification, not storage lookup, is the dominant cost driver.
3. **Operational controls remain modest**: issuer and OPRF key management calls are comparatively inexpensive, while permissionless purge offers bounded maintenance cost.

## Reproducibility

Run from `src/smart-contracts`:

```bash
forge test --gas-report
forge test --match-test testEnrollmentScaling -vv
forge build --sizes
```

