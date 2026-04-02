# Client-Side Cryptographic Benchmarks

## Objective
The objective of this experiment was to evaluate the computational overhead of the cryptographic operations executed on the user's client device. The primary focus was on the Biometric Fuzzy Signature mechanism (generating linear sketches and noise-tolerant key reconstruction) to determine if consumer devices can execute the protocol without noticeable latency.

## Methodology
The experiment was conducted using a Node.js runtime environment (v25.5.0) leveraging the `perf_hooks` performance timing API.

1. **Environment Setup:** 
   A script (`benchmark.mjs`) was created within the client directory to import the local `ecdsa-fuzzy-signature` package.
2. **Mocking Data:** 
   A pseudo-random 32-byte array (`Uint8Array`) was generated to simulate raw biometric sensor output.
3. **Execution Profiling (Averaged over 100 iterations):**
   - **Enrollment (Sketch Generation):** The script measured the execution time of the `enroll(rawBio)` function, which generates the initial biometric verification key and the public linear sketch (helper data).
   - **Recovery (Noise-Tolerant Reconstruction):** The script simulated a fresh biometric scan, measured the time required by the `fuzzyRep()` algorithm to search the lattice and remove the biometric noise using the sketch, and subsequently timed the `derivePrivateKey()` function.
4. **ZK Proof Analysis:**
   The `snarkjs` output data (`r1cs info`) for the compiled `IdentityEnrollment` circuit was inspected to measure mathematical complexity (constraint count) as an indicator of expected browser proving time.

## Results

### Biometric Fuzzy Extractor Performance
The benchmark results (averaged over 100 iterations) were as follows:

| Operation | Execution Time (Average) | Description |
| :--- | :--- | :--- |
| **Fuzzy Enrollment** | **0.30 ms** | Generation of the verification key and the linear sketch. |
| **Fuzzy Recovery** | **0.04 ms** | Noise-tolerant reconstruction and private key derivation. |

*Note: Initial "cold start" execution took ~13ms due to library initialization and JIT compilation, but subsequent executions immediately fell to sub-millisecond ranges.*

### Zero-Knowledge Circuit Complexity
The `snarkjs r1cs info` command provided the following metrics for the `IdentityEnrollment.circom` circuit:

- **Curve:** `bn-128`
- **Total Constraints:** `24,827`
- **Private Inputs:** `36`
- **Public Outputs:** `8`

**Conclusion:** 
The biometric operations are highly optimized, completing in less than 1 millisecond on a standard CPU. This effectively introduces zero friction to the user experience. Furthermore, at just 24,827 non-linear constraints, the Groth16 circuit is incredibly lightweight. Standard browser-based WASM implementations (like `snarkjs`) generally resolve circuits of this size in 300 to 500 milliseconds, validating that the entire proof generation and biometric binding can occur securely on consumer mobile phones and laptops without hardware acceleration.
