# VC + OPRF Enrollment Data Flow

This document describes the current end-to-end data flow for VC-based OPRF enrollment, including what gets enforced at each layer.

## 1) High-Level Flow

1. User clicks **Generate OPRF Enrollment Package** in the client UI.
2. Client validates fixed OPRF config (`vc-ownership`, threshold, node URLs, API key).
3. Client builds VC ownership Noir inputs from VC fields + signatures.
4. Client generates VC ownership proof in-browser.
5. Client opens OPRF sessions with nodes and authenticates using:
   - VC ownership proof/public inputs
   - holder request signature bound to request data
6. OPRF nodes return threshold responses; client verifies DLOG equality, unblinds, and finalizes OPRF output.
7. Client builds combined `vc_oprf_enrollment_proof` inputs and generates enrollment proof in-browser.
8. Client outputs package:
   - `proof: 0x...`
   - `publicSignals: bytes32[10]`
9. User submits package to `IdentityRegistry.enroll(proof, publicSignals)`.
10. Contract enforces signal structure + metadata + trust/expiry invariants and calls verifier.
11. On success, identity is stored by `nullifier`.

## 2) Client-Side Flow (Detailed)

Primary implementation: `src/client/src/lib/oprfEnrollment.ts`

### A. VC preprocessing

- VC subject/issuer fields are mapped to field elements.
- Merkle leaves are built from labeled VC fields.
- Issuer signature is decoded from VC.
- Holder live binding signature is computed on demand from holder private key over circuit-derived `hashID`.
- Hard checks:
  - holder key in VC matches active holder keypair,
  - issuer key in VC proof matches active issuer key,
  - `validUntil` is positive.

### B. Blinded-query auth proof for OPRF auth

- Circuit artifact: `/circuits/vc_blinded_query_auth_proof.json`.
- Toolchain check: circuit `noir_version` must match backend family (`0.36.x`).
- Proof is generated using `@noir-lang/noir_js` + `@noir-lang/backend_barretenberg`.
- Client serializes public inputs as **little-endian** 32-byte limbs for auth compatibility.
- Auth proof public outputs are:
  - `blindedQueryX`
  - `blindedQueryY`
  - `holderPubKeyX`
  - `holderPubKeyY`
- `hashID` remains private and is not included in auth proof public outputs.
- VC no longer needs to embed `holderBindingSignature`; holder binding is proven live during proving.

### C. Holder request signature binding

- Message domain: `holder-bjj-oprf-auth:v1`.
- Message payload: Poseidon(domain, requestId, blindedQuery.x, blindedQuery.y).
- Signed with holder BabyJubJub private key.
- Signature values included in auth payload:
  - `holder_sig_r8x`
  - `holder_sig_r8y`
  - `holder_sig_s`

### D. Live OPRF transcript fetch

- Client calls OPRF nodes (`initSessions`/`finishSessions`) via `@taceo/oprf-client`.
- Client verifies DLOG equality proof locally.
- Client unblinds and finalizes OPRF output using `@taceo/oprf-core`.
- Transcript values are normalized into BN254 field elements.

### E. Combined enrollment proof generation

- Circuit artifact: `/circuits/vc_oprf_enrollment_proof.json`.
- Inputs include VC constraints + OPRF transcript values.
- Output package:
  - raw proof bytes encoded as `0x...`
  - 10 public signals encoded as `bytes32` hex.

### F. Progress reporting

UI progress messages currently include phases such as:

- validating config
- fetching transcript
- generating blinded-query auth proof
- opening/finishing OPRF sessions
- generating enrollment proof
- finalizing package

Primary UI: `src/client/src/components/ZKProofSection.tsx`

## 3) OPRF Auth Payload Shape (Example)

Illustrative JSON payload sent to OPRF nodes under `vc-ownership` auth:

```json
{
  "api_key": "test",
  "public_inputs": [12, 44, 0, 0, 199, 18],
  "proof": [33, 144, 27, 5, 87, 250],
  "holder_sig_r8x": "17384723984723984723",
  "holder_sig_r8y": "998877665544332211",
  "holder_sig_s": "121212121212121212"
}
```

Notes:

- `public_inputs` is byte-level data (4 * 32 bytes total expected for the auth proof public outputs).
- `proof` is byte-level proof payload.
- Holder signature is decimal-string encoded field/scalar values.

## 4) Auth-Node Enforcement

Primary implementation: `src/oprf-testnet/oprf-testnet-authentication/src/vc_ownership.rs`

The server enforces:

1. **Strict payload shape**
   - `public_inputs.len() == 4 * 32`
   - `proof` non-empty
2. **API key validation**
   - validated via Unkey flow in parallel.
3. **Blinded-query auth proof verification**
   - invokes Node verifier bridge script:
     - `src/client/scripts/verify-vc-ownership-auth.mjs`
   - verifier tries LE/BE decoding and accepts only cryptographically valid proof.
4. **Public output parsing (LE) and request binding**
   - server parses blinded query + holder pubkey fields from little-endian public inputs.
   - server enforces `proof.blinded_query == request.blinded_query`.
5. **Holder request signature verification**
   - verifies signature over `(request_id, blinded_query.x, blinded_query.y)` with holder pubkey from proof outputs.
6. **OPRF key binding**
   - successful auth returns module-specific key id (`vc-ownership` module).

If these checks fail, authentication returns `ProofInvalid` (`4610`).

## 5) On-Chain Enforcement

Primary implementation: `src/smart-contracts/src/IdentityRegistry.sol`

`enroll(bytes proof, bytes32[] publicSignals)` enforces:

1. **Signal length**
   - exactly 10 public signals.
2. **Field bounds**
   - each signal `< SNARK_SCALAR_FIELD`.
3. **OPRF metadata validity**
   - `oprfKeyId != 0`, `oprfEpoch != 0`.
   - `oprfKeyId == 3` (vc-ownership binding).
4. **Trusted OPRF public key anchoring**
   - `oprfPkX/oprfPkY` in proof public signals must match contract-managed trusted key.
5. **Verifier success**
   - catches verifier errors and reverts `InvalidProof`.
6. **Business invariants**
  - nullifier not already enrolled,
  - `validUntil` not expired,
  - issuer is in trusted issuer set.

On success:

- stores record in `identitiesByNullifier`.
- emits `IdentityEnrolled` with key metadata.

## 5b) Revocation Flow

Primary implementation: `src/smart-contracts/src/IdentityRegistry.sol`

`revoke(bytes proof, bytes32[] publicSignals, uint256 challengeBlockNumber)` enforces:

1. `publicSignals.length == 4` and all values are field-bounded.
2. `challengeBlockNumber` is recent (`<= 10` blocks old) and valid.
3. `challengeBlockHash` in proof signals matches `blockhash(challengeBlockNumber) % field_modulus`.
4. Identity for `nullifier` exists.
5. Holder pubkey in proof signals matches holder pubkey stored for that nullifier.
6. Revocation verifier accepts the proof.

On success:

- deletes `identitiesByNullifier[nullifier]`.
- emits `IdentityRevoked(nullifier, challengeBlockNumber)`.

## 6) Public Signal Layout (Canonical)

Order expected by contract and generated by circuit:

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

## 7) Enrollment Call Example

Illustrative JS/TS call:

```ts
await writeContract({
  address: identityRegistry,
  abi: identityRegistryAbi,
  functionName: "enroll",
  args: [proofPackage.proof, proofPackage.publicSignals],
});
```

Where:

- `proofPackage.proof` is `0x...` bytes.
- `proofPackage.publicSignals` is `bytes32[10]` in canonical order.

## 8) Common Failure Modes

- `ProofInvalid (4610)` during OPRF auth:
  - malformed auth payload shape,
  - invalid VC ownership proof,
  - invalid holder request signature,
  - public input decoding mismatch.
- `InvalidProof()` on-chain:
  - verifier/proof mismatch,
  - wrong signal ordering/encoding,
  - generated proof not matching deployed verifier key.
- `IssuerNotTrusted()`:
  - issuer key not registered on current contract.
- `UntrustedOprfPublicKey()`:
  - registry trusted OPRF key does not match live node key used during package generation.
  - fix by updating trusted key via owner call or by deploying with dynamically fetched key.
- `IdentityExpired()`:
  - `validUntil` already in the past.
- `IdentityAlreadyExists()`:
  - nullifier already enrolled.

## 9) Security Intent Summary

- VC validity is enforced in-circuit (issuer signature + structure checks).
- OPRF transcript is bound to an authenticated VC holder.
- OPRF auth proves the blinded query is derived from a private VC-derived `hashID` without exposing `hashID` to nodes.
- Holder must prove live control of holder key for each OPRF request.
- Final enrollment proof binds VC-derived identity and OPRF nullifier in one proof.
- Contract only accepts trusted issuers and fixed OPRF key id for this module.
