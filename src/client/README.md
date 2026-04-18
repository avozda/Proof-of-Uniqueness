# Client

React + TypeScript frontend for:

- VC generation
- OPRF enrollment package generation/submission

## Commands

```bash
npm install
npm run dev
npm run build
```

## Important Paths

- Contract ABI: `src/lib/contractAbi.ts`
- Contract address config: `src/lib/wagmi.ts`
- OPRF flow UI: `src/components/ZKProofSection.tsx`
- OPRF package builder: `src/lib/oprfEnrollment.ts`

## Required Browser Assets

The frontend expects these wasm assets in `public/`:

- `barretenberg.wasm`
- `barretenberg-threads.wasm`
- `acvm_js_bg.wasm`
- `noirc_abi_wasm_bg.wasm`

If missing or replaced by HTML (e.g. 404 fallback page), browser proving fails with a wasm magic-word error.

## Current State

- This app emits a simplified, demo-oriented VC 2.0-like JSON structure (not a full interoperability profile).
- Kept minimum VC shape checks: `@context`, `type` includes `VerifiableCredential`, `issuer.id`, `credentialSubject.id`, and ISO `validFrom`/`validUntil`.
- Full production items like hosted custom JSON-LD contexts, `credentialStatus`, and `credentialSchema` are intentionally out of scope for this mock.
- Old Circom/Groth16 and revocation UI paths are removed from the frontend.
- The frontend is OPRF-enrollment focused and submits `enroll(bytes,bytes32[])`.
- OPRF package generation is strict and live-only: no scaffold fallback path.
- The app uses browser-side Noir + Barretenberg generation with `/circuits/vc_oprf_enrollment_proof.json`.
- Revocation uses browser-side Noir generation with `/circuits/vc_revocation_proof.json` and on-chain challenge block freshness checks.
- VC payload no longer includes `holderBindingSignature`; holder key possession is proven with live signatures during auth/proving.
- OPRF transcript/auth is `vc-ownership` only.
- UI no longer exposes manual package import, transcript input, network config inputs, or strict-mode toggles.
- Contract address is configured from `src/lib/wagmi.ts` and not user-editable in the UI.

## Local Devnet Note

- For strict local end-to-end with on-chain verification, start Anvil with higher contract size limit:
  `anvil --code-size-limit 50000`
  (the generated Honk verifier is larger than the default EIP-170 24KB limit).

No extra package build step is required.
