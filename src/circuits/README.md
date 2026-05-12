# Circuits

This folder contains:

- `vc_blinded_query_auth_proof`: proves that a VC holder authorized a specific blinded OPRF query and request id.
- `vc_oprf_enrollment_proof`: proves VC validity, holder-wallet binding, and a verified OPRF transcript for on-chain enrollment.

## Enrollment Public Signals

`vc_oprf_enrollment_proof` exposes seven public signals, in this order:

1. `oprfPkX`
2. `oprfPkY`
3. `validUntil`
4. `issuerPubKeyX`
5. `issuerPubKeyY`
6. `walletAddress`
7. `nullifier`

The Solidity registry expects this exact layout.

## Build

```bash
cd src/circuits/vc_blinded_query_auth_proof
nargo compile --skip-underconstrained-check
bb write_vk --scheme ultra_honk -b ./target/vc_blinded_query_auth_proof.json -o ./target/vc_blinded_query_auth_proof.vk.bin

cd ../vc_oprf_enrollment_proof
nargo compile --skip-underconstrained-check
bb write_vk --scheme ultra_honk -b ./target/vc_oprf_enrollment_proof.json -o ./target/vk
bb contract --scheme ultra_honk -k ./target/vk -b ./target/vc_oprf_enrollment_proof.json -o ./target/VcOprfEnrollmentUltraVerifier.sol
```

## Copy Artifacts

Run from the repository root after rebuilding:

```bash
cp src/circuits/vc_blinded_query_auth_proof/target/vc_blinded_query_auth_proof.json src/client/public/circuits/vc_blinded_query_auth_proof.json
cp src/circuits/vc_blinded_query_auth_proof/target/vc_blinded_query_auth_proof.json src/oprf-testnet/oprf-testnet-authentication/vc_blinded_query_auth_proof.json
cp src/circuits/vc_blinded_query_auth_proof/target/vc_blinded_query_auth_proof.vk.bin src/oprf-testnet/oprf-testnet-authentication/vc_blinded_query_auth_proof.vk.bin

cp src/circuits/vc_oprf_enrollment_proof/target/vc_oprf_enrollment_proof.json src/client/public/circuits/vc_oprf_enrollment_proof.json
cp src/circuits/vc_oprf_enrollment_proof/target/VcOprfEnrollmentUltraVerifier.sol src/smart-contracts/src/VcOprfEnrollmentUltraVerifier.sol
```

## Used By

- Client app: compiled circuit JSON in `src/client/public/circuits/`
- OPRF auth module: auth circuit JSON and verification key in `src/oprf-testnet/oprf-testnet-authentication/`
- Smart contracts: generated enrollment verifier in `src/smart-contracts/src/`
