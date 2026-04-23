# Circuits

This folder contains:

- `vc_blinded_query_auth_proof`
- `vc_oprf_enrollment_proof`

## Build

```bash
cd src/circuits/vc_blinded_query_auth_proof
nargo compile --skip-underconstrained-check
/Users/adamvozda/.bb/bb write_vk --scheme ultra_honk -b ./target/vc_blinded_query_auth_proof.json -o ./target/vc_blinded_query_auth_proof.vk.bin

cd /Users/adamvozda/Documents/Proof-of-Uniqueness/src/circuits/vc_oprf_enrollment_proof
nargo compile --skip-underconstrained-check
/Users/adamvozda/.bb/bb write_vk --scheme ultra_honk -b ./target/vc_oprf_enrollment_proof.json -o ./target/vk
/Users/adamvozda/.bb/bb contract --scheme ultra_honk -k ./target/vk -b ./target/vc_oprf_enrollment_proof.json -o ./target/VcOprfEnrollmentUltraVerifier.sol
```

## Copy Artifacts

```bash
cp src/circuits/vc_blinded_query_auth_proof/target/vc_blinded_query_auth_proof.json src/client/public/circuits/vc_blinded_query_auth_proof.json
cp src/circuits/vc_blinded_query_auth_proof/target/vc_blinded_query_auth_proof.json src/oprf-testnet/oprf-testnet-authentication/vc_blinded_query_auth_proof.json
cp src/circuits/vc_blinded_query_auth_proof/target/vc_blinded_query_auth_proof.vk.bin src/oprf-testnet/oprf-testnet-authentication/vc_blinded_query_auth_proof.vk.bin

cp src/circuits/vc_oprf_enrollment_proof/target/vc_oprf_enrollment_proof.json src/client/public/circuits/vc_oprf_enrollment_proof.json
cp src/circuits/vc_oprf_enrollment_proof/target/VcOprfEnrollmentUltraVerifier.sol src/smart-contracts/src/VcOprfEnrollmentUltraVerifier.sol
```

## Used By

- Client app: `src/client/public/circuits/`
- OPRF auth module: `src/oprf-testnet/oprf-testnet-authentication/`
- Smart contracts: `src/smart-contracts/src/`
