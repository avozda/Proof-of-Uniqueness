# VC + OPRF Data Flow

This is the current flow used by the repo.

## 1. Generate the auth proof

The client:

1. Encodes the VC fields into field elements.
2. Rebuilds the labeled Merkle leaves used by the circuits.
3. Verifies the issuer signature inside the auth circuit.
4. Uses the holder key to sign the OPRF auth message inside the auth circuit.
5. Outputs only three public values from the auth proof:
   - `request_id_field`
   - `blinded_query_x`
   - `blinded_query_y`

Important detail: the holder public key is not exposed by the auth proof.

Primary files:

- [src/circuits/vc_blinded_query_auth_proof/src/main.nr](/Users/adamvozda/Documents/Proof-of-Uniqueness/src/circuits/vc_blinded_query_auth_proof/src/main.nr)
- [src/client/src/lib/oprfEnrollment.ts](/Users/adamvozda/Documents/Proof-of-Uniqueness/src/client/src/lib/oprfEnrollment.ts)

## 2. Authenticate to the OPRF nodes

The client sends the auth proof to the `vc-ownership` auth module.

The Rust auth module checks:

- proof shape,
- proof validity,
- `request_id_field` matches the request id,
- blinded query from the proof matches the blinded query in the request,
- API key is valid.

Primary file:

- [src/oprf-testnet/oprf-testnet-authentication/src/vc_ownership.rs](/Users/adamvozda/Documents/Proof-of-Uniqueness/src/oprf-testnet/oprf-testnet-authentication/src/vc_ownership.rs)

## 3. Fetch the live OPRF transcript

After auth succeeds, the client:

1. opens sessions with the OPRF nodes,
2. collects threshold responses,
3. verifies the DLEQ proof,
4. unblinds the response,
5. derives the final OPRF output.

That transcript becomes a private input to the enrollment circuit.

## 4. Generate the enrollment proof

The enrollment circuit proves:

- the VC fields are internally consistent,
- the issuer signature is valid,
- the holder key signed the private `hash_id`,
- the OPRF transcript is valid for that same private `hash_id`.

The enrollment proof exposes six public signals:

1. `oprfPkX`
2. `oprfPkY`
3. `validUntil`
4. `issuerPubKeyX`
5. `issuerPubKeyY`
6. `nullifier`

Primary file:

- [src/circuits/vc_oprf_enrollment_proof/src/main.nr](/Users/adamvozda/Documents/Proof-of-Uniqueness/src/circuits/vc_oprf_enrollment_proof/src/main.nr)

## 5. Enroll on-chain

The client asks the connected wallet to sign an EIP-712 enrollment authorization, then calls:

```solidity
enroll(proof, publicSignals, walletAddress, enrollmentSignature)
```

The contract checks:

- public signal length is exactly 6,
- each public signal is inside the SNARK field,
- the proof is tied to the currently trusted OPRF public key,
- the wallet signed the exact enrollment payload,
- the proof verifies,
- the nullifier is new,
- the VC is not expired,
- the issuer public key is trusted.

On success it stores:

- `validUntil`
- `issuerPubKeyX`
- `issuerPubKeyY`
- `walletAddress`
- `exists`

Primary file:

- [src/smart-contracts/src/IdentityRegistry.sol](/Users/adamvozda/Documents/Proof-of-Uniqueness/src/smart-contracts/src/IdentityRegistry.sol)

## 6. Revoke on-chain

Revocation does not use zk anymore.

The wallet signs:

```solidity
Revoke(uint256 nullifier,uint256 deadline)
```

and the contract checks that signature against the stored `walletAddress` for the identity record.

## 7. What is private vs public

Private to the circuits:

- VC field values,
- holder key witness,
- issuer signature witness,
- holder signature witness,
- OPRF transcript witness,
- `hash_id`

Public in the auth proof:

- request id field,
- blinded query point

Public in the enrollment proof:

- trusted OPRF public key,
- expiry,
- issuer public key,
- nullifier

Public on-chain:

- the stored identity record,
- the bound wallet address,
- issuer trust state,
- trusted OPRF public key.
