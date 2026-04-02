# Smart Contracts

Foundry project containing:

- `IdentityRegistry.sol`
- `Groth16Verifier.sol` (enrollment)
- `Groth16RevocationVerifier.sol` (revocation)

## Commands

```bash
forge build
forge test
forge fmt
```

## Deploy

```bash
forge script script/IdentityRegistry.s.sol --rpc-url http://127.0.0.1:8545 --broadcast
```

## Notes

- `IdentityRegistry` expects two verifier addresses in constructor:
  - enrollment verifier
  - revocation verifier
- If circuits/public signals change, regenerate verifiers and redeploy.
