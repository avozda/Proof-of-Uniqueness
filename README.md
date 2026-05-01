# Proof of Uniqueness

Privacy-preserving identity verification based on zkSNARKs using:

- Noir + Barretenberg proofs
- BabyJubJub EdDSA holder and issuer keys
- threshold OPRF nodes for enrollment
- EIP-712 wallet signatures for on-chain enrollment and revocation

This is a research prototype for testing the proposed design. It is not production ready code.

## Repo layout

```text
src/
├── circuits/          Noir circuits used by the client and OPRF auth module
├── client/            React app
├── oprf-testnet/      Local OPRF node stack and auth module
└── smart-contracts/   Foundry project with IdentityRegistry
```

## Prerequisites

You need the usual local tooling for this repo:

- `git`
- `cargo`
- `docker`
- `foundry` (`forge`, `anvil`)
- `node` + `npm`
- `nargo` / `bb` (only if you want to rebuild circuit artifacts)

## Setup

### Quick setup with Make

First initialize the submodules:

This repo depends on nested code inside submodules, including vendored Noir dependencies used by the circuits.

```bash
git submodule update --init --recursive
```

Then use the root Makefile:

Start the TACEO:OPRF testnet:

```bash
make oprf-testnet
```

This also starts a local Anvil chain. If you only need the blockchain network without the OPRF stack, run:

```bash
make network
```

In another terminal, deploy the smart contract using the live OPRF public key:

```bash
make deploy
```

Then start the web client:

```bash
make web
```

Open [http://localhost:5173](http://localhost:5173).

In the local client, issuer registration is sent with the default Anvil owner private key. The connected MetaMask wallet is still used for enrollment and revocation.

### Manual setup

#### 1. Init submodules

```bash
git submodule update --init --recursive
```

#### 2. Start the local OPRF stack

The client expects three local OPRF nodes at:

- `http://127.0.0.1:10000`
- `http://127.0.0.1:10001`
- `http://127.0.0.1:10002`

Bring them up with:

```bash
cd src/oprf-testnet
chmod +x local-setup.sh
./local-setup.sh setup
```

What this script does:

- builds the OPRF workspace
- starts Docker services for the OPRF databases and keygen nodes
- starts three local OPRF nodes
- initializes OPRF keys so `/oprf_pub/*` is available on the nodes

Keep this terminal running.

This script also starts a local Anvil chain. If you only need the blockchain network without the OPRF stack, run Anvil manually:

```bash
anvil --code-size-limit 50000
```

#### 3. Deploy the smart contract

Recommended local deployment uses the live OPRF public key from the running node:

```bash
cd src/smart-contracts
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
./script/deploy-identity-registry-dynamic-oprf.sh
```

After deployment, update the client contract address in:

- [src/client/src/lib/wagmi.ts](./src/client/src/lib/wagmi.ts)

If you redeploy `IdentityRegistry`, the client must point to the new address.

#### 4. Run the client

In another terminal:

```bash
cd src/client
npm install
npm run dev
```
