# Prover Service

This prover service listens for `HashIDClaim` events from the Identity Verification smart contract and automatically generates ZK-SNARK proofs for SMT (Sparse Merkle Tree) verification.

## Functionality

When a `HashIDClaim` event is detected, the prover:

1. **Extracts** the hashID from the event's public signals
2. **Checks** if the hashID has already been processed (to avoid duplicates)
3. **Generates** siblings proof for the current SMT state
4. **Creates** a ZK-SNARK proof using the SMTVerification circuit to prove:
   - The hashID doesn't exist in the current SMT (uniqueness)
   - The new root after insertion
5. **Submits** both the original HashIDClaim proof and the new SMT proof to the contract's `insertHashID` function

## Prerequisites

### System Dependencies

- **Node.js** (v16 or later)
- **snarkjs** - Install globally: `npm install -g snarkjs`

### Rust Dependencies

All Rust dependencies are defined in `Cargo.toml` and include:

- Ethereum/Web3 support (ethers)
- Database storage (rocksdb)
- Cryptographic functions (poseidon-rs)
- ZK-SNARK proof generation libraries

## Circuit Files

The prover expects the following files in the `./zk/` directory:

- `build/SMTVerification_js/SMTVerification.wasm` - Compiled circuit WASM
- `build/SMTVerification_js/generate_witness.js` - Witness generation script
- `SMTVerification_0001.zkey` - Proving key
- `verification_key.json` - Verification key

## Configuration

Update the contract address in `main.rs`:

```rust
let contract_address: Address = "YOUR_CONTRACT_ADDRESS".parse()?;
```

## Running

```bash
cd src/prover
cargo run
```

## How It Works

### SMT Management

- Maintains a persistent Sparse Merkle Tree using RocksDB
- Generates merkle proofs (siblings) for any given hashID
- Updates the tree state after successful insertions

### ZK Proof Generation

- Uses snarkjs via command-line interface to generate proofs
- Creates circuit inputs with hashID, old root, and siblings
- Returns formatted proof components ready for smart contract submission

### Contract Interaction

- Listens for `HashIDClaim` events from the smart contract
- Calls `insertHashID` with both the original proof and the new SMT proof
- Ensures the hashID in both proofs match (as required by the contract)

## Circuit Input Format

The SMTVerification circuit expects:

```json
{
  "hashID": "123...",     // The hashID to verify and insert
  "oldRoot": "456...",    // Current SMT root
  "siblings": ["0", "0", ...] // 254 siblings for merkle proof
}
```

## Circuit Output Format

The circuit produces 3 public signals:

1. `newRoot` - The new SMT root after insertion
2. `verifiedHashID` - The hashID that was verified (should match input)
3. `publicOldRoot` - The old root (should match input)

## Error Handling

The prover includes comprehensive error handling for:

- Missing circuit files
- Failed proof generation
- Contract call failures
- Database errors
- Invalid format conversions

## Security Notes

- This implementation uses `call()` for contract interaction (read-only)
- For production, implement proper transaction signing with a wallet/signer
- Ensure proper access controls for the prover service
- Consider rate limiting for proof generation
