## Key Registry Contract for TACEO:OPRF

This repository is part of the [TACEO:OPRF](https://github.com/TaceoLabs/oprf-service) project and holds the smart contracts that act as an on-chain registry for OPRF Node parties and the generated OPRF keys.

The contract provides functionality to initiate a new key generation protocol run, with the contract itself being used as a public message board for the parties' messages during the protocol.
In addition it can also be used to trigger a key reshare procedure, which is similar to the key generation procedure, but refreshes the parties' key shares, keeping the underlying OPRF key the same.
