// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BabyJubJub} from "@taceo/babyjubjub/BabyJubJub.sol";

/// @title Types Library
/// @notice Defines common structs, enums, and constants for the project
library OprfKeyGen {
    // The roles of the nodes during key-gen. NOT_READY is the default value
    enum KeyGenRole {
        NOT_READY,
        PRODUCER,
        CONSUMER
    }

    enum Round {
        NOT_STARTED,
        ONE,
        TWO,
        THREE,
        // currently not used other than preventing that this key-gen is used for anything else
        STUCK,
        DELETED
    }

    struct OprfPeer {
        bool isParticipant;
        uint16 partyId;
    }

    struct RegisteredOprfPublicKey {
        BabyJubJub.Affine key;
        uint32 epoch;
    }

    struct Round1Contribution {
        // the commitment to the secret
        BabyJubJub.Affine commShare;
        // hash of the polynomial created by participant
        uint256 commCoeffs;
        // ephemeral public key for this round
        BabyJubJub.Affine ephPubKey;
    }

    struct Round2Contribution {
        uint256[4] compressedProof;
        // Hash of the polynomial created by participant
        SecretGenCiphertext[] ciphers;
    }

    struct SecretGenCiphertext {
        uint256 nonce;
        uint256 cipher;
        BabyJubJub.Affine commitment;
    }

    struct OprfKeyGenState {
        mapping(address => KeyGenRole) nodeRoles;
        uint256[] lagrangeCoeffs;
        Round1Contribution[] round1;
        SecretGenCiphertext[][] round2;
        BabyJubJub.Affine[] shareCommitments;
        BabyJubJub.Affine[] prevShareCommitments;
        BabyJubJub.Affine keyAggregate;
        uint32 numProducers;
        uint32 generatedEpoch;
        bool[] round2Done;
        bool[] round3Done;
        Round currentRound;
    }

    // Event that will be emitted during transaction of key-gens. This should signal the MPC-nodes that their transaction was successfully registered.
    event KeyGenConfirmation(uint160 indexed oprfKeyId, uint16 indexed partyId, uint8 round, uint32 epoch);
    // events for key-gen
    event SecretGenRound1(uint160 indexed oprfKeyId, uint256 threshold);
    event SecretGenRound2(uint160 indexed oprfKeyId, uint32 indexed epoch);
    event SecretGenRound3(uint160 indexed oprfKeyId);
    event SecretGenFinalize(uint160 indexed oprfKeyId, uint32 indexed epoch);
    // events for reshare
    event ReshareRound1(uint160 indexed oprfKeyId, uint256 threshold, uint32 indexed epoch);
    event ReshareRound3(uint160 indexed oprfKeyId, uint256[] lagrange, uint32 indexed epoch);
    // event to delete created key
    event KeyDeletion(uint160 indexed oprfKeyId);
    // abort currently running key-gen
    event KeyGenAbort(uint160 indexed oprfKeyId);
    // admin events
    event KeyGenAdminRevoked(address indexed admin);
    event KeyGenAdminRegistered(address indexed admin);
    event NotEnoughProducers(uint160 indexed oprfKeyId);
    event VerifierContractChanged(address indexed oldContract, address indexed newContract);
    // peer events
    event OprfPeerChanged(uint16 indexed partyId, address indexed oldPeer, address indexed newPeer);

    /// @notice Initializes the internal state for a new OPRF key-generation process.
    ///
    /// @dev Resets all round-specific data structures and prepares the state for Round 1. Allocates fresh storage for all rounds based on the provided numPeers.
    ///
    /// @param st The key-generation state to initialize.
    /// @param numPeers The total number of participating peers.
    function initKeyGen(OprfKeyGenState storage st, uint256 numPeers) internal {
        st.currentRound = Round.ONE;
        st.generatedEpoch = 0;
        st.round1 = new Round1Contribution[](numPeers);
        st.round2 = new SecretGenCiphertext[][](numPeers);
        for (uint256 i = 0; i < numPeers; i++) {
            st.round2[i] = new SecretGenCiphertext[](numPeers);
        }
        st.shareCommitments = new BabyJubJub.Affine[](numPeers);
        st.prevShareCommitments = new BabyJubJub.Affine[](numPeers);
        st.round2Done = new bool[](numPeers);
        st.round3Done = new bool[](numPeers);
    }

    /// @notice Initializes the internal state for an OPRF reshare process.
    ///
    /// @dev Resets round-specific data while preserving the previous share
    /// commitments for input verification. Additionally, clears lagrange coefficients which we didn't do in key-gen because we only set them during reshares.
    ///
    /// @param st The key-generation state to initialize.
    /// @param numPeers The total number of participating peers.
    /// @param generatedEpoch The new epoch to assign to the reshared key.
    function initReshare(OprfKeyGenState storage st, uint256 numPeers, uint32 generatedEpoch) internal {
        delete st.lagrangeCoeffs;

        st.currentRound = Round.ONE;
        st.generatedEpoch = generatedEpoch;
        st.round1 = new Round1Contribution[](numPeers);
        st.round2 = new SecretGenCiphertext[][](numPeers);
        for (uint256 i = 0; i < numPeers; i++) {
            st.round2[i] = new SecretGenCiphertext[](numPeers);
        }
        st.shareCommitments = new BabyJubJub.Affine[](numPeers);
        st.round2Done = new bool[](numPeers);
        st.round3Done = new bool[](numPeers);
    }

    /// @notice Resets the key-generation state to allow a fresh initialization.
    ///
    /// @dev Clears all round-specific data and node roles, but keeps the key ID
    /// reusable. Sets the current round to `NOT_STARTED`.
    ///
    /// @param st The key-generation state to reset.
    /// @param numPeers The total number of participating peers.
    /// @param peerAddresses The addresses of the participating peers.
    function reset(OprfKeyGenState storage st, uint256 numPeers, address[] memory peerAddresses) internal {
        _reset(st, numPeers, peerAddresses);
        st.currentRound = Round.NOT_STARTED;
    }

    /// @notice Deletes the key-generation state permanently.
    ///
    /// @dev Clears all associated state and marks the key ID as deleted to prevent
    /// reuse. Sets the current round to `DELETED`.
    ///
    /// @param st The key-generation state to delete.
    /// @param numPeers The total number of participating peers.
    /// @param peerAddresses The addresses of the participating peers.
    function deleteSt(OprfKeyGenState storage st, uint256 numPeers, address[] memory peerAddresses) internal {
        _reset(st, numPeers, peerAddresses);
        delete st.lagrangeCoeffs;
        delete st.prevShareCommitments;
        st.currentRound = Round.DELETED;
    }

    /// @notice Internal helper to clear round-specific key-generation state.
    ///
    /// @dev Deletes all transient protocol data and node role assignments.
    /// Does not modify the `currentRound` field.
    ///
    /// @param st The key-generation state to clear.
    /// @param numPeers The total number of participating peers.
    /// @param peerAddresses The addresses of the participating peers.
    function _reset(OprfKeyGenState storage st, uint256 numPeers, address[] memory peerAddresses) private {
        delete st.keyAggregate;
        delete st.round2Done;
        delete st.round3Done;
        delete st.round1;
        delete st.round2;
        delete st.numProducers;
        delete st.generatedEpoch;
        for (uint256 i = 0; i < numPeers; i++) {
            delete st.nodeRoles[peerAddresses[i]];
        }
        delete st.shareCommitments;
    }
}
