// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {HashIdClaimVerifier} from "./HashIdClaimVerifier.sol";
import {SMTNonMembershipVerifier} from "./SMTNonMembershipVerifier.sol";

contract IdentityVerification is HashIdClaimVerifier, SMTNonMembershipVerifier {
    uint256 public root;

    event HashIDClaim(
        uint[2] _pA,
        uint[2][2] _pB,
        uint[2] _pC,
        uint[1] _pubSignals
    );

    event HashIDInserted(uint256 hashID, uint256 newRoot);

    constructor(
        uint256 _root
    ) HashIdClaimVerifier() SMTNonMembershipVerifier() {
        root = _root;
    }

    function verify(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[1] calldata _pubSignals
    ) public {
        bytes memory data = abi.encodeWithSignature(
            "verifyHashIdProof(uint256[2],uint256[2][2],uint256[2],uint256[1])",
            _pA,
            _pB,
            _pC,
            _pubSignals
        );

        (bool success, bytes memory result) = address(this).staticcall(data);

        require(success && result.length == 32, "Verification call failed");

        bool isValid = abi.decode(result, (bool));
        require(isValid, "Invalid ZK proof");

        emit HashIDClaim(_pA, _pB, _pC, _pubSignals);
    }

    function insertHashID(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[1] calldata _pubSignals,
        uint[2] calldata _pA_smt,
        uint[2][2] calldata _pB_smt,
        uint[2] calldata _pC_smt,
        uint[3] calldata _pubSignals_smt
    ) public {
        // check that hashID of both proofs are the same
        require(_pubSignals[0] == _pubSignals_smt[1], "HashID mismatch");
        require(root == _pubSignals_smt[2], "Old root mismatch");

        bytes memory data = abi.encodeWithSignature(
            "verifyHashIdProof(uint256[2],uint256[2][2],uint256[2],uint256[1])",
            _pA,
            _pB,
            _pC,
            _pubSignals
        );

        (bool success, bytes memory result) = address(this).staticcall(data);
        require(
            success && result.length == 32,
            "HashID verification call failed"
        );
        bool isValid = abi.decode(result, (bool));
        require(isValid, "Invalid HashID proof");

        bytes memory data_smt = abi.encodeWithSignature(
            "verifySMTProof(uint256[2],uint256[2][2],uint256[2],uint256[3])",
            _pA_smt,
            _pB_smt,
            _pC_smt,
            _pubSignals_smt
        );

        (bool success_smt, bytes memory result_smt) = address(this).staticcall(
            data_smt
        );

        require(
            success_smt && result_smt.length == 32,
            "SMT verification call failed"
        );

        bool isValid_smt = abi.decode(result_smt, (bool));
        require(isValid_smt, "Invalid SMT proof");

        uint256 newRoot = _pubSignals_smt[0];
        uint256 hashId = _pubSignals[0];

        root = newRoot;

        emit HashIDInserted(hashId, newRoot);
    }
}
