// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Groth16Verifier} from "./hashIdClaim_verifier.sol";

contract IdentityVerification is Groth16Verifier {
    event HashIDClaim(
        uint[2] _pA,
        uint[2][2] _pB,
        uint[2] _pC,
        uint[1] _pubSignals
    );

    constructor() Groth16Verifier() {}

    function verify(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[1] calldata _pubSignals
    ) public {
        bytes memory data = abi.encodeWithSignature(
            "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[1])",
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
}
