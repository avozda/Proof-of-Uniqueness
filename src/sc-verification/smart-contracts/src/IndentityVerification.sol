// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Groth16Verifier} from "./verifier.sol";

contract IdentityVerification is Groth16Verifier {
    mapping(uint => bool) public hashIDs;
    constructor() Groth16Verifier() {}

    function verify(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[1] calldata _pubSignals
    ) public returns (bool) {
        uint hashID = _pubSignals[0];
        require(!hashIDs[hashID], "Identity already verified");

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

        hashIDs[hashID] = true;

        return true;
    }
}
