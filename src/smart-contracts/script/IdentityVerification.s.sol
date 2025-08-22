// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {IdentityVerification} from "../src/IndentityVerification.sol";

contract IdentityVerificationScript is Script {
    IdentityVerification public identityVerification;

    // SMT root hash from the Rust prover (empty tree with depth 254)
    uint256 constant INITIAL_SMT_ROOT = 0;

    function setUp() public {
        identityVerification = new IdentityVerification(INITIAL_SMT_ROOT);
    }

    function run() public {
        vm.startBroadcast();

        identityVerification = new IdentityVerification(INITIAL_SMT_ROOT);

        console.log(
            "IdentityVerification deployed at:",
            address(identityVerification)
        );
        console.log("Initial SMT root:", INITIAL_SMT_ROOT);

        vm.stopBroadcast();
    }
}
