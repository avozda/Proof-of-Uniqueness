// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {IdentityVerification} from "../src/IndentityVerification.sol";

contract IdentityVerificationScript is Script {
    IdentityVerification public identityVerification;

    function setUp() public {
        identityVerification = new IdentityVerification();
    }

    function run() public {
        vm.startBroadcast();

        identityVerification = new IdentityVerification();

        vm.stopBroadcast();
    }
}
