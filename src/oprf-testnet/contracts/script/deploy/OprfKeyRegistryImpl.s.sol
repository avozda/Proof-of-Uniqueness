// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {OprfKeyRegistry} from "../../src/OprfKeyRegistry.sol";

contract DeployOprfKeyRegistryImplScript is Script {
    OprfKeyRegistry public oprfKeyRegistry;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();

        vm.stopBroadcast();
        console.log("OprfKeyRegistry implementation deployed to:", address(implementation));
    }
}
