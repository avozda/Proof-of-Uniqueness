// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {OprfKeyRegistry} from "../../src/OprfKeyRegistry.sol";

contract UpgradeOprfKeyRegistryScript is Script {
    OprfKeyRegistry public oprfKeyRegistryProxy;
    address public oprfKeyRegistryNewImpl;

    function setUp() public {
        oprfKeyRegistryProxy = OprfKeyRegistry(vm.envAddress("OPRF_KEY_REGISTRY_PROXY"));
        oprfKeyRegistryNewImpl = vm.envAddress("OPRF_KEY_REGISTRY_NEW_IMPL");
    }

    function run() public {
        console.log(
            "Updating OPRF key-gen implementation from proxy",
            address(oprfKeyRegistryProxy),
            " to ",
            oprfKeyRegistryNewImpl
        );
        vm.startBroadcast();
        OprfKeyRegistry(address(oprfKeyRegistryProxy)).upgradeToAndCall(oprfKeyRegistryNewImpl, "");
        vm.stopBroadcast();
    }
}
