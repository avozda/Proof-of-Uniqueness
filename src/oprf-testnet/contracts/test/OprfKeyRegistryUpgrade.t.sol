// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {BabyJubJub} from "@taceo/babyjubjub/BabyJubJub.sol";
import {Contributions} from "./Contributions.t.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OprfKeyGen} from "../src/OprfKeyGen.sol";
import {OprfKeyRegistry} from "../src/OprfKeyRegistry.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Test} from "forge-std/Test.sol";
import {Verifier as VerifierKeyGen13} from "../src/VerifierKeyGen13.sol";

/**
 *
 *
 * @title OprfKeyRegistryV2Mock
 *
 *
 * @notice Mock V2 implementation for testing upgrades
 *
 *
 */
contract OprfKeyRegistryV2Mock is OprfKeyRegistry {
    // Add a new state variable to test storage layout preservation

    uint256 public newFeature;

    function version() public pure returns (string memory) {
        return "V2";
    }

    function setNewFeature(uint256 _value) public {
        newFeature = _value;
    }
}

contract OprfKeyRegistryUpgradeTest is Test {
    using BabyJubJub for BabyJubJub.Affine;

    uint256 public constant THRESHOLD = 2;
    uint256 public constant MAX_PEERS = 3;

    OprfKeyRegistry public oprfKeyRegistry;
    VerifierKeyGen13 public verifierKeyGen;
    ERC1967Proxy public proxy;

    address alice = address(0x1);
    address bob = address(0x2);
    address carol = address(0x3);
    address taceoAdmin = address(0x4);
    address initOwner = 0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496; // the default addr of this test contract

    function setUp() public {
        verifierKeyGen = new VerifierKeyGen13();
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, initOwner, taceoAdmin, verifierKeyGen, THRESHOLD, MAX_PEERS
        );
        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        oprfKeyRegistry = OprfKeyRegistry(address(proxy));

        // register participants for runs later
        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = carol;
        oprfKeyRegistry.registerOprfPeers(peerAddresses);
    }

    function testOwnershipTransfer() public {
        assertEq(oprfKeyRegistry.owner(), initOwner);
        vm.expectEmit(true, true, true, true);
        emit Ownable2StepUpgradeable.OwnershipTransferStarted(initOwner, taceoAdmin);
        oprfKeyRegistry.transferOwnership(taceoAdmin);
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit OwnableUpgradeable.OwnershipTransferred(initOwner, taceoAdmin);
        oprfKeyRegistry.acceptOwnership();
        vm.stopPrank();
        assertEq(oprfKeyRegistry.owner(), taceoAdmin);
    }

    function testUpgrade() public {
        // start key generation process for oprfKeyId 42
        // see testE2E in OprfKeyRegistry.t.sol for the full process
        uint160 oprfKeyId = 42;
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenRound1(oprfKeyId, THRESHOLD);
        oprfKeyRegistry.initKeyGen(oprfKeyId);
        vm.stopPrank();

        // do round 1 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(oprfKeyId, Contributions.bobKeyGenRound1Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(oprfKeyId, Contributions.aliceKeyGenRound1Contribution());
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenRound2(oprfKeyId, 0);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 2, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(oprfKeyId, Contributions.carolKeyGenRound1Contribution());
        vm.stopPrank();

        // do round 2 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.bobKeyGenRound2Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.aliceKeyGenRound2Contribution());
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenRound3(oprfKeyId);
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 2, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.carolKeyGenRound2Contribution());
        vm.stopPrank();

        // do round 3 contributions
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 3, 0);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 3, 0);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenFinalize(oprfKeyId, 0);
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 2, 3, 0);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();

        // check that the computed nullifier is correct
        BabyJubJub.Affine memory oprfKey = oprfKeyRegistry.getOprfPublicKey(oprfKeyId);
        assertEq(oprfKey.x, Contributions.SHOULD_OPRF_PUBLIC_KEY_X);
        assertEq(oprfKey.y, Contributions.SHOULD_OPRF_PUBLIC_KEY_Y);

        // Now perform upgrade
        OprfKeyRegistryV2Mock implementationV2 = new OprfKeyRegistryV2Mock();
        // upgrade as owner
        OprfKeyRegistry(address(proxy)).upgradeToAndCall(address(implementationV2), "");
        // Wrap proxy with V2 interface
        OprfKeyRegistryV2Mock oprfKeyRegistryV2 = OprfKeyRegistryV2Mock(address(proxy));

        // Verify storage was preserved
        BabyJubJub.Affine memory oprfKeyV2 = oprfKeyRegistryV2.getOprfPublicKey(oprfKeyId);
        assertEq(oprfKeyV2.x, Contributions.SHOULD_OPRF_PUBLIC_KEY_X);
        assertEq(oprfKeyV2.y, Contributions.SHOULD_OPRF_PUBLIC_KEY_Y);

        // Verify new functionality works
        assertEq(oprfKeyRegistryV2.version(), "V2");
        oprfKeyRegistryV2.setNewFeature(42);
        assertEq(oprfKeyRegistryV2.newFeature(), 42);

        // Verify old functionality still works
        uint160 newOprfKeyId = 43;
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenRound1(newOprfKeyId, 2);
        oprfKeyRegistry.initKeyGen(newOprfKeyId);
        vm.stopPrank();

        // do round 1 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(newOprfKeyId, 1, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(newOprfKeyId, Contributions.bobKeyGenRound1Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(newOprfKeyId, 0, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(newOprfKeyId, Contributions.aliceKeyGenRound1Contribution());
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenRound2(newOprfKeyId, 0);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(newOprfKeyId, 2, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(newOprfKeyId, Contributions.carolKeyGenRound1Contribution());
        vm.stopPrank();

        // do round 2 contributions
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(newOprfKeyId, 1, 2, 0);
        oprfKeyRegistry.addRound2Contribution(newOprfKeyId, Contributions.bobKeyGenRound2Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(newOprfKeyId, 0, 2, 0);
        oprfKeyRegistry.addRound2Contribution(newOprfKeyId, Contributions.aliceKeyGenRound2Contribution());
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenRound3(newOprfKeyId);
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(newOprfKeyId, 2, 2, 0);
        oprfKeyRegistry.addRound2Contribution(newOprfKeyId, Contributions.carolKeyGenRound2Contribution());
        vm.stopPrank();

        // do round 3 contributions
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(newOprfKeyId, 0, 3, 0);
        oprfKeyRegistry.addRound3Contribution(newOprfKeyId);
        vm.stopPrank();

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(newOprfKeyId, 1, 3, 0);
        oprfKeyRegistry.addRound3Contribution(newOprfKeyId);
        vm.stopPrank();

        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenFinalize(newOprfKeyId, 0);
        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(newOprfKeyId, 2, 3, 0);
        oprfKeyRegistry.addRound3Contribution(newOprfKeyId);
        vm.stopPrank();

        // check that the computed nullifier is correct
        BabyJubJub.Affine memory oprfKeyNew = oprfKeyRegistry.getOprfPublicKey(newOprfKeyId);
        assertEq(oprfKeyNew.x, Contributions.SHOULD_OPRF_PUBLIC_KEY_X);
        assertEq(oprfKeyNew.y, Contributions.SHOULD_OPRF_PUBLIC_KEY_Y);
    }
}
