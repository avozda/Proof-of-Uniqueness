// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {BabyJubJub} from "@taceo/babyjubjub/BabyJubJub.sol";
import {Contributions} from "./Contributions.t.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OprfKeyGen} from "../src/OprfKeyGen.sol";
import {OprfKeyRegistry} from "../src/OprfKeyRegistry.sol";
import {Test} from "forge-std/Test.sol";
import {Verifier as VerifierKeyGen13} from "../src/VerifierKeyGen13.sol";

contract OprfKeyRegistryKeyGenTest is Test {
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

    function initKeyGen(uint160 oprfKeyId) internal {
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenRound1(oprfKeyId, THRESHOLD);
        oprfKeyRegistry.initKeyGen(oprfKeyId);
        vm.stopPrank();
    }

    function testAbortKeyGenBeforeRound1() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        // abort before round 1
        abortKeyGen(oprfKeyId);
        // can still do keygen
        testKeyGen();
    }

    function testAbortDuringRound1() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
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

        abortKeyGen(oprfKeyId);
        testKeyGen();
    }

    function testAbortBeforeRound2() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        abortKeyGen(oprfKeyId);
        testKeyGen();
    }

    function testAbortDuringRound2() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.bobKeyGenRound2Contribution());
        vm.stopPrank();
        abortKeyGen(oprfKeyId);
        testKeyGen();
    }

    function testAbortBeforeRound3() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        keyGenRound2Contributions(oprfKeyId);
        abortKeyGen(oprfKeyId);
        testKeyGen();
    }

    function testAbortDuringRound3() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        keyGenRound2Contributions(oprfKeyId);
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 3, 0);
        oprfKeyRegistry.addRound3Contribution(oprfKeyId);
        vm.stopPrank();
        abortKeyGen(oprfKeyId);
        testKeyGen();
    }

    function testDeleteAfterInitKeyGenShouldFail() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);

        vm.prank(taceoAdmin);
        // now delete
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.WrongRound.selector, 1));
        oprfKeyRegistry.deleteOprfPublicKey(oprfKeyId);
        vm.stopPrank();

        // finish key-gen
        keyGenRound1Contributions(oprfKeyId);
        keyGenRound2Contributions(oprfKeyId);
        keyGenRound3Contributions(oprfKeyId);

        checkGeneratedKey(oprfKeyId, 0);
    }

    function testAbortAfterDeleteShouldFail() public {
        uint160 oprfKeyId = 42;
        testKeyGen();

        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyDeletion(oprfKeyId);
        oprfKeyRegistry.deleteOprfPublicKey(oprfKeyId);
        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, oprfKeyId));
        oprfKeyRegistry.abortKeyGen(oprfKeyId);
        vm.stopPrank();
    }

    function testDeleteBeforeRound1() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);

        vm.prank(taceoAdmin);
        // now delete
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.WrongRound.selector, 1));
        oprfKeyRegistry.deleteOprfPublicKey(oprfKeyId);
        vm.stopPrank();

        // finish key-gen
        keyGenRound1Contributions(oprfKeyId);
        keyGenRound2Contributions(oprfKeyId);
        keyGenRound3Contributions(oprfKeyId);

        checkGeneratedKey(oprfKeyId, 0);
    }

    function testDeleteBeforeRound2() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        vm.prank(taceoAdmin);
        // now delete
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.WrongRound.selector, 2));
        oprfKeyRegistry.deleteOprfPublicKey(oprfKeyId);
        vm.stopPrank();
        // finish key-gen
        keyGenRound2Contributions(oprfKeyId);
        keyGenRound3Contributions(oprfKeyId);

        checkGeneratedKey(oprfKeyId, 0);
    }

    function testDeleteBeforeRound3() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        keyGenRound2Contributions(oprfKeyId);

        vm.prank(taceoAdmin);
        // now delete
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.WrongRound.selector, 3));
        oprfKeyRegistry.deleteOprfPublicKey(oprfKeyId);
        vm.stopPrank();
        // finish key-gen
        keyGenRound3Contributions(oprfKeyId);

        checkGeneratedKey(oprfKeyId, 0);
    }

    function testKeyGen() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        keyGenRound2Contributions(oprfKeyId);
        keyGenRound3Contributions(oprfKeyId);

        checkGeneratedKey(oprfKeyId, 0);
    }

    function testKeyGenThenDelete() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);
        keyGenRound2Contributions(oprfKeyId);
        keyGenRound3Contributions(oprfKeyId);

        checkGeneratedKey(oprfKeyId, 0);

        deleteOprfKey(oprfKeyId);
        checkGeneratedIsDeleted(oprfKeyId);
    }

    function testKeyGenRound1Replay() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(oprfKeyId, Contributions.bobKeyGenRound1Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.BadContribution.selector));
        oprfKeyRegistry.addRound1KeyGenContribution(oprfKeyId, Contributions.bobKeyGenRound1Contribution());
        vm.stopPrank();
    }

    function testKeyGenRound2Replay() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        keyGenRound1Contributions(oprfKeyId);

        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.bobKeyGenRound2Contribution());
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(VerifierKeyGen13.ProofInvalid.selector));
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.bobKeyGenRound2Contribution());
        vm.stopPrank();
    }

    function testKeyGenRound2ReplayButDistinctKey() public {
        uint160 oprfKeyId = 42;
        initKeyGen(oprfKeyId);
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(oprfKeyId, Contributions.bobKeyGenRound1Contribution());
        vm.stopPrank();

        OprfKeyGen.Round1Contribution memory bobReplay = Contributions.bobKeyGenRound1Contribution();
        bobReplay.ephPubKey = Contributions.aliceKeyGenRound1Contribution().ephPubKey;

        // this works now
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 0, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(oprfKeyId, bobReplay);
        vm.stopPrank();

        vm.prank(carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.SecretGenRound2(oprfKeyId, 0);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 2, 1, 0);
        oprfKeyRegistry.addRound1KeyGenContribution(oprfKeyId, Contributions.carolKeyGenRound1Contribution());
        vm.stopPrank();

        // Bob sends his proof
        vm.prank(bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenConfirmation(oprfKeyId, 1, 2, 0);
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.bobKeyGenRound2Contribution());
        vm.stopPrank();

        // Alice can't just simply replay
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(VerifierKeyGen13.ProofInvalid.selector));
        oprfKeyRegistry.addRound2Contribution(oprfKeyId, Contributions.bobKeyGenRound2Contribution());
        vm.stopPrank();
    }

    function keyGenRound1Contributions(uint160 oprfKeyId) internal {
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
    }

    function keyGenRound2Contributions(uint160 oprfKeyId) internal {
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
    }

    function keyGenRound3Contributions(uint160 oprfKeyId) private {
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
    }

    function checkGeneratedKey(uint160 oprfKeyId, uint32 generatedEpoch) internal view {
        // check that the computed key is correct
        BabyJubJub.Affine memory oprfKey = oprfKeyRegistry.getOprfPublicKey(oprfKeyId);
        assertEq(oprfKey.x, Contributions.SHOULD_OPRF_PUBLIC_KEY_X);
        assertEq(oprfKey.y, Contributions.SHOULD_OPRF_PUBLIC_KEY_Y);

        OprfKeyGen.RegisteredOprfPublicKey memory oprfKeyAndEpoch = oprfKeyRegistry.getOprfPublicKeyAndEpoch(oprfKeyId);
        assertEq(oprfKey.x, Contributions.SHOULD_OPRF_PUBLIC_KEY_X);
        assertEq(oprfKey.y, Contributions.SHOULD_OPRF_PUBLIC_KEY_Y);
        assertEq(oprfKeyAndEpoch.key.x, Contributions.SHOULD_OPRF_PUBLIC_KEY_X);
        assertEq(oprfKeyAndEpoch.key.y, Contributions.SHOULD_OPRF_PUBLIC_KEY_Y);
        assertEq(oprfKeyAndEpoch.epoch, generatedEpoch);
    }

    function checkGeneratedIsDeleted(uint160 oprfKeyId) internal {
        // check that the key is deleted
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, 42));
        oprfKeyRegistry.getOprfPublicKey(oprfKeyId);

        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.DeletedId.selector, 42));
        oprfKeyRegistry.getOprfPublicKeyAndEpoch(oprfKeyId);
    }

    function abortKeyGen(uint160 oprfKeyId) internal {
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenAbort(oprfKeyId);
        oprfKeyRegistry.abortKeyGen(oprfKeyId);
        vm.stopPrank();
    }

    function deleteOprfKey(uint160 oprfKeyId) internal {
        vm.prank(taceoAdmin);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyDeletion(oprfKeyId);
        oprfKeyRegistry.deleteOprfPublicKey(oprfKeyId);
        vm.stopPrank();
    }
}
