// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {BabyJubJub} from "@taceo/babyjubjub/BabyJubJub.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {OprfKeyGen} from "../src/OprfKeyGen.sol";
import {OprfKeyRegistry} from "../src/OprfKeyRegistry.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Test} from "forge-std/Test.sol";
import {Verifier as VerifierKeyGen13} from "../src/VerifierKeyGen13.sol";

contract OprfKeyRegistryTest is Test {
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
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.OprfPeerChanged(0, address(0), alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.OprfPeerChanged(1, address(0), bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.OprfPeerChanged(2, address(0), carol);
        oprfKeyRegistry.registerOprfPeers(peerAddresses);
    }

    function testConstructedCorrectly() public {
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, initOwner, taceoAdmin, verifierKeyGen, THRESHOLD, MAX_PEERS
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        OprfKeyRegistry oprfKeyRegistryTest = OprfKeyRegistry(address(proxyTest));

        assert(oprfKeyRegistryTest.keygenAdmins(taceoAdmin));
        assertEq(address(oprfKeyRegistryTest.keyGenVerifier()), address(verifierKeyGen));
        assertEq(oprfKeyRegistryTest.threshold(), 2);
        assertEq(oprfKeyRegistryTest.numPeers(), 3);
        assert(!oprfKeyRegistryTest.isContractReady());
        assert(oprfKeyRegistryTest.owner() == initOwner);

        // TODO call other functions to check that it reverts correctly
    }

    function testRegisterParticipants() public {
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, initOwner, taceoAdmin, verifierKeyGen, THRESHOLD, MAX_PEERS
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        OprfKeyRegistry oprfKeyRegistryTest = OprfKeyRegistry(address(proxyTest));

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = carol;

        // check that not ready
        assert(!oprfKeyRegistryTest.isContractReady());
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.OprfPeerChanged(0, address(0), alice);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.OprfPeerChanged(1, address(0), bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.OprfPeerChanged(2, address(0), carol);
        oprfKeyRegistryTest.registerOprfPeers(peerAddresses);

        // check that ready after call
        assert(oprfKeyRegistryTest.isContractReady());

        // check that parties can read their partyID
        vm.prank(alice);
        uint256 aliceId = oprfKeyRegistryTest.getPartyIdForParticipant(alice);
        assertEq(aliceId, 0);
        vm.stopPrank();

        vm.prank(bob);
        uint256 bobId = oprfKeyRegistryTest.getPartyIdForParticipant(bob);
        assertEq(bobId, 1);
        vm.stopPrank();

        vm.prank(carol);
        uint256 carolId = oprfKeyRegistryTest.getPartyIdForParticipant(carol);
        assertEq(carolId, 2);
        vm.stopPrank();

        // check that taceo is not a participant
        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.NotAParticipant.selector));
        oprfKeyRegistryTest.getPartyIdForParticipant(taceoAdmin);
        vm.stopPrank();
    }

    function testRegisterParticipantsNotTACEO() public {
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, initOwner, taceoAdmin, verifierKeyGen, THRESHOLD, MAX_PEERS
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        OprfKeyRegistry oprfKeyRegistryTest = OprfKeyRegistry(address(proxyTest));

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = carol;
        // check that not ready
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        oprfKeyRegistryTest.registerOprfPeers(peerAddresses);
    }

    function testRegisterParticipantsNotDistinct() public {
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, initOwner, taceoAdmin, verifierKeyGen, THRESHOLD, MAX_PEERS
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        OprfKeyRegistry oprfKeyRegistryTest = OprfKeyRegistry(address(proxyTest));

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = alice;
        peerAddresses[1] = bob;
        peerAddresses[2] = alice;

        // check that not ready
        assert(!oprfKeyRegistryTest.isContractReady());
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.PartiesNotDistinct.selector));
        oprfKeyRegistryTest.registerOprfPeers(peerAddresses);
    }

    function testUpdateParticipants() public {
        // check the partyIDs
        vm.prank(alice);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(alice), 0);
        vm.stopPrank();

        vm.prank(bob);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(bob), 1);
        vm.stopPrank();

        vm.prank(carol);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(carol), 2);
        vm.stopPrank();

        address[] memory peerAddresses = new address[](3);
        peerAddresses[0] = bob;
        peerAddresses[1] = carol;
        peerAddresses[2] = taceoAdmin;

        // update
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.OprfPeerChanged(0, alice, bob);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.OprfPeerChanged(1, bob, carol);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.OprfPeerChanged(2, carol, taceoAdmin);
        oprfKeyRegistry.registerOprfPeers(peerAddresses);

        vm.prank(bob);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(bob), 0);
        vm.stopPrank();

        vm.prank(carol);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(carol), 1);
        vm.stopPrank();

        vm.prank(taceoAdmin);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(taceoAdmin), 2);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.NotAParticipant.selector));
        oprfKeyRegistry.getPartyIdForParticipant(alice);
        vm.stopPrank();

        address[] memory peerAddresses2 = new address[](3);
        peerAddresses2[0] = bob;
        peerAddresses2[1] = carol;
        peerAddresses2[2] = alice;

        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.OprfPeerChanged(2, taceoAdmin, alice);
        oprfKeyRegistry.registerOprfPeers(peerAddresses2);

        vm.prank(bob);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(bob), 0);
        vm.stopPrank();

        vm.prank(carol);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(carol), 1);
        vm.stopPrank();

        vm.prank(alice);
        assertEq(oprfKeyRegistry.getPartyIdForParticipant(alice), 2);
        vm.stopPrank();
    }

    function testRegisterParticipantsWrongNumberKeys() public {
        // Deploy implementation
        OprfKeyRegistry implementation = new OprfKeyRegistry();
        // Encode initializer call
        bytes memory initData = abi.encodeWithSelector(
            OprfKeyRegistry.initialize.selector, initOwner, taceoAdmin, verifierKeyGen, THRESHOLD, MAX_PEERS
        );
        // Deploy proxy
        ERC1967Proxy proxyTest = new ERC1967Proxy(address(implementation), initData);
        OprfKeyRegistry oprfKeyRegistryTest = OprfKeyRegistry(address(proxyTest));

        address[] memory peerAddressesWrong = new address[](2);
        peerAddressesWrong[0] = alice;
        peerAddressesWrong[1] = bob;

        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.UnexpectedAmountPeers.selector, 3));
        oprfKeyRegistryTest.registerOprfPeers(peerAddressesWrong);
    }

    function testInitKeyGenRevokeRegisterAdmin() public {
        uint160 oprfKeyId = 42;
        vm.startPrank(taceoAdmin);
        // register another admin
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenAdminRegistered(alice);
        oprfKeyRegistry.addKeyGenAdmin(alice);
        assertEq(2, oprfKeyRegistry.amountKeygenAdmins());

        // revoke taceo
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.KeyGenAdminRevoked(taceoAdmin);
        oprfKeyRegistry.revokeKeyGenAdmin(taceoAdmin);
        assertEq(1, oprfKeyRegistry.amountKeygenAdmins());

        // try start key-gen as taceo
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.OnlyAdmin.selector));
        oprfKeyRegistry.initKeyGen(oprfKeyId);
        vm.stopPrank();

        // start key-gen as alice
        vm.prank(alice);
        oprfKeyRegistry.initKeyGen(oprfKeyId);
        vm.stopPrank();
    }

    function testRevokeLastAdmin() public {
        vm.startPrank(taceoAdmin);
        // register another admin
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.LastAdmin.selector));
        oprfKeyRegistry.revokeKeyGenAdmin(taceoAdmin);
        assertEq(1, oprfKeyRegistry.amountKeygenAdmins());
        vm.stopPrank();
    }

    function testRevokeAdminThatIsNoAdmin() public {
        vm.startPrank(taceoAdmin);
        vm.recordLogs();
        oprfKeyRegistry.revokeKeyGenAdmin(alice);
        assertEq(1, oprfKeyRegistry.amountKeygenAdmins());
        vm.stopPrank();
        assertEq(0, vm.getRecordedLogs().length);
    }

    function testRegisterAdminTwice() public {
        vm.startPrank(taceoAdmin);
        vm.recordLogs();
        oprfKeyRegistry.addKeyGenAdmin(taceoAdmin);
        assertEq(1, oprfKeyRegistry.amountKeygenAdmins());
        vm.stopPrank();
        assertEq(0, vm.getRecordedLogs().length);
    }

    function testChangeVerifierContract() public {
        address newAddress = address(0x42);
        vm.expectEmit(true, true, true, true);
        emit OprfKeyGen.VerifierContractChanged(address(verifierKeyGen), newAddress);
        oprfKeyRegistry.changeVerifierContract(newAddress);
    }

    function testChangeVerifierContractNoOwner() public {
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, alice));
        oprfKeyRegistry.changeVerifierContract(address(0x42));
        vm.stopPrank();
    }

    function testInitKeyGenResubmit() public {
        vm.prank(taceoAdmin);
        oprfKeyRegistry.initKeyGen(42);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.AlreadySubmitted.selector));
        vm.prank(taceoAdmin);
        oprfKeyRegistry.initKeyGen(42);
    }

    function testInitReshareBeforeKeyGen() public {
        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.UnknownId.selector, 42));
        oprfKeyRegistry.initReshare(42);
    }

    function testInitKeyGenWithZero() public {
        vm.prank(taceoAdmin);
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.BadContribution.selector));
        oprfKeyRegistry.initKeyGen(0);
    }

    function testDeleteBeforeKeyGen() public {
        uint160 oprfKeyId = 42;
        vm.prank(taceoAdmin);
        // now delete
        vm.expectRevert(abi.encodeWithSelector(OprfKeyRegistry.UnknownId.selector, 42));
        oprfKeyRegistry.deleteOprfPublicKey(oprfKeyId);
        vm.stopPrank();
    }
}
