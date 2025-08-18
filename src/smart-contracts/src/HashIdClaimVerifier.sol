// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract HashIdClaimVerifier {
    // Scalar field size
    uint256 constant hashid_r =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant hashid_q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant hashid_alphax =
        6922235750525215442977270786876140688176775595650224751229762020803609515161;
    uint256 constant hashid_alphay =
        16001318484618728714895105741287672464159167793837215088419564117099565374195;
    uint256 constant hashid_betax1 =
        18266355872294831192301654948213566512731223339973217209839443228504528169712;
    uint256 constant hashid_betax2 =
        18909420205818186924455946550520458543413537476165254446829174060316072340546;
    uint256 constant hashid_betay1 =
        7587749707599331113664502765882842560353071727804573239168147278641754201528;
    uint256 constant hashid_betay2 =
        7132758333250065390063684881809514122267861409757585646848080479666827294961;
    uint256 constant hashid_gammax1 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant hashid_gammax2 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant hashid_gammay1 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant hashid_gammay2 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant hashid_deltax1 =
        16155653844821176467445429302468755766792538147458926930006006656911581572711;
    uint256 constant hashid_deltax2 =
        19228757565059266298671195588326412707729125310447778557466385067306726223575;
    uint256 constant hashid_deltay1 =
        16170040034771808288639897627012959381628134025261304160922483197885988974940;
    uint256 constant hashid_deltay2 =
        21127872540584946580699518911000993226474606495073479429109814585933619400265;

    uint256 constant hashid_IC0x =
        12768869670335558406538059091887897712038431925337779065064533523172242641020;
    uint256 constant hashid_IC0y =
        9169885491993811205423821176751122464690935033952780679234188280172190168949;

    uint256 constant hashid_IC1x =
        21446642229251030811881348687018215427859417025851409509646833555287433126612;
    uint256 constant hashid_IC1y =
        7844296496941893795253379610839577006523875124388318943862573573295978507607;

    // Memory data
    uint16 constant hashid_pVk = 0;
    uint16 constant hashid_pPairing = 128;

    uint16 constant hashid_pLastMem = 896;

    function verifyHashIdProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[1] calldata _pubSignals
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, hashid_r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, hashid_pPairing)
                let _pVk := add(pMem, hashid_pVk)

                mstore(_pVk, hashid_IC0x)
                mstore(add(_pVk, 32), hashid_IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(
                    _pVk,
                    hashid_IC1x,
                    hashid_IC1y,
                    calldataload(add(pubSignals, 0))
                )

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(
                    add(_pPairing, 32),
                    mod(sub(hashid_q, calldataload(add(pA, 32))), hashid_q)
                )

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), hashid_alphax)
                mstore(add(_pPairing, 224), hashid_alphay)

                // beta2
                mstore(add(_pPairing, 256), hashid_betax1)
                mstore(add(_pPairing, 288), hashid_betax2)
                mstore(add(_pPairing, 320), hashid_betay1)
                mstore(add(_pPairing, 352), hashid_betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, hashid_pVk)))
                mstore(
                    add(_pPairing, 416),
                    mload(add(pMem, add(hashid_pVk, 32)))
                )

                // gamma2
                mstore(add(_pPairing, 448), hashid_gammax1)
                mstore(add(_pPairing, 480), hashid_gammax2)
                mstore(add(_pPairing, 512), hashid_gammay1)
                mstore(add(_pPairing, 544), hashid_gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), hashid_deltax1)
                mstore(add(_pPairing, 672), hashid_deltax2)
                mstore(add(_pPairing, 704), hashid_deltay1)
                mstore(add(_pPairing, 736), hashid_deltay2)

                let success := staticcall(
                    sub(gas(), 2000),
                    8,
                    _pPairing,
                    768,
                    _pPairing,
                    0x20
                )

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, hashid_pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
