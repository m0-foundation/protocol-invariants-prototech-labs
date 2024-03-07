// SPDX-FileCopyrightText: © 2024 Prototech Labs <info@prototechlabs.dev>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright © 2024 Christopher Mooney
// Copyright © 2024 Chris Smith
// Copyright © 2024 Brian McMichael
// Copyright © 2024 Derek Flossman
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
pragma solidity ^0.8.23;

import { MTokenInvariants } from "../MTokenInvariants.t.sol";
// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";

contract MTokenRegressionTests is MTokenInvariants {
    function setUp() public override {
        super.setUp();
    }

    function _setMaxLeap(uint256 maxLeap) internal {
        _mTokenHandler.setMaxLeap(maxLeap);
    }

    // =========== Further Exploration Required ===========

    // function test_regression_invariant_M_B2_B3_B4_da6d4845_failure() external {
    //     _setMaxLeap(200000);
    //     _mTokenHandler.mint(115792089237316195423570985008687907853269984665640564039457584007913129639935, 452247059504320551675974, 46667416485406766757911130859955596839284290204802730212);
    //     _mTokenHandler.allowEarningOnBehalf(115792089237316195423570985008687907853269984665640564039457584007913129639934);
    //     _mTokenHandler.startEarning(373652006262320467999595998008604310570066778511835158316780844561);
    //     _mTokenHandler.startEarning(764549955);
    //     _mTokenHandler.mint(23605339856914304328848201318149084194632226948617038, 2, 599038166544913752810534203563046714);
    //     _mTokenHandler.updateIsEarnersListIgnored(8, true);
    //     _mTokenHandler.startEarningOnBehalfOf(3866627391537203399435265920853722409652251837836601569281283658, 115792089237316195423570985008687907853269984665640564039457584007913129639934);
    //     _mTokenHandler.mint(2, 26087760733375464616778398666076159213579546586049957456620983487020, 31074428715259089129761320986565626547332596902834918);

    //     invariant_M_B2_B3_B4();
    // }

    // function test_regression_invariant_M_B2_B3_B4_b8462236_failure() external {
    //     _setMaxLeap(200000);
    //     _mTokenHandler.updateIsEarnersListIgnored(115792089237316195423570985008687907853269984665640564039457584007913129639933, true);
    //     _mTokenHandler.startEarning(1322);
    //     _mTokenHandler.mint(115792089237316195423570985008687907853269984665640564039457584007913129639934, 319223391147983177612721736064420985887644979120440362735279297979, 115792089237316195423570985008687907853269984665640564039457584007913129639934);
    //     _mTokenHandler.startEarning(4968821038007916838901351145008266316643283127184099257668839502498378);
    //     _mTokenHandler.startEarning(15793244);
    //     _mTokenHandler.mint(78517167103814719436873156054713463222818932359426984083260, 115792089237316195423570985008687907853269984665640564039457584007913129639933, 115792089237316195423570985008687907853269984665640564039457584007913129639932);
    //     _mTokenHandler.mint(220368847, 115792089237316195423570985008687907853269984665640564039457584007913129639935, 115792089237316195423570985008687907853269984665640564039457584007913129639932);

    //     invariant_M_B2_B3_B4();
    // }

    // function test_regression_invariant_M_B2_B3_B4_bc05665d_failure() external {
    //     _setMaxLeap(200000);
    //     _mTokenHandler.approve(4735, 196865, 27020502126871186281680295503780039255774807856615338576534450657750299223612);
    //     _mTokenHandler.mint(3, 115792089237316195423570985008687907853269984665640564039457584007913129639933, 115792089237316195423570985008687907853269984665640564039457584007913129639934);
    //     _mTokenHandler.updateIsEarnersListIgnored(18446744073709479002, true);
    //     _mTokenHandler.startEarning(73471348132037465186676393389869);
    //     _mTokenHandler.mint(4431914140782419944044491717332193772489787004242686532081902035, 63142830188540883120336683563465149827, 115792089237316195423570985008687907853269984665640564039457584007913129639933);
    //     _mTokenHandler.startEarning(9968);
    //     _mTokenHandler.mint(1743344158744109694565720221638813290769557, 115792089237316195423570985008687907853269984665640564039457584007913129639933, 115792089237316195423570985008687907853269984665640564039457584007913129639932);

    //     invariant_M_B2_B3_B4();
    // }
}
