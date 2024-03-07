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

import { MinterGatewayInvariants, console } from "../MinterGatewayInvariants.t.sol";

contract MinterGatewayRegressionTests is MinterGatewayInvariants {

    function setUp() public override {
        super.setUp();
    }

    function _setMaxLeap(uint256 maxLeap) internal {
        _minterGatewayHandler.setMaxLeap(maxLeap);
    }

    function test_regression_invariant_MG_B1_fa0e6476_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(22593, 3771);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_B1();
    }

    function test_regression_invariant_MG_B2_64112dab_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(22593, 4072907491);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_B2();
    }

    function test_regression_invariant_MG_B3_64112dab_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(22593, 4072907491);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_B3();
    }

    function test_regression_invariant_MG_B4_1fd379c5_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(17374, 4072907491);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_B4();
    }

    function test_regression_invariant_MG_B5_45b25b9e_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(22593, 3179243142);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_B5();
    }

    function test_regression_invariant_MG_B6_4d0c8cf5_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(131, 1522);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_B6();
    }

    function test_regression_invariant_MG_B7_549439db_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(17374, 3771);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_B7();
    }

    function test_regression_invariant_MG_B8_979d3ec2_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(17374, 4072907491);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_B8();
    }

    function test_regression_invariant_MG_B9_64112dab_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(22593, 4072907491);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_B9();
    }

    function test_regression_invariant_MG_G1_979d3ec2_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(17374, 4072907491);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_G1();
    }

    function test_regression_invariant_MG_M1_979d3ec2_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(17374, 4072907491);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_M1();
    }

    function test_regression_invariant_MG_M2_979d3ec2_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(17374, 4072907491);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_M2();
    }

    function test_regression_invariant_MG_N1_979d3ec2_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(17374, 4072907491);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_N1();
    }

    function test_regression_invariant_MG_N2_979d3ec2_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(17374, 4072907491);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_N2();
    }

    function test_regression_invariant_MG_T1_defd2029_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.updateMintRatio(1757, 6648);
        _minterGatewayHandler.updateMintFreezerTime(216017959017590092151982804865324, 4294967294);
        _minterGatewayHandler.burnM_minterPrincipalMax(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0x9C82D5452b1B0bb8402e657162d74C6d8ed81bd8, 42103246570071479623086, 0);

        invariant_MG_T1();
    }
}
