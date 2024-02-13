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

// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";

import { ProtocolInvariants } from "../ProtocolInvariants.t.sol";

contract ProtocolRegressionTests is ProtocolInvariants {

    function setUp() public override {
        super.setUp();
    }

    function _setMaxLeap(uint256 maxLeap) internal {
        _minterGatewayHandler.setMaxLeap(maxLeap);
        _mTokenHandler.setMaxLeap(maxLeap);
    }

    // earners overflows
    // function test_regression_invariant_M_B2_B3_B4_880410c4_failure() external {
    //     _setMaxLeap(500000);
    //     _mTokenHandler.updateIsEarnersListIgnored(482615503566387599912779291605873014882755448541786262084, true);
    //     _mTokenHandler.mint(2, 9650690465195152347881526194995, 115792089237316195423570985008687907853269984665640564039457584007913129639932);
    //     _mTokenHandler.startEarning(6779599439146420999878776523370086409616907235);
    //     _mTokenHandler.startEarning(989459965652266897858);
    //     _mTokenHandler.mint(0, 115792089237316195423570985008687907853269984665640564039457584007913129639934, 115792089237316195423570985008687907853269984665640564039457584007913129639935);

    //     invariant_M_B2_B3_B4();
    // }

    // =========== Further Exploration Required ===========

    // function test_regression_invariant_M_B2_B3_B4_096ee078_failure() external {
    //     _setMaxLeap(200000);
    //     _minterGatewayHandler.updateCollateralThreshold(11208, 15757);
    //     _minterGatewayHandler.mintM(70496997610736145893134515890996, 106404599847);
    //     _minterGatewayHandler.updateCollateralInterval(139834576000142828007826637400691611363, 1);
    //     _minterGatewayHandler.updatePenaltyRate(4687054904495521308354280732584734107466838107493623197910947335394195989, 4294967295);
    //     _minterGatewayHandler.proposeMint(1305, 4521, 1663316815);

    //     invariant_M_B2_B3_B4();
    // }
}
