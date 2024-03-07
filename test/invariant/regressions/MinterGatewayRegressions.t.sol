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

    ///////////////////////// Begin Valid regressions /////////////////////////
    function test_regression_invariant_MG_B8_0f887631_failure() external {
        _setMaxLeap(43200);
        _minterGatewayHandler.freezeMinter(1875, 6531);
        _minterGatewayHandler.proposeMint(1168, 21504, 2842722828453697979017187004962313056323450918916513186810143368522445619201);
        _minterGatewayHandler.proposeRetrieval(1670617071, 1127);
        _minterGatewayHandler.freezeMinter(215386877620634697283195853089078548798984188230902445320592946791973902, 115792089237316195423570985008687907853269984665640564039457584007913129639935);
        _minterGatewayHandler.mintM(13462415238350522994975542907801965671131702475192695331171400117732539, 115792089237316195423570985008687907853269984665640564039457584007913129639932);
        _minterGatewayHandler.updateCollateralInterval(1, 19);
        _minterGatewayHandler.freezeMinter(1580616919, 1674416791);
        _minterGatewayHandler.updateCollateral(198571843959024771361160079894863967054889216, 115792089237316195423570985008687907853269984665640564039457584007913129639934);
        _minterGatewayHandler.proposeMint(2, 0, 795241873597757511877289020032563093300687682375750941727894485);

        // Invariant B8 is not valid as long as Finding 10.3 is unresolved
        invariant_MG_B8();
    }
    ///////////////////////// End Valid regressions ///////////////////////////

}
