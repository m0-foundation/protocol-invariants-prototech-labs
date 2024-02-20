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

import { ZeroTokenInvariants } from "../ZeroTokenInvariants.t.sol";
// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";

contract ZeroTokenRegressionTests is ZeroTokenInvariants {
    function setUp() public override {
        super.setUp();
    }

    function _setMaxLeap(uint256 maxLeap) internal {
        _zeroTokenHandler.setMaxLeap(maxLeap);
    }

    // TODO: keep this regression around until Finding 7.1 is resolved and re-tested
    // may need git checkout 55e82fb481695ad91b9afbbea1248ca161b548a5 to reproduce
    function test_regression_invariant_ZT_P1_dcc5c365_failure() external {
        console.log("zero address votes: ", zeroToken.getVotes(address(0)));
        _zeroTokenHandler.delegateBySigWithSignature(0, 4740936329651237291510126, 300071015589032596298344845016257483511895667468841636, 96894251519372880130759386086791722235917156683817816834);
        console.log("zero address votes: ", zeroToken.getVotes(address(0)));
        _zeroTokenHandler.permit(1443, 2072, 59234, 12904, 30049578511147215784808879450479816275028553870824074561265229521678225113088, 243313642115106858902493542147085865830094663268);
        console.log("zero address votes: ", zeroToken.getVotes(address(0)));
        _zeroTokenHandler.delegateBySigWithSignature(7154, 16823, 6842, 19084);
        console.log("zero address votes: ", zeroToken.getVotes(address(0)));

        invariant_ZT_P1();
    }
}
