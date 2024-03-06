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

import { RegistrarInvariants } from "../RegistrarInvariants.t.sol";
// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";

contract RegistrarRegressionTests is RegistrarInvariants {
    function setUp() public override {
        super.setUp();
    }

    function _setMaxLeap(uint256 maxLeap) internal {
        _registrarHandler.setMaxLeap(maxLeap);
    }

    function test_regression_invariant_R_M2_adddd87e_failure() external {
        _setMaxLeap(3600);
        _registrarHandler.removeFromList(8784990296086728386472442459532773829916124999010626314444799661087631, 0x9a0ed316e65260cde5650f032a50a3a908fb8a2f9a3a4f44be3e687bea58c61b, 0xb862285bf6Cc39625e5f8A304F6b24dCabbF3Fb1);
        _registrarHandler.setKey(115792089237316195423570985008687907853269984665640564039457584007913129639933, 0xc2acf414b81c7e3a5dc7019890f393a864c8c905f87f08a55621f3c902952560, 0xed76eceac4cecf1fe2d13ec3c66c814ce56ca11053c542e3d202bd5d2dccc706);
        _registrarHandler.setKey(316995621703706653271479440712189289668746414849, 0xc2acf414b81c7e3a5dc7019890f393a864c8c905f87f08a55621f3c902952560, 0x0000000000000000000000000000000000000000000000000000000000001827);

        invariant_R_M2();
    }

    function test_regression_invariant_R_M2_c8fb3e00_failure() external {
        _setMaxLeap(3600);
        _registrarHandler.setKey(1, 0x025a345137ef85d332d8e76a16872d2f984844d08c07733d0a0e94e2a0f0f12c, 0x45b0bd383db6ff51dc7496f9b7d782784692073fcc2e8530286c5d32fa0fbf58);
        _registrarHandler.setKey(15560648, 0x025a345137ef85d332d8e76a16872d2f984844d08c07733d0a0e94e2a0f0f12c, 0x00000000000000000000000000000000000000000000000000000000000050f5);

        invariant_R_M2();
    }
}
