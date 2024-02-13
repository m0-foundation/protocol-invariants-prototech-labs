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

import "./abstract/ThresholdGovernorHandler.sol";
import { ZeroGovernor } from "../lib/Ttg.sol";

contract ZeroGovernorHandler is ThresholdGovernorHandler {
    // ZeroGovernor public override governor;

    constructor(
        address _testContract,
        address _governor,
        bytes4[] memory validCallData_
    ) BaseHandler(_testContract) ThresholdGovernorHandler(validCallData_) BatchGovernorHandler(_governor) {
        // Constructor code here
    }

    function init(
        uint256 _numOfActors
    ) external {
        addActors(_numOfActors);
        zero = addActor(address(0), "zero");
        token = addActor(governor, "ZeroGovernor");

        validateActors();
    }

    function init(
        InvariantUtils.Actor[] memory _actors,
        InvariantUtils.Actor[] memory _receivers
    ) external {
        for(uint256 i = 0; i < _receivers.length; i++) {
            actors.push(_receivers[i]);

            if (_receivers[i].addr == governor) {
                // we want the zeroGovernor to be able to call itself
                msgSenders.push(_receivers[i]);
            }
        }

        validateActors(actors);

        for(uint256 i = 0; i < _actors.length; i++) {
            msgSenders.push(_actors[i]);
        }

        validateActors(msgSenders);
    }

    //
    // ZeroGovernor.sol - Testable functions
    //

    /* NOTE: Both resetToPowerHolders() and resetToZeroHolders() redeploy MZero
        contracts under the hood.  This means that all the handlers need to have
        their underlying objects swapped out on a successfull call.  In the
        case of a full integration, we have to poke this change all the way
        up to MZeroInvariants so that it can propogate those changes down to
        the other handlers.

        In addition to this, the new contracts will be added to fuzz selectors
        and calls will start happening to them dirrectly.  This means that
        we need to remove each new function from the fuzz selectors list.

    function resetToPowerHolders(
        uint256 _actorIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        if (actor.addr != governor) {
            addExpectedError("NotSelf()");
        }

        // TODO: onlySelf... need to simulate this.
        startGas();
        try ZeroGovernor(governor).resetToPowerHolders() {
            stopGas();


        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedErrorBytes32(0x0);
            expectedError(_err);
        }
    }

    function resetToZeroHolders(
        uint256 _actorIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        if (actor.addr != governor) {
            addExpectedError("NotSelf()");
        }

        startGas();
        try ZeroGovernor(governor).resetToZeroHolders() {
            stopGas();


        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedErrorBytes32(0x0);
            expectedError(_err);
        }
    }
    */

    function setCashToken(
        uint256 _actorIndex,
        address _newCashToken,
        uint256 _newProposalFee
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        if (actor.addr != governor) {
            addExpectedError("NotSelf()");
        }

        // TODO: Use valid cash tokens. This fix is in the reset PR.
        startGas();
        try ZeroGovernor(governor).setCashToken(_newCashToken, _newProposalFee) {
            stopGas();


        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("InvalidCashToken()");
            expectedError(_err);
        }
    }

    function setEmergencyProposalThresholdRatio(
        uint256 _actorIndex,
        uint16  _newThresholdRatio
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        if (actor.addr != governor) {
            addExpectedError("NotSelf()");
        }

        //  min 271, max 10000, range outside to expect some errors
        _newThresholdRatio = uint16(bound(_newThresholdRatio, 0, 11000));
        if (_newThresholdRatio < 271 ||
            _newThresholdRatio > 10000) {
            addExpectedError("InvalidThresholdRatio(uint256,uint256,uint256)");
        }

        startGas();
        try ZeroGovernor(governor).setEmergencyProposalThresholdRatio(_newThresholdRatio) {
            stopGas();


        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedErrorBytes32(0x0);
            expectedError(_err);
        }
    }

    function setZeroProposalThresholdRatio(
        uint256 _actorIndex,
        uint16  _newThresholdRatio
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        if (actor.addr != governor) {
            addExpectedError("NotSelf()");
        }

        //  min 271, max 10000, range outside to expect some errors
        _newThresholdRatio = uint16(bound(_newThresholdRatio, 0, 11000));
        if (_newThresholdRatio < 271 ||
            _newThresholdRatio > 10000) {
            addExpectedError("InvalidThresholdRatio(uint256,uint256,uint256)");
        }

        startGas();
        try ZeroGovernor(governor).setZeroProposalThresholdRatio(_newThresholdRatio) {
            stopGas();


        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedErrorBytes32(0x0);
            expectedError(_err);
        }
    }

}
