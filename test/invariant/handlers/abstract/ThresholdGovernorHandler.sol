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

import "./BatchGovernorHandler.sol";
import { IThresholdGovernor, IGovernor } from "../../lib/Ttg.sol";

abstract contract ThresholdGovernorHandler is BatchGovernorHandler {

    bytes4[] internal _validCallData;

    constructor(bytes4[] memory validCallData_) {
        _validCallData = validCallData_;
    }

    function execute(
        uint256 _actorIndex,
        uint256 _arrayRandomness,
        bytes32 descriptionHash
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        // targets should be exactly 1
        uint256 targetsLength = bound(_arrayRandomness, 0, 2);
        address[] memory targets = new address[](targetsLength);
        for(uint256 i = 0; i < targetsLength; i++) {
            uint256 randomNum = random256(_arrayRandomness);
            targets[i] = actors[bound(randomNum, 0, actors.length - 1)].addr;
            _arrayRandomness = randomNum;
        }

        // values should be exactly 1
        uint256 valuesLength = bound(_arrayRandomness, 0, 2);
        uint256[] memory values = new uint256[](valuesLength);
        for(uint256 i = 0; i < valuesLength; i++) {
            values[i] = random256(_arrayRandomness);
            _arrayRandomness = values[i];
        }

        // callDatas should be exactly 1
        uint256 callDatasLength = bound(_arrayRandomness, 0, 2);
        bytes[] memory callDatas = new bytes[](callDatasLength);
        for(uint256 i = 0; i < callDatasLength; i++) {
            if (bound(_actorIndex, 0, 9) == 0)  {
                // 10% of the time release a callData chaos monkey
                uint256 randomNum = random256(_arrayRandomness);
                callDatas[i] = bytes(abi.encodePacked(randomNum));
                _arrayRandomness = randomNum;
            } else {
                // get a valid callData
                callDatas[i] = abi.encodePacked(_validCallData[bound(_arrayRandomness, 0, _validCallData.length - 1)]);
            }
        }

        uint48 beforeProposeVoteStart = _getCallDatasVoteStart(callDatas);

        try IThresholdGovernor(governor).execute(
            targets, // not used
            values, // not used
            callDatas,
            descriptionHash // not used
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if(callDatasLength == 0) addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x32)));

            if(beforeProposeVoteStart == 0) {
                // TODO get better info on when each of these should appear
                addExpectedError("ProposalDoesNotExist()");
                addExpectedError("ProposalCannotBeExecuted()");
            }
            if(clock() - 1 == 0) addExpectedError("InvalidVoteStart()");
            expectedError(_err);
        }
    }

    function propose(
        uint256 _actorIndex,
        uint256 _arrayRandomness
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        // targets should be exactly 1
        uint256 targetsLength = bound(_arrayRandomness, 0, 2);
        address[] memory targets = new address[](targetsLength);
        for(uint256 i = 0; i < targetsLength; i++) {
            uint256 randomNum = random256(_arrayRandomness);
            targets[i] = actors[bound(randomNum, 0, actors.length - 1)].addr;
            _arrayRandomness = randomNum;
        }

        // values should be exactly 1
        uint256 valuesLength = bound(_arrayRandomness, 0, 2);
        uint256[] memory values = new uint256[](valuesLength);
        for(uint256 i = 0; i < valuesLength; i++) {
            values[i] = random256(_arrayRandomness);
            _arrayRandomness = values[i];
        }

        // callDatas should be exactly 1
        uint256 callDatasLength = bound(_arrayRandomness, 0, 2);
        bytes[] memory callDatas = new bytes[](callDatasLength);
        for(uint256 i = 0; i < callDatasLength; i++) {
            if (bound(_actorIndex, 0, 9) == 0)  {
                // 10% of the time release a callData chaos monkey
                uint256 randomNum = random256(_arrayRandomness);
                callDatas[i] = bytes(abi.encodePacked(randomNum));
                _arrayRandomness = randomNum;
            } else {
                // get a valid callData
                callDatas[i] = abi.encodePacked(_validCallData[bound(_arrayRandomness, 0, _validCallData.length - 1)]);
            }
        }

        uint48 beforeProposeVoteStart = _getCallDatasVoteStart(callDatas);

        try IThresholdGovernor(governor).propose(
            targets, // address[]
            values, // uint256[]
            callDatas, // bytes[]
            "description" // string that goes to the event
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if(targetsLength   != 1) addExpectedError("InvalidTargetsLength()");
            if(valuesLength    != 1) addExpectedError("InvalidValuesLength()");
            if(callDatasLength != 1) addExpectedError("InvalidCallDatasLength()");

            if(targetsLength   > 0 && targets[0] != address(governor)) addExpectedError("InvalidTarget()");
            if(valuesLength    > 0 && values[0]  != 0)                 addExpectedError("InvalidValue()");
            if(callDatasLength > 0 && !validCallData(callDatas[0]))    addExpectedError("InvalidCallData()");

            if(beforeProposeVoteStart != 0) addExpectedError("ProposalExists()");
            expectedError(_err);
        }
    }

    function validCallData(bytes memory _callData) internal view returns (bool valid) {
        bytes4 func = bytes4(_callData);

        for(uint256 i = 0; i < _validCallData.length; i++) {
            if(func == _validCallData[i]) {
                valid = true;
                break;
            }
        }
    }

    function _getCallDatasVoteStart(bytes[] memory callDatas) internal view returns (uint48 _start) {
        if (callDatas.length == 1) {
            uint256 proposalId = IThresholdGovernor(governor).hashProposal(
                callDatas[0]
            );
            _start = _getProposalVoteStart(proposalId);
        }
    }
}
