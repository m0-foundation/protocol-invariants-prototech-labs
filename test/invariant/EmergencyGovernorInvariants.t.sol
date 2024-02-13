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
import { BaseInvariants } from "./lib/BaseInvariants.sol";
import { BaseMZeroInvariants } from "./lib/BaseMZeroInvariants.sol";
import { InvariantUtils } from "./lib/InvariantUtils.sol";
import {
    EmergencyGovernorHandler,
    RegistrarGovernorHandler,
    ThresholdGovernorHandler,
    BatchGovernorHandler
} from "./handlers/EmergencyGovernorHandler.sol";

import {
    EmergencyGovernor,
    MockEmergencyGovernor,
    MockEmergencyGovernorDeployer,
    MockStandardGovernorDeployer,
    MockRegistrar,
    MockStandardGovernor,
    MockPowerTokenDeployer,
    MockBootstrapToken,
    MockEmergencyGovernor,
    ZeroGovernor
} from "./lib/Ttg.sol";

contract InvariantMockRegistrar is MockRegistrar {
    function setKey(bytes32 key, bytes32 value) external view {}
}

contract EmergencyGovernorInvariants is BaseInvariants, BaseMZeroInvariants {

    EmergencyGovernorHandler public _emergencyGovernorHandler;

    function setUp() public virtual {
        if (!_integration) {
            _mockBootstrapToken = new MockBootstrapToken();
            _mockZeroToken = new MockBootstrapToken();
            _mockPowerToken = new MockBootstrapToken();
            _mockEmergencyGovernor = new MockEmergencyGovernor();
            _mockEmergencyGovernorDeployer = new MockEmergencyGovernorDeployer();
            _mockPowerTokenDeployer = new MockPowerTokenDeployer();
            _mockRegistrar = new InvariantMockRegistrar();
            _mockStandardGovernor = new MockStandardGovernor();
            _mockStandardGovernorDeployer = new MockStandardGovernorDeployer();

            _mockBootstrapToken.setTotalSupply(1);
            _mockPowerToken.setTotalSupply(1);

            _mockEmergencyGovernor.setThresholdRatio(1);
            _mockEmergencyGovernorDeployer.setNextDeploy(address(_mockEmergencyGovernor));

            _mockPowerTokenDeployer.setNextDeploy(address(_mockPowerToken));

            _mockStandardGovernor.setVoteToken(address(_mockPowerToken));
            _mockStandardGovernor.setCashToken(address(_cashToken1));
            _mockStandardGovernor.setProposalFee(1e18);

            _mockStandardGovernorDeployer.setNextDeploy(address(_mockStandardGovernor));

            zeroGovernor = new ZeroGovernor(
                address(_mockZeroToken),
                address(_mockEmergencyGovernorDeployer),
                address(_mockPowerTokenDeployer),
                address(_mockStandardGovernorDeployer),
                address(_mockBootstrapToken),
                1,
                1,
                _zeroProposalThresholdRatio,
                _allowedCashTokens
            );

            emergencyGovernor = new EmergencyGovernor(
                address(_mockPowerToken),
                address(zeroGovernor),
                address(_mockRegistrar),
                address(_mockStandardGovernor),
                _emergencyProposalThresholdRatio
            );
        }

        bytes4[] memory validCallDatas = new bytes4[](5);
        validCallDatas[0] = EmergencyGovernor.addToList.selector;
        validCallDatas[1] = EmergencyGovernor.removeFromList.selector;
        validCallDatas[2] = EmergencyGovernor.removeFromAndAddToList.selector;
        validCallDatas[3] = EmergencyGovernor.setKey.selector;
        validCallDatas[4] = EmergencyGovernor.setStandardProposalFee.selector;

        _emergencyGovernorHandler = new EmergencyGovernorHandler(
            address(this),
            address(emergencyGovernor),
            validCallDatas
        );

        if (!_integration) {
            _emergencyGovernorHandler.init(NUM_OF_ACTORS);
        } else {
            _emergencyGovernorHandler.init(_actors, _receivers);
        }

        // add all testable functions
        bytes4[] memory selectors = new bytes4[](17);
        selectors[0]  = BatchGovernorHandler.castVote.selector;
        selectors[1]  = BatchGovernorHandler.castVoteBySigVRS.selector;
        selectors[2]  = BatchGovernorHandler.castVoteBySigSignature.selector;
        selectors[3]  = BatchGovernorHandler.castVotes.selector;
        selectors[4]  = BatchGovernorHandler.castVotesBySigVRS.selector;
        selectors[5]  = BatchGovernorHandler.castVotesBySigSignature.selector;
        selectors[6]  = BatchGovernorHandler.castVoteWithReason.selector;
        selectors[7]  = ThresholdGovernorHandler.execute.selector;
        selectors[8]  = ThresholdGovernorHandler.propose.selector;
        selectors[9]  = RegistrarGovernorHandler.addToList.selector;
        selectors[10] = RegistrarGovernorHandler.removeFromList.selector;
        selectors[11] = RegistrarGovernorHandler.removeFromAndAddToList.selector;
        selectors[12] = RegistrarGovernorHandler.setKeyBytes32.selector;
        selectors[13] = RegistrarGovernorHandler.setKeyUint256.selector;
        selectors[14] = RegistrarGovernorHandler.setKeyAddress.selector;
        selectors[15] = EmergencyGovernorHandler.setThresholdRatio.selector;
        selectors[16] = EmergencyGovernorHandler.setStandardProposalFee.selector;

        targetSelector(FuzzSelector({
            addr: address(_emergencyGovernorHandler),
            selectors: selectors
        }));

        targetContract(address(_emergencyGovernorHandler));
    }

    //
    // metadata invariants
    //
    function invariant_EG_M1() public leap {
        require(
            address(zeroGovernor) == emergencyGovernor.zeroGovernor(),
            "Metadata Invariant EG_M1"
        );
    }

    // Functions don't exceed max gas
    function invariant_EG_G1() public leap {
        require(
            _emergencyGovernorHandler.gasViolations() == 0,
            "Gas Invariant EG_G1"
        );
    }
}
