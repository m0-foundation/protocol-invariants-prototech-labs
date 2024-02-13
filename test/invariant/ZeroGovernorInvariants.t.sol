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
    ZeroGovernorHandler,
    ThresholdGovernorHandler,
    BatchGovernorHandler
} from "./handlers/ZeroGovernorHandler.sol";

import {
    MockZeroGovernor,
    MockEmergencyGovernorDeployer,
    MockStandardGovernorDeployer,
    MockStandardGovernor,
    MockPowerTokenDeployer,
    MockBootstrapToken,
    MockEmergencyGovernor,
    ZeroGovernor
} from "./lib/Ttg.sol";

contract ZeroGovernorInvariants is BaseInvariants, BaseMZeroInvariants {

    ZeroGovernorHandler public _zeroGovernorHandler;

    function setUp() public virtual {

        if (!_integration) {
            _mockBootstrapToken = new MockBootstrapToken();
            _mockZeroToken = new MockBootstrapToken();
            _mockPowerToken = new MockBootstrapToken();
            _mockEmergencyGovernor = new MockEmergencyGovernor();
            _mockEmergencyGovernorDeployer = new MockEmergencyGovernorDeployer();
            _mockPowerTokenDeployer = new MockPowerTokenDeployer();
            _mockStandardGovernor = new MockStandardGovernor();
            _mockStandardGovernorDeployer = new MockStandardGovernorDeployer();

            _mockBootstrapToken.setTotalSupply(1);
            _mockZeroToken.setTotalSupply(1);
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
                _emergencyProposalThresholdRatio,
                _zeroProposalThresholdRatio,
                _allowedCashTokens
            );
        }

        bytes4[] memory validCallDatas = new bytes4[](3);
        // TODO: see note in ZeroGovernorHandler.sol
        // validCallDatas[0] = ZeroGovernor.resetToPowerHolders.selector;
        // validCallDatas[1] = ZeroGovernor.resetToZeroHolders.selector;
        validCallDatas[0] = ZeroGovernor.setCashToken.selector;
        validCallDatas[1] = ZeroGovernor.setEmergencyProposalThresholdRatio.selector;
        validCallDatas[2] = ZeroGovernor.setZeroProposalThresholdRatio.selector;

        _zeroGovernorHandler = new ZeroGovernorHandler(
            address(this),
            address(zeroGovernor),
            validCallDatas
        );

        if (!_integration) {
            _zeroGovernorHandler.init(NUM_OF_ACTORS);
        } else {
            _zeroGovernorHandler.init(_actors, _receivers);
        }

        // add all testable functions
        bytes4[] memory selectors = new bytes4[](12);
        selectors[0]  = BatchGovernorHandler.castVote.selector;
        selectors[1]  = BatchGovernorHandler.castVoteBySigVRS.selector;
        selectors[2]  = BatchGovernorHandler.castVoteBySigSignature.selector;
        selectors[3]  = BatchGovernorHandler.castVotes.selector;
        selectors[4]  = BatchGovernorHandler.castVotesBySigVRS.selector;
        selectors[5]  = BatchGovernorHandler.castVotesBySigSignature.selector;
        selectors[6]  = BatchGovernorHandler.castVoteWithReason.selector;
        selectors[7]  = ThresholdGovernorHandler.execute.selector;
        selectors[8]  = ThresholdGovernorHandler.propose.selector;
        // TODO: see note in ZeroGovernorHandler.sol
        // selectors[9]  = ZeroGovernorHandler.resetToPowerHolders.selector;
        // selectors[10] = ZeroGovernorHandler.resetToZeroHolders.selector;
        selectors[9]  = ZeroGovernorHandler.setCashToken.selector;
        selectors[10] = ZeroGovernorHandler.setEmergencyProposalThresholdRatio.selector;
        selectors[11] = ZeroGovernorHandler.setZeroProposalThresholdRatio.selector;

        targetSelector(FuzzSelector({
            addr: address(_zeroGovernorHandler),
            selectors: selectors
        }));

        targetContract(address(_zeroGovernorHandler));
    }

    //
    // metadata invariants
    //
    function invariant_ZG_M1() public leap {
        require(
            zeroGovernor.isAllowedCashToken(address(_cashToken1)),
            "Metadata Invariant ZG_M1"
        );
    }

    // Functions don't exceed max gas
    function invariant_ZG_G1() public leap {
        require(
            _zeroGovernorHandler.gasViolations() == 0,
            "Gas Invariant ZG_G1"
        );
    }
}
