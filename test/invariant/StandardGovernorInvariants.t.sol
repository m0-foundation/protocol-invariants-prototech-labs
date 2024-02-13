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
    StandardGovernorHandler,
    RegistrarGovernorHandler,
    ThresholdGovernorHandler,
    BatchGovernorHandler
} from "./handlers/StandardGovernorHandler.sol";

import {
    MockERC20,
    MockPowerToken,
    MockZeroToken,
    MockRegistrar,
    StandardGovernor,
    Registrar
} from "./lib/Ttg.sol";

contract InvariantMockRegistrar is MockRegistrar {
    function setKey(bytes32 key, bytes32 value) external view {}
}

contract StandardGovernorInvariants is BaseInvariants, BaseMZeroInvariants {
    StandardGovernorHandler public _standardGovernorHandler;

    uint256 internal _maxTotalZeroRewardPerActiveEpoch = 5 * 10**12;

    function setUp() public virtual {
        if (!_integration) {
            MockERC20 _cashToken            = new MockERC20();
            MockPowerToken _mockPowerToken  = new MockPowerToken();
            MockZeroToken _mockZeroToken    = new MockZeroToken();
            MockRegistrar _mockRegistrar    = new InvariantMockRegistrar();

            _powerToken.addr = address(_mockPowerToken);
            _zeroToken.addr  = address(_mockZeroToken);
            _registrar.addr  = address(_mockRegistrar);

            standardGovernor = new StandardGovernor(
                _powerToken.addr,
                _emergencyGovernor.addr,
                _zeroGovernor.addr,
                address(_cashToken),
                _registrar.addr,
                _distributionVault.addr,
                _zeroToken.addr,
                _standardProposalFee,
                _maxTotalZeroRewardPerActiveEpoch
            );
        }

        bytes4[] memory validCallDatas = new bytes4[](5);
        validCallDatas[0] = StandardGovernor.addToList.selector;
        validCallDatas[1] = StandardGovernor.removeFromList.selector;
        validCallDatas[2] = StandardGovernor.removeFromAndAddToList.selector;
        validCallDatas[3] = StandardGovernor.setKey.selector;
        validCallDatas[4] = StandardGovernor.setProposalFee.selector;

        _standardGovernorHandler = new StandardGovernorHandler(
            address(this),
            address(standardGovernor),
            validCallDatas
        );

        if (!_integration) {
            _standardGovernorHandler.init(NUM_OF_ACTORS);
        } else {
            _standardGovernorHandler.init(_actors, _receivers);
        }

        bytes4[] memory selectors = new bytes4[](18);
        selectors[0]  = ThresholdGovernorHandler.execute.selector;
        selectors[1]  = ThresholdGovernorHandler.propose.selector;
        selectors[2]  = StandardGovernorHandler.setCashToken.selector;
        selectors[3]  = StandardGovernorHandler.sendProposalFeeToVault.selector;
        selectors[4]  = StandardGovernorHandler.setProposalFee.selector;
        selectors[5]  = RegistrarGovernorHandler.addToList.selector;
        selectors[6]  = RegistrarGovernorHandler.removeFromList.selector;
        selectors[7]  = RegistrarGovernorHandler.removeFromAndAddToList.selector;
        selectors[8]  = RegistrarGovernorHandler.setKeyBytes32.selector;
        selectors[9]  = RegistrarGovernorHandler.setKeyUint256.selector;
        selectors[10] = RegistrarGovernorHandler.setKeyAddress.selector;
        selectors[11] = BatchGovernorHandler.castVote.selector;
        selectors[12] = BatchGovernorHandler.castVotes.selector;
        selectors[13] = BatchGovernorHandler.castVoteWithReason.selector;
        selectors[14] = BatchGovernorHandler.castVoteBySigVRS.selector;
        selectors[15] = BatchGovernorHandler.castVoteBySigSignature.selector;
        selectors[16] = BatchGovernorHandler.castVotesBySigVRS.selector;
        selectors[17] = BatchGovernorHandler.castVotesBySigSignature.selector;

        targetSelector(FuzzSelector({
            addr: address(_standardGovernorHandler),
            selectors: selectors
        }));

        targetContract(address(_standardGovernorHandler));
    }

    //
    // metadata invariants
    //
    function invariant_SG_M1() public leap {
        require(
            standardGovernor.emergencyGovernor() == _emergencyGovernor.addr, "Metadata Invariant M1"
        );
    }

    function invariant_SG_M2() public leap {
        require(
            standardGovernor.vault() == _distributionVault.addr, "Metadata Invariant M2"
        );
    }

    function invariant_SG_M3() public leap {
        require(
            standardGovernor.zeroGovernor() == _zeroGovernor.addr, "Metadata Invariant M3"
        );
    }

    function invariant_SG_M4() public leap {
        require(
            standardGovernor.zeroToken() == _zeroToken.addr, "Metadata Invariant M4"
        );
    }

    function invariant_SG_M5() public leap {
        require(
            standardGovernor.maxTotalZeroRewardPerActiveEpoch() == _maxTotalZeroRewardPerActiveEpoch, "Metadata Invariant M5"
        );
    }

    function invariant_SG_M6() public leap {
        require(
            standardGovernor.registrar() == _registrar.addr, "Metadata Invariant M6"
        );
    }

    function invariant_SG_M7() public leap {
        require(
            standardGovernor.voteToken() == _powerToken.addr, "Metadata Invariant M7"
        );
    }

    //
    // Authorization Invariants
    //
    function invariant_SG_Z1() public leap {
        require(
            _standardGovernorHandler.nonZeroGovernorViolationCount() == 0,
            "Authorization Invariant SG_Z1"
        );
    }

    // Functions don't exceed max gas
    function invariant_SG_G1() public leap {
        require(
            _standardGovernorHandler.gasViolations() == 0,
            "Gas Invariant SG_G1"
        );
    }
}
