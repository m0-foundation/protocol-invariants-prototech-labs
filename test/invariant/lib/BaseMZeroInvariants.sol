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

pragma solidity 0.8.23;

import { BaseInvariants } from "./BaseInvariants.sol";
import { InvariantUtils } from "../lib/InvariantUtils.sol";

import {
    MinterGateway,
    MockMToken,
    MockRateModel,
    MockTTGRegistrar,
    MToken,
    TTGRegistrarReader
} from "../lib/Protocol.sol";

import {
    MockEmergencyGovernor,
    MockEmergencyGovernorDeployer,
    MockStandardGovernorDeployer,
    MockRegistrar,
    MockStandardGovernor,
    MockPowerTokenDeployer,
    MockBootstrapToken,
    MockEmergencyGovernor,
    MockZeroGovernor,
    DistributionVault,
    ERC20ExtendedHarness,
    PowerToken,
    Registrar,
    StandardGovernor,
    EmergencyGovernor,
    ZeroGovernor,
    ZeroToken
} from "../lib/Ttg.sol";

contract BaseMZeroInvariants is BaseInvariants {
    InvariantUtils.Actor public deployer;

    InvariantUtils.Actor internal _zero;
    InvariantUtils.Actor internal _registrar;
    InvariantUtils.Actor internal _standardGovernor;
    InvariantUtils.Actor internal _emergencyGovernor;
    InvariantUtils.Actor internal _zeroGovernor;
    InvariantUtils.Actor internal _powerToken;
    InvariantUtils.Actor internal _zeroToken;
    InvariantUtils.Actor internal _distributionVault;
    InvariantUtils.Actor internal _minterGateway;
    InvariantUtils.Actor internal _mToken;

    bool internal _integration;
    bool internal _realRegistrar;

    DistributionVault   public distributionVault;
    EmergencyGovernor   public emergencyGovernor;
    MinterGateway       public minterGateway;
    MToken              public mToken;
    PowerToken          public powerToken;
    Registrar           public registrar;
    StandardGovernor    public standardGovernor;
    ZeroGovernor        public zeroGovernor;
    ZeroToken           public zeroToken;

    address[] internal _initialPowerAccounts;
    uint256[] internal _initialPowerBalances;
    address[] internal _initialZeroAccounts;
    uint256[] internal _initialZeroBalances;

    uint16 internal _emergencyProposalThresholdRatio = 9_000; // 90%
    uint16 internal _zeroProposalThresholdRatio = 6_000; // 60%

    ERC20ExtendedHarness internal _cashToken1 = new ERC20ExtendedHarness("Cash Token 1", "CASH1", 18);
    ERC20ExtendedHarness internal _cashToken2 = new ERC20ExtendedHarness("Cash Token 1", "CASH2", 6);

    address[] internal _allowedCashTokens = [address(_cashToken1), address(_cashToken2)];

    uint256 internal _standardProposalFee = 1_000;

    address internal _earnerRateModel = address(new MockRateModel());
    address internal _minterRateModel = address(new MockRateModel());

    // TTG mocks
    MockBootstrapToken internal _mockBootstrapToken;
    MockBootstrapToken internal _mockZeroToken;
    MockBootstrapToken internal _mockPowerToken;
    MockEmergencyGovernor internal _mockEmergencyGovernor;
    MockEmergencyGovernorDeployer internal _mockEmergencyGovernorDeployer;
    MockPowerTokenDeployer internal _mockPowerTokenDeployer;
    MockRegistrar internal _mockRegistrar;
    MockStandardGovernor internal _mockStandardGovernor;
    MockStandardGovernorDeployer internal _mockStandardGovernorDeployer;
    MockZeroGovernor internal _mockZeroGovernor;

    // Protocol mocks
    MockMToken internal _mockMToken;
    MockTTGRegistrar internal _mockTTGRegistrar;

    constructor() {
        (deployer.addr, deployer.key) = makeAddrAndKey("Deployer");
        (_zero.addr, _zero.key) = makeAddrAndKey("Zero Address");
        (_registrar.addr, _registrar.key) = makeAddrAndKey("Registrar");
        (_standardGovernor.addr, _standardGovernor.key) = makeAddrAndKey("StandardGovernor");
        (_emergencyGovernor.addr, _emergencyGovernor.key) = makeAddrAndKey("EmergencyGovernor");
        (_zeroGovernor.addr, _zeroGovernor.key) = makeAddrAndKey("ZeroGovernor");
        (_powerToken.addr, _powerToken.key) = makeAddrAndKey("PowerToken");
        (_zeroToken.addr, _zeroToken.key) = makeAddrAndKey("ZeroToken");
        (_distributionVault.addr, _distributionVault.key) = makeAddrAndKey("DistributionVault");
        (_minterGateway.addr, _minterGateway.key) = makeAddrAndKey("MinterGateway");
        (_mToken.addr, _mToken.key) = makeAddrAndKey("MToken");
    }

    function integration() external view returns (bool) {
        return _integration;
    }

    function realRegistrar() external view returns (bool) {
        return _realRegistrar;
    }
}
