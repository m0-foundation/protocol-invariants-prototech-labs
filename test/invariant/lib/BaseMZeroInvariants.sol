// SPDX-License-Identifier: UNLICENSED

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
    MockPowerToken,
    MockBootstrapToken,
    MockEmergencyGovernor,
    MockZeroGovernor,
    MockZeroToken,
    DistributionVault,
    ERC20ExtendedHarness,
    PowerToken,
    PowerTokenDeployer,
    Registrar,
    StandardGovernor,
    StandardGovernorDeployer,
    EmergencyGovernor,
    EmergencyGovernorDeployer,
    ZeroGovernor,
    ZeroToken
} from "../lib/Ttg.sol";

contract BaseMZeroInvariants is BaseInvariants {
    InvariantUtils.Actor public deployer;

    InvariantUtils.Actor internal _zero;
    InvariantUtils.Actor internal _registrar;
    InvariantUtils.Actor internal _standardGovernor;
    InvariantUtils.Actor internal _standardGovernorDeployer;
    InvariantUtils.Actor internal _emergencyGovernor;
    InvariantUtils.Actor internal _emergencyGovernorDeployer;
    InvariantUtils.Actor internal _zeroGovernor;
    InvariantUtils.Actor internal _powerToken;
    InvariantUtils.Actor internal _powerTokenDeployer;
    InvariantUtils.Actor internal _zeroToken;
    InvariantUtils.Actor internal _distributionVault;
    InvariantUtils.Actor internal _minterGateway;
    InvariantUtils.Actor internal _mToken;

    bool internal _integration;
    bool internal _realRegistrar;

    DistributionVault           public distributionVault;
    EmergencyGovernor           public emergencyGovernor;
    EmergencyGovernorDeployer   public emergencyGovernorDeployer;
    MinterGateway               public minterGateway;
    MToken                      public mToken;
    PowerToken                  public powerToken;
    PowerTokenDeployer          public powerTokenDeployer;
    Registrar                   public registrar;
    StandardGovernor            public standardGovernor;
    StandardGovernorDeployer    public standardGovernorDeployer;
    ZeroGovernor                public zeroGovernor;
    ZeroToken                   public zeroToken;

    address[] internal _initialPowerAccounts;
    uint256[] internal _initialPowerBalances;
    address[] internal _initialZeroAccounts;
    uint256[] internal _initialZeroBalances;

    uint16 internal _emergencyProposalThresholdRatio = 9_000; // 90%
    uint16 internal _zeroProposalThresholdRatio = 6_000; // 60%

    ERC20ExtendedHarness internal _cashToken1 = new ERC20ExtendedHarness("Cash Token 1", "CASH1", 18);
    ERC20ExtendedHarness internal _cashToken2 = new ERC20ExtendedHarness("Cash Token 2", "CASH2", 6);
    ERC20ExtendedHarness internal _cashToken3 = new ERC20ExtendedHarness("Cash Token 3", "CASH3", 0);

    address[] internal _allowedCashTokens = [address(_cashToken1), address(_cashToken2), address(_cashToken3)];

    uint256 internal _standardProposalFee = 1_000;

    address internal _earnerRateModel = address(new MockRateModel());
    address internal _minterRateModel = address(new MockRateModel());

    // TTG mocks
    MockBootstrapToken internal _mockBootstrapToken;
    MockPowerToken internal _mockPowerToken;
    MockZeroToken internal _mockZeroToken;
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
        (_standardGovernorDeployer.addr, _standardGovernorDeployer.key) = makeAddrAndKey("StandardGovernorDeployer");
        (_emergencyGovernor.addr, _emergencyGovernor.key) = makeAddrAndKey("EmergencyGovernor");
        (_emergencyGovernorDeployer.addr, _emergencyGovernorDeployer.key) = makeAddrAndKey("EmergencyGovernorDeployer");
        (_zeroGovernor.addr, _zeroGovernor.key) = makeAddrAndKey("ZeroGovernor");
        (_powerToken.addr, _powerToken.key) = makeAddrAndKey("PowerToken");
        (_powerTokenDeployer.addr, _powerTokenDeployer.key) = makeAddrAndKey("PowerTokenDeployer");
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
