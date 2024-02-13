pragma solidity ^0.8.23;

// solhint-disable-next-line no-console, no-global-import
import "forge-std/console.sol";
import { BaseMZeroInvariants } from "./lib/BaseMZeroInvariants.sol";
import { PowerTokenInvariants } from "./PowerTokenInvariants.t.sol";
import { ZeroTokenInvariants } from "./ZeroTokenInvariants.t.sol";
import { DistributionVaultInvariants } from "./DistributionVaultInvariants.t.sol";
import { StandardGovernorInvariants } from "./StandardGovernorInvariants.t.sol";
import { EmergencyGovernorInvariants } from "./EmergencyGovernorInvariants.t.sol";
import { ZeroGovernorInvariants } from "./ZeroGovernorInvariants.t.sol";
import { RegistrarInvariants } from "./RegistrarInvariants.t.sol";
import { InvariantUtils, IToken } from "./lib/InvariantUtils.sol";

import {
    DeployBase,
    DistributionVault,
    PowerToken,
    PowerTokenDeployer,
    Registrar,
    StandardGovernor,
    StandardGovernorDeployer,
    EmergencyGovernor,
    EmergencyGovernorDeployer,
    ZeroGovernor,
    ZeroToken
} from "./lib/Ttg.sol";


contract TTGInvariants is
    BaseMZeroInvariants,
    PowerTokenInvariants,
    ZeroTokenInvariants,
    DistributionVaultInvariants,
    StandardGovernorInvariants,
    EmergencyGovernorInvariants,
    ZeroGovernorInvariants,
    RegistrarInvariants
{

    DeployBase public deployTTG;

    function setUp() public virtual override(
        PowerTokenInvariants,
        ZeroTokenInvariants,
        DistributionVaultInvariants,
        StandardGovernorInvariants,
        EmergencyGovernorInvariants,
        ZeroGovernorInvariants,
        RegistrarInvariants
    ) {
        InvariantUtils.Actor memory guy;

        // If not called from MZeroInvariants, we need to set up the actors
        if (_actors.length == 0) {
            vm.warp(1_663_224_162);

            for (uint256 i = 0; i < NUM_OF_ACTORS; i++) {
                (guy.addr, guy.key) = makeAddrAndKey(
                    string(abi.encodePacked("Actor", vm.toString(i)))
                );
                _initialPowerAccounts.push(guy.addr);
                _initialPowerBalances.push(1e6);
                _initialZeroAccounts.push(guy.addr);
                _initialZeroBalances.push(1e12);
                _actors.push(guy);
                _receivers.push(guy);
            }

            // deployer actor
            _initialPowerAccounts.push(deployer.addr);
            _initialPowerBalances.push(0);
            _initialZeroAccounts.push(deployer.addr);
            _initialZeroBalances.push(0);
            _actors.push(deployer);
            _receivers.push(deployer);

            // zero actor
            _initialPowerAccounts.push(_zero.addr);
            _initialPowerBalances.push(0);
            _initialZeroAccounts.push(_zero.addr);
            _initialZeroBalances.push(0);
            _receivers.push(_zero);
        }

        deployTTG = new DeployBase();

        _registrar.addr = deployTTG.deploy(
            deployer.addr,
            _initialPowerAccounts,
            _initialPowerBalances,
            _initialZeroAccounts,
            _initialZeroBalances,
            _standardProposalFee,
            _allowedCashTokens
        );
        registrar = Registrar(_registrar.addr);
        _realRegistrar = true;

        // TODO:
        // one downside with this ordering of operations is that we cannot
        // easily give the following actos a balance of power tokens as they
        // would need to have been in the _initialPowerAccounts() array. One
        // way to solve this is to add unused addresses to the array and then
        // transfer the power tokens to the actors we want to have them.
        // PowerBootstrapToken might also solve this problem.

        // zero token
        zeroToken = ZeroToken(registrar.zeroToken());
        _zeroToken.addr = address(zeroToken);
        vm.prank(registrar.standardGovernor());
        zeroToken.mint(_zeroToken.addr, 1e12);
        _receivers.push(_zeroToken);

        // registrar
        vm.prank(registrar.standardGovernor());
        zeroToken.mint(_registrar.addr, 1e12);
        _receivers.push(_registrar);

        // zero actor
        vm.prank(registrar.standardGovernor());
        zeroToken.mint(_zero.addr, 1e12);

        // deployer actor
        vm.prank(registrar.standardGovernor());
        zeroToken.mint(deployer.addr, 1e12);

        // TODO make sure the contract deployer actors are not in the msgSender list
        // power token deployer
        powerTokenDeployer = PowerTokenDeployer(registrar.powerTokenDeployer());
        _powerTokenDeployer.addr = address(powerTokenDeployer);
        vm.prank(registrar.standardGovernor());
        zeroToken.mint(_powerTokenDeployer.addr, 1e12);
        _actors.push(_powerTokenDeployer);

        // standard governeor deployer
        standardGovernorDeployer = StandardGovernorDeployer(registrar.standardGovernorDeployer());
        _standardGovernorDeployer.addr = address(standardGovernorDeployer);
        vm.prank(registrar.standardGovernor());
        zeroToken.mint(_standardGovernorDeployer.addr, 1e12);
        _actors.push(_standardGovernorDeployer);

        // emergency governeor deployer
        emergencyGovernorDeployer = EmergencyGovernorDeployer(registrar.emergencyGovernorDeployer());
        _emergencyGovernorDeployer.addr = address(emergencyGovernorDeployer);
        vm.prank(registrar.standardGovernor());
        zeroToken.mint(_emergencyGovernorDeployer.addr, 1e12);
        _actors.push(_emergencyGovernorDeployer);

        // power token
        powerToken = PowerToken(registrar.powerToken());
        _powerToken.addr = address(powerToken);
        vm.prank(registrar.standardGovernor());
        zeroToken.mint(_powerToken.addr, 1e12);
        _receivers.push(_powerToken);

        // distribution vault
        distributionVault = DistributionVault(registrar.vault());
        _distributionVault.addr = address(distributionVault);
        vm.prank(registrar.standardGovernor());
        zeroToken.mint(_distributionVault.addr, 1e12);
        _receivers.push(_distributionVault);

        // StandardGovernor
        standardGovernor = StandardGovernor(registrar.standardGovernor());
        _standardGovernor.addr = address(standardGovernor);
        vm.prank(_standardGovernor.addr);
        zeroToken.mint(_standardGovernor.addr, 1e12);
        _receivers.push(_standardGovernor);

        // EmergencyGovernor
        emergencyGovernor = EmergencyGovernor(registrar.emergencyGovernor());
        _emergencyGovernor.addr = address(emergencyGovernor);
        vm.prank(_standardGovernor.addr);
        zeroToken.mint(_emergencyGovernor.addr, 1e12);
        _receivers.push(_emergencyGovernor);

        // ZeroGovernor
        zeroGovernor = ZeroGovernor(registrar.zeroGovernor());
        _zeroGovernor.addr = address(zeroGovernor);
        vm.prank(_standardGovernor.addr);
        zeroToken.mint(_zeroGovernor.addr, 1e12);
        _receivers.push(_zeroGovernor);

        // flag to the other modules that we're running in integration mode
        _integration = true;

        PowerTokenInvariants.setUp();
        ZeroTokenInvariants.setUp();
        DistributionVaultInvariants.setUp();
        StandardGovernorInvariants.setUp();
        EmergencyGovernorInvariants.setUp();
        ZeroGovernorInvariants.setUp();
        RegistrarInvariants.setUp();

        _emergencyGovernorHandler._initRateModels(address(registrar));
        _standardGovernorHandler._initRateModels(address(registrar));
    }

    function poke(address standardGovernor_, address emergencyGovernor_, address powerToken_) external override {
        // new standard governor
        standardGovernor = StandardGovernor(standardGovernor_);
        _standardGovernor.addr = address(standardGovernor);
        _actors.push(_standardGovernor);
        _standardGovernorHandler.addActor(_standardGovernor);
        _standardGovernorHandler.setGovernor(_standardGovernor.addr);
        excludeContract(_standardGovernor.addr);

        // new emergency governor
        emergencyGovernor = EmergencyGovernor(emergencyGovernor_);
        _emergencyGovernor.addr = address(emergencyGovernor);
        _actors.push(_emergencyGovernor);
        _emergencyGovernorHandler.addActor(_emergencyGovernor);
        _emergencyGovernorHandler.setGovernor(_emergencyGovernor.addr);
        excludeContract(_emergencyGovernor.addr);

        // new power token
        powerToken = PowerToken(powerToken_);
        _powerToken.addr = address(powerToken);
        _actors.push(_powerToken);
        _powerTokenHandler.addActor(_powerToken);
        _powerTokenHandler.setPowerToken(_powerToken.addr);
        excludeContract(_powerToken.addr);
    }

    // Invariant harness sanity check
    function invariant_TTG_T1() public leap {
        uint256 timestamp = block.timestamp;
        require(timestamp == currentTimestamp, "Invariant TTG_T1");
        require(timestamp == _distributionVaultHandler.timestamp(), "Invariant TTG_T1_DV");
        require(timestamp == _zeroTokenHandler.timestamp(), "Invariant TTG_T1_ZT");
        require(timestamp == _powerTokenHandler.timestamp(), "Invariant TTG_T1_PT");
        //require(timestamp == _registrarHandler.timestamp(), "Invariant TTG_T1_R");
        //require(timestamp == _mTokenHandler.timestamp(), "Invariant TTG_T1_M");
        //require(timestamp == _standardGovernorHandler.timestamp(), "Invariant TTG_T1_SG");
        //require(timestamp == _emergencyGovernorHandler.timestamp(), "Invariant TTG_T1_EG");
        //require(timestamp == _zeroGovernorHandler.timestamp(), "Invariant TTG_T1_ZG");
        //require(timestamp == _minterGatewayHandler.timestamp(), "Invariant TTG_T1_MG");
    }

    function invariant_TTG_M1() public leap {
        require(
            _standardGovernor.addr == registrar.standardGovernor(),
            "Invariant TTG_M1"
        );
    }

    function invariant_TTG_M2() public leap {
        require(
            _emergencyGovernor.addr == registrar.emergencyGovernor(),
            "Invariant TTG_M2"
        );
    }

    function invariant_TTG_M3() public leap {
        require(
            _powerToken.addr == registrar.powerToken(),
            "Invariant TTG_M3"
        );
    }
}
