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
    Registrar,
    StandardGovernor,
    EmergencyGovernor,
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


            // zero actor
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

        // we need the StandardGovernor
        standardGovernor = StandardGovernor(registrar.standardGovernor());
        _standardGovernor.addr = address(standardGovernor);
        vm.prank(_standardGovernor.addr);
        zeroToken.mint(_standardGovernor.addr, 1e12);
        _receivers.push(_standardGovernor);

        // we need the EmergencyGovernor
        emergencyGovernor = EmergencyGovernor(registrar.emergencyGovernor());
        _emergencyGovernor.addr = address(emergencyGovernor);
        vm.prank(_standardGovernor.addr);
        zeroToken.mint(_emergencyGovernor.addr, 1e12);
        _receivers.push(_emergencyGovernor);

        // we need the ZeroGovernor
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
}
