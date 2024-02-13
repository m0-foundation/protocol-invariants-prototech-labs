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

/* solhint-disable no-global-import */
import "../../../lib/ttg/src/DistributionVault.sol";
import "../../../lib/ttg/src/EmergencyGovernor.sol";
import "../../../lib/ttg/src/EmergencyGovernorDeployer.sol";
import "../../../lib/ttg/src/PowerBootstrapToken.sol";
import "../../../lib/ttg/src/PowerToken.sol";
import "../../../lib/ttg/src/PowerTokenDeployer.sol";
import "../../../lib/ttg/src/Registrar.sol";
import "../../../lib/ttg/src/StandardGovernor.sol";
import "../../../lib/ttg/src/StandardGovernorDeployer.sol";
import "../../../lib/ttg/src/ZeroGovernor.sol";
import "../../../lib/ttg/src/ZeroToken.sol";
import "../../../lib/ttg/src/abstract/interfaces/IBatchGovernor.sol";

import "../../../lib/ttg/src/libs/PureEpochs.sol";

import "../../../lib/ttg/src/abstract/interfaces/IThresholdGovernor.sol";

import "../../../lib/ttg/script/DeployBase.s.sol";

import "../../../lib/ttg/test/utils/Mocks.sol";
import "../../../lib/ttg/test/utils/ERC20ExtendedHarness.sol";
/* solhint-enable no-global-import */
