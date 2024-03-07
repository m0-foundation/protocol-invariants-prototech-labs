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

import "./base/BaseHandler.sol";
import {
    DistributionVault,
    PowerToken,
    ZeroToken
} from "../lib/Ttg.sol";

contract DistributionVaultHandler is BaseHandler {
    DistributionVault public distributionVault;

    PowerToken  public powerToken;
    ZeroToken   public zeroToken;

    // Defined in PureEpochs.sol
    uint40 internal constant _EPOCH_PERIOD = 15 days;

    uint256 public totalClaimed;
    uint256 public totalDistributed;
    uint256 public lastTokenBalance; // Token1
    uint256 public remainingClaimable;
    uint256 public remainingHasClaimed;

    constructor(
        address _testContract,
        DistributionVault _distributionVault,
        ZeroToken _zeroToken,
        PowerToken _powerToken
    ) BaseHandler(_testContract) {
        distributionVault = _distributionVault;
        zeroToken         = _zeroToken;
        powerToken        = _powerToken;
    }

    function init(
        uint256 _numOfActors
    ) external {
        addActors(_numOfActors);
        zero  = addActor(address(0), "zero");
        token = addActor(address(distributionVault), "DistributionVault");
        validateActors();
    }

    function init(
        InvariantUtils.Actor[] memory _actors,
        InvariantUtils.Actor[] memory _receivers
    ) external {
        for(uint256 i = 0; i < _actors.length; i++) {
            msgSenders.push(_actors[i]);
        }

        validateActors(msgSenders);

        for(uint256 i = 0; i < _receivers.length; i++) {
            actors.push(_receivers[i]);
        }

        validateActors(actors);
    }

    function _expectDivisionBy0(uint256 startEpoch, uint256 endEpoch) internal view returns (bool) {
        if (startEpoch > endEpoch) return false;
        if (endEpoch >= distributionVault.clock()) return false;
        uint256[] memory totalSupplies = zeroToken.pastTotalSupplies(startEpoch, endEpoch);
        for(uint256 i = 0; i < totalSupplies.length; i++) {
            // if totalSupply is 0 we will get a division by zero error
            if(totalSupplies[i] == 0) return true;
        }
        return false;
    }

    function _getEpochs(uint256 timestamp) internal pure returns (uint256 start, uint256 end) {
        start = uint256(uint16(((timestamp - BASE_TIMESTAMP) / _EPOCH_PERIOD) + 1));
        end = bound(timestamp, 0, start + 2);
    }

    //
    // Testable functions
    //

    // TODO consider adding random successful claim sequences to the fuzzing
    function claim(
        uint256 _actorIndex,
        uint256 _destinationIndex,
        uint256 _startEpoch,
        uint256 _endEpoch
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint256 destinationIndex = bound(_destinationIndex, 0, actors.length - 1);
        // actual ZeroToken safeCasts these to uint16 in pastBalancesOf and pastTotalSupplies
        (_startEpoch, _endEpoch) = _getEpochs(bound(_actorIndex, BASE_TIMESTAMP, BASE_TIMESTAMP + 2 days));

        startGas();
        try distributionVault.claim(
            address(powerToken), // token
            _startEpoch,
            _endEpoch,
            actors[destinationIndex].addr // destination
        ) returns (uint256 claimed) {
            stopGas();
            // success
            uint256 claimableAfter = distributionVault.getClaimable(
                address(powerToken),
                actor.addr,
                _startEpoch,
                _endEpoch
            );
            remainingClaimable += claimableAfter;
            for(uint256 epoch = _startEpoch; epoch < _endEpoch + 1; epoch++) {
                bool hasClaimed = distributionVault.hasClaimed(
                    address(powerToken),
                    epoch,
                    actor.addr
                );
                if (!hasClaimed) remainingHasClaimed += 1;
            }
            totalClaimed += claimed;
            totalDistributed -= claimed;
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actors[destinationIndex].addr == address(0)) {
                addExpectedError("InvalidDestinationAddress()");
            }
            if (isVotingEpoch()) {
                addExpectedError("TransferFailed()");
            }
            if (powerToken.balanceOf(address(powerToken)) == 0) addExpectedError("TransferFailed()");
            if(_endEpoch >= distributionVault.clock()) addExpectedError("NotPastTimepoint(uint256,uint256)");
            if(_startEpoch > _endEpoch) {
                addExpectedError("StartEpochAfterEndEpoch(uint256,uint256)");
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            } else {
                // if totalSupply is 0 we will get a division by zero error
                if(_expectDivisionBy0(_startEpoch, _endEpoch)) addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x12)));
            }
            // TransferFailed();
            expectedError(_err);
        }
    }

    function claimBySig(
        uint256 _actorIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint256 accountIndex = bound(_actorIndex, 0, actors.length / 2);

        // actual ZeroToken safeCasts these to uint16 in pastBalancesOf and pastTotalSupplies
        (uint256 _startEpoch, uint256 _endEpoch) = _getEpochs(bound(_actorIndex, BASE_TIMESTAMP, BASE_TIMESTAMP + 2 days));

        // build signature
        InvariantUtils.Signature memory sign;
        {
            bytes32 digest = distributionVault.getClaimDigest(
                address(powerToken),
                _startEpoch,
                _endEpoch,
                actors[bound(_actorIndex, accountIndex, actors.length - 1)].addr, // destination
                distributionVault.nonces(actors[accountIndex].addr),
                _actorIndex // stand-in for deadline
            );

            (sign.v, sign.r, sign.s) = vm.sign(actors[accountIndex].key, digest);
            // 10% of the time release a signature chaos monkey
            if (bound(_actorIndex, 0, 9) == 0)  {
                sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
                sign.s = bytes32(_actorIndex);
            }
        }

        startGas();
        try distributionVault.claimBySig(
            actors[accountIndex].addr,
            address(powerToken), // token
            _startEpoch,
            _endEpoch,
            actors[bound(_actorIndex, accountIndex, actors.length - 1)].addr, // destination
            _actorIndex, // stand-in for deadline
            abi.encodePacked(sign.r, sign.s, sign.v) // signature
        ) returns (uint256 claimed) {
            stopGas();
            // success
            uint256 claimableAfter = distributionVault.getClaimable(
                address(powerToken),
                actor.addr,
                _startEpoch,
                _endEpoch
            );
            remainingClaimable += claimableAfter;
            for(uint256 epoch = _startEpoch; epoch < _endEpoch + 1; ++epoch) {
                bool hasClaimed = distributionVault.hasClaimed(
                    address(powerToken),
                    epoch,
                    actors[accountIndex].addr
                );
                if (!hasClaimed) remainingHasClaimed += 1;
            }
            totalClaimed += claimed;
            totalDistributed -= claimed;
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if(isVotingEpoch()) {
                addExpectedError("VoteEpoch()");
                addExpectedError("TransferFailed()");
            }
            if(_endEpoch >= distributionVault.clock()) addExpectedError("NotPastTimepoint(uint256,uint256)");
            if(_startEpoch > _endEpoch) {
                addExpectedError("StartEpochAfterEndEpoch(uint256,uint256)");
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            } else {
                // if totalSupply is 0 we will get a division by zero error
                if(_expectDivisionBy0(_startEpoch, _endEpoch)) addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x12)));
            }
            if (actors[bound(_actorIndex, accountIndex, actors.length - 1)].addr == address(0)) {
                addExpectedError("InvalidDestinationAddress()");
            }
            if (actors[accountIndex].addr == address(0)                 ||
                actors[accountIndex].addr == address(distributionVault) ||
                sign.s == bytes32(_actorIndex)) {
                addExpectedError("SignerMismatch()");
                addExpectedError("InvalidSignatureV()");
                addExpectedError("InvalidSignature()");
                }
            // _actorIndex is a stand-in for deadline
            if(_actorIndex < block.timestamp) addExpectedError("SignatureExpired(uint256,uint256)");
            // TransferFailed();
            expectedError(_err);
        }
    }

    function distribute(
        uint256 _actorIndex,
        uint256 tokenBalance
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        tokenBalance;

        startGas();
        // TODO consider changing this if we can't prove that the only way the distributionVault's
        // token balance changes is through the DistributionVault
        // uint256 previousBalance = powerToken.balanceOf(address(distributionVault));
        // uint256 newBalance = bound(tokenBalance, previousBalance, type(uint256).max);
        // TODO: this hack is broke on the full integration
        // powerToken.setBalance(address(distributionVault), newBalance);
        try distributionVault.distribute(address(powerToken)) returns (uint256 amount) {
            stopGas();
            // success
            totalDistributed += amount;
            lastTokenBalance += amount;
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {

            expectedError(_err);
        }
    }
}
