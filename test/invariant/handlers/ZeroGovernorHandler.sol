
pragma solidity ^0.8.23;

import "./abstract/ThresholdGovernorHandler.sol";
import {
    IEmergencyGovernorDeployer,
    IPowerTokenDeployer,
    IStandardGovernorDeployer,
    PowerToken,
    StandardGovernor,
    ZeroGovernor,
    ZeroToken
} from "../lib/Ttg.sol";

contract ZeroGovernorHandler is ThresholdGovernorHandler {
    uint256 public resetCount;

    constructor(
        address _testContract,
        address _governor,
        bytes4[] memory validCallData_,
        address[] memory _cashTokens
    ) BaseHandler(_testContract)
      ThresholdGovernorHandler(validCallData_)
      BatchGovernorHandler(_governor) {
        cashTokens = _cashTokens;
    }

    function init(
        uint256 _numOfActors
    ) external {
        addActors(_numOfActors);
        zero = addActor(address(0), "zero");
        token = addActor(governor, "ZeroGovernor");

        validateActors();
    }

    function init(
        InvariantUtils.Actor[] memory _actors,
        InvariantUtils.Actor[] memory _receivers
    ) external {
        for(uint256 i = 0; i < _receivers.length; i++) {
            actors.push(_receivers[i]);

            if (_receivers[i].addr == governor) {
                // we want the zeroGovernor to be able to call itself
                msgSenders.push(_receivers[i]);
            }
        }

        validateActors(actors);

        for(uint256 i = 0; i < _actors.length; i++) {
            msgSenders.push(_actors[i]);
        }

        validateActors(msgSenders);
    }

    //
    // ZeroGovernor.sol - Testable functions
    //

    function resetToPowerHolders(
        uint256 _actorIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint48  lastEpoch = ZeroGovernor(governor).clock() - 1;
        uint256 pastTotalSupply = PowerToken(
            StandardGovernor(ZeroGovernor(governor).standardGovernor()).voteToken()
        ).pastTotalSupply(lastEpoch);
        if (!testContract.integration() ||
            resetCount > 5 ||
            pastTotalSupply == 0            // TODO: remove guard to test regression for Issue 145
        ) {
            return;
        }
        startGas();
        try ZeroGovernor(governor).resetToPowerHolders() {
            stopGas();
            resetCount++;
            testContract.poke(
                ZeroGovernor(governor).standardGovernor(),
                ZeroGovernor(governor).emergencyGovernor(),
                StandardGovernor(ZeroGovernor(governor).standardGovernor()).voteToken()
            );
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != governor) addExpectedError("NotSelf()");
            addExpectedErrorBytes32(0x0);
            expectedError(_err);
        }
    }

    function resetToZeroHolders(
        uint256 _actorIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint48  lastEpoch = ZeroGovernor(governor).clock() - 1;
        uint256 pastTotalSupply = ZeroToken(ZeroGovernor(governor).voteToken()).pastTotalSupply(lastEpoch);
        if (!testContract.integration() ||
            resetCount > 5 ||
            pastTotalSupply == 0            // TODO: remove guard to test regression for Issue 145
        ) {
            return;
        }
        startGas();
        try ZeroGovernor(governor).resetToZeroHolders() {
            stopGas();
            resetCount++;
            testContract.poke(
                ZeroGovernor(governor).standardGovernor(),
                ZeroGovernor(governor).emergencyGovernor(),
                StandardGovernor(ZeroGovernor(governor).standardGovernor()).voteToken() 
            );
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != governor) addExpectedError("NotSelf()");
            addExpectedErrorBytes32(0x0);
            expectedError(_err);
        }
    }

    function setCashToken(
        uint256 _actorIndex,
        uint256 _newCashToken,
        uint256 _newProposalFee
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, governor, 33) {
        _newCashToken  = bound(_newCashToken, 0, cashTokens.length - 1);

        startGas();
        try ZeroGovernor(governor).setCashToken(
            cashTokens[_newCashToken],
            _newProposalFee
        ) {
            stopGas();
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != governor) addExpectedError("NotSelf()");
            addExpectedError("InvalidCashToken()");
            expectedError(_err);
        }
    }

    function setEmergencyProposalThresholdRatio(
        uint256 _actorIndex,
        uint16  _newThresholdRatio
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        //  min 271, max 10000, range outside to expect some errors
        _newThresholdRatio = uint16(bound(_newThresholdRatio, 0, 11000));

        startGas();
        try ZeroGovernor(governor).setEmergencyProposalThresholdRatio(_newThresholdRatio) {
            stopGas();
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != governor) addExpectedError("NotSelf()");
            if (_newThresholdRatio < 271 ||
                _newThresholdRatio > 10000) {
                addExpectedError("InvalidThresholdRatio(uint256,uint256,uint256)");
            }
            addExpectedErrorBytes32(0x0);
            expectedError(_err);
        }
    }

    function setZeroProposalThresholdRatio(
        uint256 _actorIndex,
        uint16  _newThresholdRatio
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        //  min 271, max 10000, range outside to expect some errors
        _newThresholdRatio = uint16(bound(_newThresholdRatio, 0, 11000));

        startGas();
        try ZeroGovernor(governor).setZeroProposalThresholdRatio(_newThresholdRatio) {
            stopGas();
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != governor) addExpectedError("NotSelf()");
            if (_newThresholdRatio < 271 ||
                _newThresholdRatio > 10000) {
                addExpectedError("InvalidThresholdRatio(uint256,uint256,uint256)");
            }
            addExpectedErrorBytes32(0x0);
            expectedError(_err);
        }
    }

}
