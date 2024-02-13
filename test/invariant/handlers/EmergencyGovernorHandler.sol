
pragma solidity ^0.8.23;

import "./abstract/RegistrarGovernorHandler.sol";
import { EmergencyGovernor } from "../lib/Ttg.sol";

contract EmergencyGovernorHandler is RegistrarGovernorHandler {
    // EmergencyGovernor public emergencyGovernor;

    InvariantUtils.Actor public zeroGovernor;
    uint16  internal constant MIN_THRESHOLD_RATIO = 271;
    uint256 public   constant ONE                 = 10_000;

    constructor(
        address _testContract,
        address _governor,
        bytes4[] memory validCallData_
    ) BaseHandler(_testContract)
      ThresholdGovernorHandler(validCallData_)
      BatchGovernorHandler(_governor) {}

    function init(
        uint256 _numOfActors
    ) external {
        _initRateModels(EmergencyGovernor(governor).registrar());

        addActors(_numOfActors);
        zero         = addActor(address(0), "zero");
        token        = addActor(governor, "EmergencyGovernor");
        zeroGovernor = addActor(EmergencyGovernor(governor).zeroGovernor(), "zeroGovernor");
        zeroGovernorAddr = zeroGovernor.addr;

        validateActors();
    }

    function init(
        InvariantUtils.Actor[] memory _actors,
        InvariantUtils.Actor[] memory _receivers
    ) external {
        for (uint256 i = 0; i < _receivers.length; i++) {
            actors.push(_receivers[i]);

            if (_receivers[i].addr == governor) {
                // we want the emergencyGovernor to be able to call itself
                msgSenders.push(_receivers[i]);
            }

            if (_receivers[i].addr == EmergencyGovernor(governor).zeroGovernor()) {
                // we want the zeroGovernor to be able to call this too
                msgSenders.push(_receivers[i]);
                zeroGovernor = _receivers[i];
                zeroGovernorAddr = zeroGovernor.addr;
            }
        }

        validateActors(actors);

        for(uint256 i = 0; i < _actors.length; i++) {
            msgSenders.push(_actors[i]);
        }

        validateActors(msgSenders);
    }

    //
    // Testable functions
    //
    function setThresholdRatio(
        uint256 _actorIndex,
        uint16 _newRatio
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, EmergencyGovernor(governor).zeroGovernor(), 50) {

        startGas();
        try EmergencyGovernor(governor).setThresholdRatio(
            _newRatio
        ) {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != EmergencyGovernor(governor).zeroGovernor()) addExpectedError("NotZeroGovernor()");
            if (
                _newRatio > ONE ||
                _newRatio < MIN_THRESHOLD_RATIO
            ) addExpectedError("InvalidThresholdRatio(uint256,uint256,uint256)");
            expectedError(_err);
        }
    }

    function setStandardProposalFee(
        uint256 _actorIndex,
        uint256 _newProposalFee
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        startGas();
        try EmergencyGovernor(governor).setStandardProposalFee(
            _newProposalFee
        ) {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != governor) addExpectedError("NotSelf()");
            expectedError(_err);
        }
    }
}
