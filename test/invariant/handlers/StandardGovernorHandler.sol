
pragma solidity ^0.8.23;
import "./abstract/RegistrarGovernorHandler.sol";
import { InvariantUtils } from "../lib/InvariantUtils.sol";
import { StandardGovernor, BatchGovernor, IGovernor } from "../lib/Ttg.sol";

contract StandardGovernorHandler is RegistrarGovernorHandler {

    InvariantUtils.Actor public zeroGovernor;

    uint256 public nonZeroGovernorViolationCount;

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
        _initRateModels(StandardGovernor(governor).registrar());

        addActors(_numOfActors);
        zero         = addActor(address(0), "zero");
        token        = addActor(governor, "StandardGovernor");
        zeroGovernor = addActor(StandardGovernor(governor).zeroGovernor(), "zeroGovernor");

        validateActors();
    }

    function init(
        InvariantUtils.Actor[] memory _actors,
        InvariantUtils.Actor[] memory _receivers
    ) external {
        for (uint256 i = 0; i < _receivers.length; i++) {
            actors.push(_receivers[i]);

            if (_receivers[i].addr == governor) {
                // we want the standardGovernor to be able to call itself
                msgSenders.push(_receivers[i]);
            }

            if (_receivers[i].addr == StandardGovernor(governor).zeroGovernor()) {
                // we want the zeroGovernor to be able to call this too
                msgSenders.push(_receivers[i]);
                zeroGovernor = _receivers[i];
                zeroGovernorAddr = zeroGovernor.addr;
            }
        }

        validateActors(actors);

        for (uint256 i = 0; i < _actors.length; i++) {
            msgSenders.push(_actors[i]);
        }

        validateActors(msgSenders);
    }

    //
    // Testable functions
    //
    function setCashToken(
        uint256 _actorIndex,
        uint256 _newCashToken,
        uint256 _newProposalFee
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, governor, 33) {
        _newCashToken  = bound(_newCashToken, 0, cashTokens.length - 1);

        startGas();
        try StandardGovernor(governor).setCashToken(
            cashTokens[_newCashToken],
            _newProposalFee
        ) {
            stopGas();
            // success
            if (actor.addr != zeroGovernor.addr) {
                nonZeroGovernorViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if(cashTokens[_newCashToken] == address(0)) addExpectedError("InvalidCashTokenAddress()");
            if(actor.addr != StandardGovernor(governor).zeroGovernor()) addExpectedError("NotZeroGovernor()");
            expectedError(_err);
        }
    }

    function sendProposalFeeToVault(
        uint256 _actorIndex,
        uint256 _proposalId
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint256 proposalVoteStart = _getProposalVoteStart(_proposalId);
        IGovernor.ProposalState proposalState;
        if (proposalVoteStart > 0) {
            proposalState = StandardGovernor(governor).state(_proposalId);
        }
        // bytes32 proposalFeeLocation = keccak256(abi.encodePacked(_proposalId, uint256(5) /*slot 5*/));
        // uint256 proposalFee = uint256(vm.load(governor, proposalFeeLocation));
        // try StandardGovernor(governor).state(_proposalId) returns (ProposalState _state) {
        //     state = _state;
        // } catch {}

        startGas();
        try StandardGovernor(governor).sendProposalFeeToVault(
            _proposalId
        ) {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (proposalVoteStart == 0) addExpectedError("ProposalDoesNotExist()");
            // if (proposal.state != IGovernor.ProposalState.Expired && state != IGovernor.ProposalState.Defeated) addExpectedError("FeeNotDestinedForVault(ProposalState)";
            // if (proposalFee == 0) addExpectedError("NoFeeToSend()");
            expectedError(_err);
        }
    }

    function setProposalFee(
        uint256 _actorIndex,
        uint256 _newProposalFee
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, governor, 33) {

        startGas();
        try StandardGovernor(governor).setProposalFee(
            _newProposalFee
        ) {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (
                actor.addr != governor ||
                actor.addr != StandardGovernor(governor).zeroGovernor()
            ) addExpectedError("NotSelfOrEmergencyGovernor()");
            expectedError(_err);
        }
    }
}
