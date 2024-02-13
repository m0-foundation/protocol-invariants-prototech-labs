
pragma solidity ^0.8.23;

import "../base/BaseHandler.sol";
import { IGovernor, IBatchGovernor } from "../../lib/Ttg.sol";

abstract contract BatchGovernorHandler is BaseHandler {

    address public governor;
    address public zeroGovernorAddr;

    constructor(address _governor) {
        setGovernor(_governor);
    }

    function setGovernor(address _governor) public {
        governor = _governor;
    }

    //
    // BatchGovernor.sol - Testable functions
    //
    function castVote(
        uint256 _actorIndex,
        uint256 _proposalId,
        uint8 _support
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint48 voteStart = _getProposalVoteStart(_proposalId);
        try IBatchGovernor(governor).castVote(
            _proposalId,
            _support
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            // voteStart = 0 will result in an EvmRevert error (0x0)
            // because of unchecked underflow in _castVote
            // it will also result in ProposalDoesNotExist() error
            if(voteStart == 0) {
                addExpectedErrorBytes32(0x0);
                addExpectedError("ProposalDoesNotExist()");
            }
            // TODO: figure out what causes this in PowerToken
            addExpectedError("NotPastTimepoint(uint48,uint48)");
            expectedError(_err);
        }
    }

    function castVotes(
        uint256 _actorIndex,
        uint256 _proposalIdsRandomness,
        uint256 _supportRandomness
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint256 proposalLength = bound(_proposalIdsRandomness, 0, 10);
        uint256[] memory proposalIds = new uint256[](proposalLength);
        for(uint256 i = 0; i < proposalLength; i++) {
            proposalIds[i] = random256(_proposalIdsRandomness);
            _proposalIdsRandomness = proposalIds[i];
        }
        uint256 supportLength = bound(_supportRandomness, 0, 10);
        uint8[] memory support = new uint8[](supportLength);
        for(uint256 i = 0; i < supportLength; i++) {
            uint256 random = random256(_supportRandomness);
            support[i] = uint8(random);
            _supportRandomness = random;
        }
        // adds all voteStart values for all proposals
        uint256 sumProposalVoteStart = _sumProposalVoteStart(proposalIds);
        try IBatchGovernor(governor).castVotes(
            proposalIds,
            support
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            // If any proposal voteStart is 0 then the proposal does not exist
            // which will result in an EvmRevert error (0x0) because of unchecked underflow in _castVote
            if(sumProposalVoteStart < proposalIds.length) {
                addExpectedErrorBytes32(0x0);
                addExpectedError("ProposalDoesNotExist()");
            }
            // array out-of-bounds error
            if(proposalLength > supportLength) addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x32)));
            // TODO: figure out what causes this in PowerToken
            addExpectedError("NotPastTimepoint(uint48,uint48)");
            expectedError(_err);
        }
    }

    function castVoteWithReason(
        uint256 _actorIndex,
        uint256 _proposalId,
        uint8 _support
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint48 voteStart = _getProposalVoteStart(_proposalId);
        try IBatchGovernor(governor).castVoteWithReason(
            _proposalId,
            _support,
            "reason" // nothing happens with this value, just recorded in transaction
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            // voteStart = 0 will result in an EvmRevert error (0x0)
            // because of unchecked underflow in _castVote
            // it will also result in ProposalDoesNotExist() error
            if(voteStart == 0) {
                addExpectedErrorBytes32(0x0);
                addExpectedError("ProposalDoesNotExist()");
            }
            // TODO: figure out what causes this in PowerToken
            addExpectedError("NotPastTimepoint(uint48,uint48)");
            expectedError(_err);
        }
    }

    function castVoteBySigVRS(
        uint256 _actorIndex,
        uint256 _signerIndex,
        uint256 _proposalId,
        uint8 _support
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        bool chaos; // set if we have a bad signature
        InvariantUtils.Actor memory signer = actors[bound(_signerIndex, 0, actors.length - 1)];
        uint48 voteStart = _getProposalVoteStart(_proposalId);

        InvariantUtils.Signature memory sign;
        {
            bytes32 digest = IBatchGovernor(governor).getBallotDigest(_proposalId, _support);

            (sign.v, sign.r, sign.s) = vm.sign(signer.key, digest);
            // 10% of the time release a signature chaos monkey
            if (bound(_actorIndex, 0, 9) == 0)  {
                sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
                sign.s = bytes32(_actorIndex);
                chaos = true;
            }
        }

        try IBatchGovernor(governor).castVoteBySig(
            _proposalId,
            _support,
            sign.v,
            sign.r,
            sign.s
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (signer.addr != InvariantUtils.GetAddress(signer.key) || chaos) {
                addExpectedError("InvalidSignature()");
            }
            // voteStart = 0 will result in an EvmRevert error (0x0)
            // because of unchecked underflow in _castVote
            // it will also result in ProposalDoesNotExist() error
            if(voteStart == 0) {
                addExpectedErrorBytes32(0x0);
                addExpectedError("ProposalDoesNotExist()");
            }
            // TODO: figure out what causes this in PowerToken
            addExpectedError("NotPastTimepoint(uint48,uint48)");
            expectedError(_err);
        }
    }

    function castVoteBySigSignature(
        uint256 _actorIndex,
        uint256 _signerIndex,
        uint256 _proposalId,
        uint8 _support
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        bool chaos; // set if we have a bad signature
        InvariantUtils.Actor memory signer = actors[bound(_signerIndex, 0, actors.length - 1)];
        uint48 voteStart = _getProposalVoteStart(_proposalId);

        bytes memory signature;
        {
            InvariantUtils.Signature memory sign;
            bytes32 digest = IBatchGovernor(governor).getBallotDigest(_proposalId, _support);

            (sign.v, sign.r, sign.s) = vm.sign(signer.key, digest);
            // 10% of the time release a signature chaos monkey
            if (bound(_actorIndex, 0, 9) == 0)  {
                sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
                sign.s = bytes32(_actorIndex);
                chaos = true;
            }

            signature = abi.encodePacked(sign.r, sign.s, sign.v);
        }

        try IBatchGovernor(governor).castVoteBySig(
            signer.addr,
            _proposalId,
            _support,
            signature
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (signer.addr != InvariantUtils.GetAddress(signer.key) || chaos) {
                addExpectedError("InvalidSignature()");
            }
            // voteStart = 0 will result in an EvmRevert error (0x0)
            // because of unchecked underflow in _castVote
            // it will also result in ProposalDoesNotExist() error
            if(voteStart == 0) {
                addExpectedErrorBytes32(0x0);
                addExpectedError("ProposalDoesNotExist()");
            }
            // TODO: figure out what causes this in PowerToken
            addExpectedError("NotPastTimepoint(uint48,uint48)");
            expectedError(_err);
        }
    }

    function castVotesBySigVRS(
        uint256 _actorIndex,
        uint256 _signerIndex,
        uint256 _proposalIdsRandomness,
        uint256 _supportRandomness
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        bool chaos; // set if we have a bad signature
        InvariantUtils.Actor memory signer = actors[bound(_signerIndex, 0, actors.length - 1)];

        uint256 proposalLength = bound(_proposalIdsRandomness, 0, 10);
        uint256[] memory proposalIds = new uint256[](proposalLength);
        for(uint256 i = 0; i < proposalLength; i++) {
            proposalIds[i] = random256(_proposalIdsRandomness);
            _proposalIdsRandomness = proposalIds[i];
        }
        uint256 supportLength = bound(_supportRandomness, 0, 10);
        uint8[] memory support = new uint8[](supportLength);
        for(uint256 i = 0; i < supportLength; i++) {
            uint256 random = random256(_supportRandomness);
            support[i] = uint8(random);
            _supportRandomness = random;
        }

        // adds all voteStart values for all proposals
        uint256 sumProposalVoteStart = _sumProposalVoteStart(proposalIds);

        InvariantUtils.Signature memory sign;
        {
            (sign.v, sign.r, sign.s) = vm.sign(signer.key, IBatchGovernor(governor).getBallotsDigest(proposalIds, support));
            // 10% of the time release a signature chaos monkey
            if (bound(_actorIndex, 0, 9) == 0)  {
                sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
                sign.s = bytes32(_actorIndex);
                chaos = true;
            }
        }

        try IBatchGovernor(governor).castVotesBySig(
            proposalIds,
            support,
            sign.v,
            sign.r,
            sign.s
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (signer.addr != InvariantUtils.GetAddress(signer.key) || chaos) {
                addExpectedError("InvalidSignature()");
            }
            // If any proposal voteStart is 0 then the proposal does not exist
            // which will result in an EvmRevert error (0x0) because of unchecked underflow in _castVote
            if(sumProposalVoteStart < proposalIds.length) {
                addExpectedErrorBytes32(0x0);
                addExpectedError("ProposalDoesNotExist()");
            }
            // array out-of-bounds error
            if(proposalLength > supportLength) addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x32)));
            // TODO: figure out what causes this in PowerToken
            addExpectedError("NotPastTimepoint(uint48,uint48)");
            expectedError(_err);
        }
    }

    function castVotesBySigSignature(
        uint256 _actorIndex,
        uint256 _signerIndex,
        uint256 _proposalIdsRandomness,
        uint256 _supportRandomness
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        bool chaos; // set if we have a bad signature
        InvariantUtils.Actor memory signer = actors[bound(_signerIndex, 0, actors.length - 1)];

        uint256[] memory proposalIds = new uint256[](bound(_proposalIdsRandomness, 0, 10));
        for(uint256 i = 0; i < proposalIds.length; i++) {
            proposalIds[i] = random256(_proposalIdsRandomness);
            _proposalIdsRandomness = proposalIds[i];
        }
        uint8[] memory support = new uint8[](bound(_supportRandomness, 0, 10));
        for(uint256 i = 0; i < support.length; i++) {
            uint256 random = random256(_supportRandomness);
            support[i] = uint8(random);
            _supportRandomness = random;
        }

        // adds all voteStart values for all proposals
        uint256 sumProposalVoteStart = _sumProposalVoteStart(proposalIds);

        bytes memory signature;
        {
            InvariantUtils.Signature memory sign;
            bytes32 digest = IBatchGovernor(governor).getBallotsDigest(proposalIds, support);

            (sign.v, sign.r, sign.s) = vm.sign(signer.key, digest);
            // 10% of the time release a signature chaos monkey
            if (bound(_actorIndex, 0, 9) == 0)  {
                sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
                sign.s = bytes32(_actorIndex);
                chaos = true;
            }

            signature = abi.encodePacked(sign.r, sign.s, sign.v);
        }

        try IBatchGovernor(governor).castVotesBySig(
            signer.addr,
            proposalIds,
            support,
            signature
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (signer.addr != InvariantUtils.GetAddress(signer.key) || chaos) {
                addExpectedError("InvalidSignature()");
            }
            // If any proposal voteStart is 0 then the proposal does not exist
            // which will result in an EvmRevert error (0x0) because of unchecked underflow in _castVote
            if(sumProposalVoteStart < proposalIds.length) {
                addExpectedErrorBytes32(0x0);
                addExpectedError("ProposalDoesNotExist()");
            }
            // array out-of-bounds error
            if(proposalIds.length > support.length) addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x32)));
            // TODO: figure out what causes this in PowerToken
            addExpectedError("NotPastTimepoint(uint48,uint48)");
            expectedError(_err);
        }
    }

    //
    // Helper Internal Functions
    //

    function _getProposalVoteStart(uint256 proposalId) internal view returns (uint16 voteStart_) {
        // proposals in slot 1
        bytes32 bytes32Proposal = vm.load(governor, keccak256(abi.encodePacked(proposalId, uint256(1))));
        if (bytes32Proposal != bytes32(0)) {
                voteStart_ = uint16(uint256(bytes32Proposal) >> (256 - 16));
        } else {
            console.logBytes32(bytes32Proposal);
            if (IBatchGovernor(governor).proposalDeadline(proposalId) != IBatchGovernor(governor).votingPeriod()) {
                console.log("proposal retrieval failed for some reason");
                revert();
            }
        }
    }

    function _sumProposalVoteStart(
        uint256[] memory proposalIds
    ) internal view returns (uint256 sumProposalVoteStart_) {
        for(uint256 i = 0; i < proposalIds.length; i++) {
            sumProposalVoteStart_ += _getProposalVoteStart(proposalIds[i]);
        }
    }
}
