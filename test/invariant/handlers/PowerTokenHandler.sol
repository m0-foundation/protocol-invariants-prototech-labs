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
import { EIP3009Handler } from "./base/EIP3009Handler.sol";
import { EIP5805Handler } from "./base/EIP5805Handler.sol";
import { PowerToken, MockCashToken } from "../lib/Ttg.sol";

contract PowerTokenHandler is BaseHandler, EIP3009Handler, EIP5805Handler {
    PowerToken public powerToken;

    // violation counters
    uint256 public invalidNonce2612Count;
    uint256 public maxAllowanceViolationCount;
    uint256 public minterGatewayViolationCount;
    uint256 public spendAllowanceViolationCount;
    uint256 public standardGovernorAuthorizationViolationCount;
    uint256 public expectedVoteEpochViolationCount;

    // state
    bool    public firstMaxAllowance = true;
    mapping(uint256 => uint256) public totalSupplyBalances;
    uint256 public totalSupplyCheckpoints;
    uint256[] public epochPassed;
    function getEpochPassed() public view returns (uint256[] memory) { return epochPassed; }
    mapping(uint256 => uint256) public epochBalances;
    mapping(uint256 => uint256) public epochTargetSupplies;
    mapping(uint256 => uint256) public epochAmountToAuction;

    modifier markState() {
        _;
        _markState();
    }

    constructor(
        address _testContract,
        address _powerToken
    ) BaseHandler(_testContract) {
        setPowerToken(_powerToken);
    }

    function setPowerToken(address _powerToken) public {
        powerToken = PowerToken(_powerToken);
    }

    function init(
        uint256 _numOfActors
    ) external {
        addActor(powerToken.standardGovernor(), "standardGovernor");
        addActors(_numOfActors);
        addActor(address(0), "zero");
        addActor(address(powerToken), "powerToken");

        addActor(powerToken.cashToken(), "cashTokenDefault");

        MockCashToken cashToken2 = new MockCashToken();
        cashToken2.setTransferFromFail(true);
        addActor(address(cashToken2), "cashTokenTransferFromFail");

        MockCashToken cashToken3 = new MockCashToken();
        cashToken3.setTransferFromFail(false);
        addActor(address(cashToken3), "cashTokenTransferFromSuccess");

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

    //
    // Testable functions
    //
    function buy(
        uint256 _actorIndex,
        uint256 _minAmount,
        uint256 _maxAmount,
        uint256 _destination
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {

        InvariantUtils.Actor memory _dest = actors[bound(_destination, 0, actors.length - 1)];

        // 10% will fall out of bounds
        _minAmount = bound(_minAmount, 0, type(uint240).max) * 11 / 10;
        if (_minAmount > type(uint240).max) addExpectedError("InvalidUInt240()");
        _maxAmount = bound(_maxAmount, 0, type(uint240).max) * 11 / 10;
        if (_maxAmount > type(uint240).max) addExpectedError("InvalidUInt240()");

        if (isVotingEpoch()) {
            addExpectedError("VoteEpoch()");
        }

        startGas();
        try powerToken.buy(_minAmount, _maxAmount, _dest.addr, uint16(clock())) {
            stopGas();

            if (isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }

        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("TransferFromFailed()");
            //addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            addExpectedError("InsufficientAuctionSupply(uint240,uint240)");
            expectedError(_err);
        }
    }

    function markNextVotingEpochAsActive(
        uint256 _actorIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, powerToken.standardGovernor(), 90) markState {

        startGas();
        try powerToken.markNextVotingEpochAsActive() {
            stopGas();

            if (actor.addr != powerToken.standardGovernor()) {
                standardGovernorAuthorizationViolationCount++;
            }

        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != powerToken.standardGovernor()) {
                addExpectedError("NotStandardGovernor()");
            }
            expectedError(_err);
        }
    }

    function markParticipation(
        uint256 _actorIndex,
        uint256 _delegatee
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, powerToken.standardGovernor(), 90) markState {
        uint256 delegateeIndex = bound(_delegatee, 0, actors.length - 1);

        if (powerToken.hasParticipatedAt(actors[delegateeIndex].addr, powerToken.clock())) {
            addExpectedError("AlreadyParticipated()");
        }

        // // Voting epochs are odd numbered.
        if (!isVotingEpoch()) {
            addExpectedError("NotVoteEpoch()");
        }

        startGas();
        try powerToken.markParticipation(actors[delegateeIndex].addr) {
            stopGas();

            if (!isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }

            if (actor.addr != powerToken.standardGovernor()) {
                standardGovernorAuthorizationViolationCount++;
            }

        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != powerToken.standardGovernor()) {
                addExpectedError("NotStandardGovernor()");
            }

            expectedError(_err);
        }
    }

    function setNextCashToken(
        uint256 _actorIndex,
        uint256 _nextCashToken
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, powerToken.standardGovernor(), 90) markState {

        InvariantUtils.Actor memory randomCashToken = actors[bound(_nextCashToken, 0, actors.length - 1)];

        if (randomCashToken.addr == address(0)) {
            addExpectedError("InvalidCashTokenAddress()");
        }

        startGas();
        try powerToken.setNextCashToken(randomCashToken.addr) {
            stopGas();

            if (actor.addr != powerToken.standardGovernor()) {
                standardGovernorAuthorizationViolationCount++;
            }

        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != powerToken.standardGovernor()) {
                addExpectedError("NotStandardGovernor()");
            }
            expectedError(_err);
        }
    }

    function delegateBySig(
        uint256 _actorIndex,
        uint256 _delegatee,
        uint256 _nonce,
        uint256 _expiry
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {

        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory signer = actors[bound(_actorIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory delegatee = actors[bound(_delegatee, 0, actors.length - 1)];
        _expiry = bound(_expiry, BASE_TIMESTAMP, block.timestamp * 4);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        if (_expiry < block.timestamp) {
            addExpectedError("SignatureExpired(uint256,uint256)");
        }

        bytes32 digest = InvariantUtils.GetDelegateDigest(
            IToken(address(powerToken)),
            delegatee.addr,
            _nonce,
            _expiry
        );

        (sign.v, sign.r, sign.s) = vm.sign(signer.key, digest);

        if (isVotingEpoch()) {
            addExpectedError("VoteEpoch()");
        }

        // TODO remove if Finding 7.1 is resolved
        if (delegatee.addr == address(0)) {
            addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
        }

        startGas();
        try powerToken.delegateBySig(
            delegatee.addr,
            _nonce,
            _expiry,
            sign.v,
            sign.r,
            sign.s
        ) {
            stopGas();

            if (isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }

        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("InvalidSignature()");
            addExpectedError("ReusedNonce(uint256,uint256)");
            expectedError(_err);
        }
    }

    function delegateBySigWithSignature(
        uint256 _actorIndex,
        uint256 _delegatee,
        uint256 _nonce,
        uint256 _expiry
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        /* function delegateBySig(
            address account,
            address delegatee,
            uint256 nonce,
            uint256 expiry,
            bytes memory signature
        ) external; */
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory signer = actors[bound(_actorIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory delegatee = actors[bound(_delegatee, 0, actors.length - 1)];
        _expiry = bound(_expiry, BASE_TIMESTAMP, block.timestamp * 11 / 10);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        if (_expiry < block.timestamp) {
            addExpectedError("SignatureExpired(uint256,uint256)");
        }

        bytes32 digest = InvariantUtils.GetDelegateDigest(
            IToken(address(powerToken)),
            delegatee.addr,
            _nonce,
            _expiry
        );

        (sign.v, sign.r, sign.s) = vm.sign(signer.key, digest);
        bytes memory signature = abi.encodePacked(
            sign.r,
            sign.s,
            sign.v
        );

        if (isVotingEpoch()) {
            addExpectedError("VoteEpoch()");
        }

        // TODO remove if Finding 7.1 is resolved
        if (delegatee.addr == address(0) ||
            delegatee.addr == address(powerToken)) {
            addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
        }

        startGas();
        try powerToken.delegateBySig(
            signer.addr,
            delegatee.addr,
            _nonce,
            _expiry,
            signature
        ) {
            stopGas();

            if (isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }

        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("InvalidSignature()");
            addExpectedError("ReusedNonce(uint256,uint256)");
            expectedError(_err);
        }
    }

    function delegate(
        uint256 _actorIndex,
        uint256 _delegatee
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Actor memory delegatee = actors[bound(_delegatee, 0, actors.length - 1)];

        if (isVotingEpoch()) {
            addExpectedError("VoteEpoch()");
        }

        if (powerToken.getVotes(actor.addr) == 0) {
            // If actor's votes are 0, the call reverts with a Panic overflow
            addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
        }

        //  TODO remove if Finding 7.1 is resolved
        if (delegatee.addr == address(0)) {
            addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
        }

        startGas();
        try powerToken.delegate(delegatee.addr) {
            stopGas();

            if (isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }

        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            expectedError(_err);
        }
    }

    function approve(
        uint256 _actorIndex,
        uint256 _spenderIndex,
        uint256 _amount
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Actor memory spender = actors[bound(_spenderIndex, 0, actors.length - 1)];

        startGas();
        try powerToken.approve(spender.addr, (firstMaxAllowance) ? type(uint256).max : _amount) {
            stopGas();
            firstMaxAllowance = false;
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            expectedError(_err);
        }
    }

    function transfer(
        uint256 _actorIndex,
        uint256 _recipientIndex,
        uint256 _amount
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Actor memory recipient = actors[bound(_recipientIndex, 0, actors.length - 1)];
        _amount = bound(_amount, 0, powerToken.balanceOf(actor.addr));

        if (isVotingEpoch()) {
            addExpectedError("VoteEpoch()");
        }

        startGas();
        try powerToken.transfer(recipient.addr, _amount) {
            stopGas();

            if (isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }

        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (powerToken.getVotes(actor.addr) < _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            expectedError(_err);
        }
    }

    function transferFrom(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        bool maxAllowance = false;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        uint256 beforeAllowance = powerToken.allowance(from.addr, actor.addr);

        if (beforeAllowance == type(uint256).max) {
            maxAllowance = true;
        }

        _amount = bound(
            _amount,
            0,
            uint240((powerToken.balanceOf(from.addr) >=  powerToken.allowance(from.addr, actor.addr)) ?
                powerToken.balanceOf(from.addr) :
                powerToken.allowance(from.addr, actor.addr))
        );

        if (_amount > type(uint240).max) {
            addExpectedError("InvalidUInt240()");
        }

        if (isVotingEpoch()) {
            addExpectedError("VoteEpoch()");
        }

        // Finding 11.2: Consider a named error for insufficient allowance
        if (powerToken.allowance(from.addr, actor.addr) < _amount) {
            addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
        }

        // Finding 11.1: Consider a named error for insufficient balance
        if (powerToken.balanceOf(from.addr) < _amount) {
            addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
        }

        startGas();
        try powerToken.transferFrom(from.addr, to.addr, _amount) {
            stopGas();

            if (isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }

            if (maxAllowance &&
                powerToken.allowance(from.addr, actor.addr) != type(uint256).max) {
                maxAllowanceViolationCount++;
            }
            if (!maxAllowance &&
                beforeAllowance != powerToken.allowance(from.addr, actor.addr) + _amount) {
                spendAllowanceViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (powerToken.getVotes(from.addr) < _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }

            expectedError(_err);
        }
    }

    function transferWithAuthorization(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount,
        uint256 _validAfter,
        uint256 _validBefore,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 11 / 10);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 11 / 10);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        console.log("balanceOf: ", powerToken.balanceOf(from.addr));
        console.log("allowance: ", powerToken.allowance(actor.addr, from.addr));

        _amount = bound(
            _amount,
            0,
            uint240((powerToken.balanceOf(from.addr) >=  powerToken.allowance(actor.addr, from.addr)) ?
                powerToken.balanceOf(from.addr) :
                powerToken.allowance(actor.addr, from.addr))
        );

        if (_amount > type(uint240).max) {
            addExpectedError("InvalidUInt240()");
        }

        console.log("Amount: ", _amount);

        bytes32 digest = InvariantUtils.Get3009Digest(
            IToken(address(powerToken)),
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            powerToken.TRANSFER_WITH_AUTHORIZATION_TYPEHASH()
        );
        (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        if (isVotingEpoch()) {
            addExpectedError("VoteEpoch()");
        }

        if (_validAfter < _validBefore) {
            addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
        }

        startGas();
        try powerToken.transferWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            sign.v,
            sign.r,
            sign.s
        ) {
            stopGas();

            if (isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }

            if (!nonceState[from.addr][bytes32(_nonce)]) {
                nonceState[from.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
            if (block.timestamp <= _validAfter ||
                block.timestamp >= _validBefore) {
                EIP3009ValidViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (powerToken.getVotes(from.addr) < _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            addExpectedError("SignerMismatch()");
            addExpectedError("InvalidSignature()");
            addExpectedError("AuthorizationUsed(address,bytes32)");
            addExpectedError("AuthorizationExpired(uint256,uint256)");
            addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            expectedError(_err);
        }
    }

    function transferWithAuthorizationWithSignature(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount,
        uint256 _validAfter,
        uint256 _validBefore,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 11 / 10);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 11 / 10);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        _amount = bound(
            _amount,
            0,
            uint240(powerToken.balanceOf(from.addr) >=  powerToken.allowance(actor.addr, from.addr) ?
                powerToken.balanceOf(from.addr) :
                powerToken.allowance(actor.addr, from.addr))
        );

        if (_amount > type(uint240).max) {
            addExpectedError("InvalidUInt240()");
        }

        bytes32 digest = InvariantUtils.Get3009Digest(
            IToken(address(powerToken)),
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            powerToken.TRANSFER_WITH_AUTHORIZATION_TYPEHASH()
        );
        (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes memory signature = abi.encodePacked(
            sign.r,
            sign.s,
            sign.v
        );

        if (isVotingEpoch()) {
            addExpectedError("VoteEpoch()");
        }

        startGas();
        try powerToken.transferWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            signature
        ) {
            stopGas();

            if (isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }

            if (!nonceState[from.addr][bytes32(_nonce)]) {
                nonceState[from.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
            if (block.timestamp <= _validAfter ||
                block.timestamp >= _validBefore) {
                EIP3009ValidViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (powerToken.getVotes(from.addr) < _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            addExpectedError("SignerMismatch()");
            addExpectedError("InvalidSignature()");
            addExpectedError("AuthorizationUsed(address,bytes32)");
            addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            addExpectedError("AuthorizationExpired(uint256,uint256)");
            addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            expectedError(_err);
        }
    }

    function transferWithAuthorizationWithVS(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount,
        uint256 _validAfter,
        uint256 _validBefore,
        uint256 _nonce
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 11 / 10);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 11 / 10);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        _amount = bound(
            _amount,
            0,
            uint240((powerToken.balanceOf(from.addr) >=  powerToken.allowance(actor.addr, from.addr)) ?
                powerToken.balanceOf(from.addr) :
                powerToken.allowance(actor.addr, from.addr))
        );

        if (_amount > type(uint240).max) {
            addExpectedError("InvalidUInt240()");
        }

        bytes32 digest = InvariantUtils.Get3009Digest(
            IToken(address(powerToken)),
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            powerToken.TRANSFER_WITH_AUTHORIZATION_TYPEHASH()
        );
        (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes32 vs = sign.s;

        if (sign.v == 28) {
            // then left-most bit of s has to be flipped to 1 to get vs
            vs = sign.s | bytes32(uint256(1) << 255);
        }

        if (isVotingEpoch()) {
            addExpectedError("VoteEpoch()");
        }

        startGas();
        try powerToken.transferWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            sign.r,
            vs
        ) {
            stopGas();

            if (isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }

            if (!nonceState[from.addr][bytes32(_nonce)]) {
                nonceState[from.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
            if (block.timestamp <= _validAfter ||
                block.timestamp >= _validBefore) {
                EIP3009ValidViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (powerToken.getVotes(from.addr) < _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            addExpectedError("SignerMismatch()");
            addExpectedError("InvalidSignature()");
            addExpectedError("AuthorizationUsed(address,bytes32)");
            addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            addExpectedError("AuthorizationExpired(uint256,uint256)");
            addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            expectedError(_err);
        }
    }

    function receiveWithAuthorization(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount,
        uint256 _validAfter,
        uint256 _validBefore,
        uint256 _nonce
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 11 / 10);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 11 / 10);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        _amount = bound(
            _amount,
            0,
            uint240((powerToken.balanceOf(from.addr) >=  powerToken.allowance(actor.addr, from.addr)) ?
                powerToken.balanceOf(from.addr) :
                powerToken.allowance(actor.addr, from.addr))
        );

        if (_amount > type(uint240).max) {
            addExpectedError("InvalidUInt240()");
        }

        bytes32 digest = InvariantUtils.Get3009Digest(
            IToken(address(powerToken)),
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            powerToken.RECEIVE_WITH_AUTHORIZATION_TYPEHASH()
        );
        (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        if (isVotingEpoch()) {
            addExpectedError("VoteEpoch()");
        }

        startGas();
        try powerToken.receiveWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            sign.v,
            sign.r,
            sign.s
        ) {
            stopGas();
            if (isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }
            if (!nonceState[from.addr][bytes32(_nonce)]) {
                nonceState[from.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
            if (block.timestamp <= _validAfter ||
                block.timestamp >= _validBefore) {
                EIP3009ValidViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (powerToken.getVotes(from.addr) < _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            addExpectedError("InvalidSignature()");
            addExpectedError("SignerMismatch()");
            addExpectedError("AuthorizationUsed(address,bytes32)");
            addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            addExpectedError("AuthorizationExpired(uint256,uint256)");
            addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            addExpectedError("CallerMustBePayee(address,address)");
            expectedError(_err);
        }
    }

    function receiveWithAuthorizationWithSignature(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount,
        uint256 _validAfter,
        uint256 _validBefore,
        uint256 _nonce
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 11 / 10);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 11 / 10);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        _amount = bound(
            _amount,
            0,
            (powerToken.balanceOf(from.addr) >=  powerToken.allowance(actor.addr, from.addr)) ?
                powerToken.balanceOf(from.addr) :
                powerToken.allowance(actor.addr, from.addr)
        );

        if (_amount > type(uint240).max) {
            addExpectedError("InvalidUInt240()");
        }

        bytes32 digest = InvariantUtils.Get3009Digest(
            IToken(address(powerToken)),
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            powerToken.RECEIVE_WITH_AUTHORIZATION_TYPEHASH()
        );
        (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes memory signature = abi.encodePacked(
            sign.r,
            sign.s,
            sign.v
        );

        if (isVotingEpoch()) {
            addExpectedError("VoteEpoch()");
        }

        startGas();
        try powerToken.receiveWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            signature
        ) {
            stopGas();
            if (isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }
            if (!nonceState[from.addr][bytes32(_nonce)]) {
                nonceState[from.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
            if (block.timestamp <= _validAfter ||
                block.timestamp >= _validBefore) {
                EIP3009ValidViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (powerToken.getVotes(from.addr) < _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            addExpectedError("InvalidSignature()");
            addExpectedError("SignerMismatch()");
            addExpectedError("AuthorizationUsed(address,bytes32)");
            addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            addExpectedError("AuthorizationExpired(uint256,uint256)");
            addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            addExpectedError("CallerMustBePayee(address,address)");
            expectedError(_err);
        }
    }

    function receiveWithAuthorizationWithVS(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount,
        uint256 _validAfter,
        uint256 _validBefore,
        uint256 _nonce
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 11 / 10);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 11 / 10);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        _amount = bound(
            _amount,
            0,
            uint240((powerToken.balanceOf(from.addr) >=  powerToken.allowance(actor.addr, from.addr)) ?
                powerToken.balanceOf(from.addr) :
                powerToken.allowance(actor.addr, from.addr))
        );

        if (_amount > type(uint240).max) {
            addExpectedError("InvalidUInt240()");
        }

        bytes32 digest = InvariantUtils.Get3009Digest(
            IToken(address(powerToken)),
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            powerToken.RECEIVE_WITH_AUTHORIZATION_TYPEHASH()
        );
        (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes32 vs = sign.s;

        if (sign.v == 28) {
            // then left-most bit of s has to be flipped to 1 to get vs
            vs = sign.s | bytes32(uint256(1) << 255);
        }

        if (isVotingEpoch()) {
            addExpectedError("VoteEpoch()");
        }

        startGas();
        try powerToken.receiveWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            sign.r,
            vs
        ) {
            stopGas();
            if (isVotingEpoch()) {
                expectedVoteEpochViolationCount++;
            }
            if (!nonceState[from.addr][bytes32(_nonce)]) {
                nonceState[from.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
            if (block.timestamp <= _validAfter ||
                block.timestamp >= _validBefore) {
                EIP3009ValidViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (powerToken.getVotes(from.addr) < _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            addExpectedError("InvalidSignature()");
            addExpectedError("SignerMismatch()");
            addExpectedError("AuthorizationUsed(address,bytes32)");
            addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            addExpectedError("AuthorizationExpired(uint256,uint256)");
            addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            addExpectedError("CallerMustBePayee(address,address)");
            expectedError(_err);
        }
    }

    function cancelAuthorization(
        uint256 _actorIndex,
        uint256 _authorizerIndex,
        uint256 _nonce
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory authorizer = actors[bound(_authorizerIndex, 0, actors.length - 1)];
        _nonce = bound(_nonce, 0, MAX_NONCE);

        bytes32 digest = InvariantUtils.Get3009CancelDigest(
            IToken(address(powerToken)),
            authorizer.addr,
            bytes32(_nonce)
        );
        (sign.v, sign.r, sign.s) = vm.sign(authorizer.key, digest);

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        startGas();
        try powerToken.cancelAuthorization(
            authorizer.addr,
            bytes32(_nonce),
            sign.v,
            sign.r,
            sign.s
        ) {
            stopGas();
            if (!nonceState[authorizer.addr][bytes32(_nonce)]) {
                nonceState[authorizer.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("SignerMismatch()");
            addExpectedError("InvalidSignature()");
            addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            expectedError(_err);
        }
    }

    function cancelAuthorizationWithSignature(
        uint256 _actorIndex,
        uint256 _authorizerIndex,
        uint256 _nonce
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory authorizer = actors[bound(_authorizerIndex, 0, actors.length - 1)];
        _nonce = bound(_nonce, 0, MAX_NONCE);

        bytes32 digest = InvariantUtils.Get3009CancelDigest(
            IToken(address(powerToken)),
            authorizer.addr,
            bytes32(_nonce)
        );
        (sign.v, sign.r, sign.s) = vm.sign(authorizer.key, digest);

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes memory signature = abi.encodePacked(
            sign.r,
            sign.s,
            sign.v
        );

        startGas();
        try powerToken.cancelAuthorization(
            authorizer.addr,
            bytes32(_nonce),
            signature
        ) {
            stopGas();
            if (!nonceState[authorizer.addr][bytes32(_nonce)]) {
                nonceState[authorizer.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("SignerMismatch()");
            addExpectedError("InvalidSignature()");
            addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            expectedError(_err);
        }
    }

    function cancelAuthorizationWithVS(
        uint256 _actorIndex,
        uint256 _authorizerIndex,
        uint256 _nonce
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory authorizer = actors[bound(_authorizerIndex, 0, actors.length - 1)];
        _nonce = bound(_nonce, 0, MAX_NONCE);

        bytes32 digest = InvariantUtils.Get3009CancelDigest(
            IToken(address(powerToken)),
            authorizer.addr,
            bytes32(_nonce)
        );
        (sign.v, sign.r, sign.s) = vm.sign(authorizer.key, digest);

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes32 vs = sign.s;

        if (sign.v == 28) {
            // then left-most bit of s has to be flipped to 1 to get vs
            vs = sign.s | bytes32(uint256(1) << 255);
        }

        startGas();
        try powerToken.cancelAuthorization(
            authorizer.addr,
            bytes32(_nonce),
            sign.r,
            vs
        ) {
            stopGas();
            if (!nonceState[authorizer.addr][bytes32(_nonce)]) {
                nonceState[authorizer.addr][bytes32(_nonce)] = true;
            } else {
                nonceViolation3009Count++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("SignerMismatch()");
            addExpectedError("InvalidSignature()");
            addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            expectedError(_err);
        }
    }

    function permit(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _spenderIndex,
        uint256 _amount,
        uint256 _nonce,
        uint256 _deadline
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory spender = actors[bound(_spenderIndex, 0, actors.length - 1)];
        _nonce = bound(
            _nonce,
            (powerToken.nonces(from.addr) > 0) ? powerToken.nonces(from.addr) - 1 : 0,
            powerToken.nonces(from.addr) + 1
        );

        bytes32 digest = InvariantUtils.GetPermitDigest(
            IToken(address(powerToken)),
            from.addr,
            spender.addr,
            _amount,
            _nonce,
            _deadline
        );
        (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        startGas();
        try powerToken.permit(
            from.addr,
            spender.addr,
            _amount,
            _deadline,
            sign.v,
            sign.r,
            sign.s
        ) {
            stopGas();
            if ((powerToken.nonces(from.addr) - 1) != _nonce) {
                invalidNonce2612Count++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("SignerMismatch()");
            addExpectedError("InvalidSignature()");
            addExpectedError("SignatureExpired(uint256,uint256)");
            expectedError(_err);
        }
    }

    function permitWithSignature(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _spenderIndex,
        uint256 _amount,
        uint256 _nonce,
        uint256 _deadline
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) markState {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory spender = actors[bound(_spenderIndex, 0, actors.length - 1)];
        _nonce = bound(
            _nonce,
            (powerToken.nonces(from.addr) > 0) ? powerToken.nonces(from.addr) - 1 : 0,
            powerToken.nonces(from.addr) + 1
        );

        bytes32 digest = InvariantUtils.GetPermitDigest(
            IToken(address(powerToken)),
            from.addr,
            spender.addr,
            _amount,
            _nonce,
            _deadline
        );
        (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        bytes memory signature = abi.encodePacked(
            sign.r,
            sign.s,
            sign.v
        );

        startGas();
        try powerToken.permit(
            from.addr,
            spender.addr,
            _amount,
            _deadline,
            signature
        ) {
            stopGas();
            if ((powerToken.nonces(from.addr) - 1) != _nonce) {
                invalidNonce2612Count++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("SignerMismatch()");
            addExpectedError("InvalidSignature()");
            addExpectedError("SignatureExpired(uint256,uint256)");
            expectedError(_err);
        }
    }

    function _markState() internal {
        uint256 epoch = powerToken.clock();
        uint256 supply = powerToken.totalSupply();
        uint256 targetSupply = powerToken.targetSupply();

        if (isVotingEpoch()) {
            if (epochPassed.length == 0) {
                epochPassed.push(epoch);
                epochBalances[epoch] = supply;
                epochTargetSupplies[epoch] = targetSupply;
            } else if (epoch > epochPassed[epochPassed.length - 1]) {
                epochPassed.push(epoch);
                epochBalances[epoch] = supply;
                epochTargetSupplies[epoch] = targetSupply;
            }
        }

        epochAmountToAuction[epoch] = powerToken.amountToAuction();
        totalSupplyBalances[totalSupplyCheckpoints] = supply;
        totalSupplyCheckpoints++;
    }

}
