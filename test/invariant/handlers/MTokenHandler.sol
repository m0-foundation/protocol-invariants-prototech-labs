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
import {
    MockRateModel,
    MockTTGRegistrar,
    MToken,
    TTGRegistrarReader
} from "../lib/Protocol.sol";
import { Registrar } from "../lib/Ttg.sol";

contract MTokenHandler is BaseHandler, EIP3009Handler {
    MToken public mToken;

    InvariantUtils.Actor internal _minterGateway;
    InvariantUtils.Actor internal _registrar;

    // violation counters
    uint256 public invalidNonce2612Count;
    uint256 public maxAllowanceViolationCount;
    uint256 public minterGatewayViolationCount;
    uint256 public spendAllowanceViolationCount;
    uint256 public startingMTokenSupply;

    // state
    bool public firstMaxAllowance = true;

    constructor(
        address _testContract,
        MToken _mToken,
        InvariantUtils.Actor memory _minterGatewayActor,
        InvariantUtils.Actor memory _registrarActor
    ) BaseHandler(_testContract) {
        mToken = _mToken;
        _minterGateway = _minterGatewayActor;
        _registrar = _registrarActor;
    }

    function init(uint256 _numOfActors) external {
        InvariantUtils.Actor memory guy;

        for(uint256 i = 0; i < _numOfActors; i++) {
            guy = addActor(string(abi.encodePacked("Actor", vm.toString(i))));
            _ensureMTokenAmount(guy.addr, 1e18);

            // only add even actors to the EARNERS_LIST
            if (i % 2 == 0 && !testContract.realRegistrar()) {
                MockTTGRegistrar(_registrar.addr).addToList(TTGRegistrarReader.EARNERS_LIST, guy.addr);
            }
        }

        // zero actor
        zero = addActor(address(0), "zero");

        // token actor
        token = addActor(address(mToken), "MToken");

        // minter gateway
        addActor(_minterGateway);

        // registrar
        addActor(_registrar);

        validateActors();
    }

    function init(
        InvariantUtils.Actor[] memory _actors,
        InvariantUtils.Actor[] memory _receivers
    ) external {
        for(uint256 i = 0; i < _actors.length; i++) {
            msgSenders.push(_actors[i]);
            _ensureMTokenAmount(_actors[i].addr, 1e18);

            // only add even actors to the EARNERS_LIST
            if (i % 2 == 0 && !testContract.realRegistrar()) {
                MockTTGRegistrar(_registrar.addr).addToList(TTGRegistrarReader.EARNERS_LIST, _actors[i].addr);
            }
        }

        validateActors(msgSenders);

        for(uint256 i = 0; i < _receivers.length; i++) {
            actors.push(_receivers[i]);
        }

        validateActors(actors);
    }

    function _ensureMTokenAmount(address _actor, uint256 _amount) internal {
        uint256 actorBalance = mToken.balanceOf(_actor);
        if (_amount > actorBalance) {
            vm.prank(_minterGateway.addr);
            mToken.mint(_actor, _amount - actorBalance);
            startingMTokenSupply += _amount - actorBalance;
        }
    }

    //
    // Testable functions
    //
    function approve(
        uint256 _actorIndex,
        uint256 _spenderIndex,
        uint256 _amount
    ) external resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Actor memory spender = actors[bound(_spenderIndex, 0, actors.length - 1)];

        startGas();
        try mToken.approve(spender.addr, (firstMaxAllowance) ? type(uint256).max : _amount) {
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
    ) external resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Actor memory recipient = actors[bound(_recipientIndex, 0, actors.length - 1)];
        _amount = bound(_amount, 0, mToken.balanceOf(actor.addr));

        startGas();
        try mToken.transfer(recipient.addr, _amount) {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if ((mToken.isEarning(recipient.addr) && MAX_UINT112 < mToken.balanceOf(recipient.addr) + _amount) ||
                MAX_UINT112 < mToken.totalEarningSupply() + _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
                addExpectedError("InvalidUInt112()");
            }
            expectedError(_err);
        }
    }

    function transferFrom(
        uint256 _actorIndex,
        uint256 _fromIndex,
        uint256 _toIndex,
        uint256 _amount
    ) external resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        bool maxAllowance = false;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        uint256 beforeAllowance = mToken.allowance(from.addr, actor.addr);

        if (beforeAllowance == type(uint256).max) {
            maxAllowance = true;
        }

        _amount = bound(
            _amount,
            0,
            uint240((mToken.balanceOf(from.addr) >=  mToken.allowance(from.addr, actor.addr)) ?
                mToken.balanceOf(from.addr) :
                mToken.allowance(from.addr, actor.addr))
        );


        startGas();
        try mToken.transferFrom(from.addr, to.addr, _amount) {
            stopGas();

            if (maxAllowance &&
                mToken.allowance(from.addr, actor.addr) != type(uint256).max) {
                maxAllowanceViolationCount++;
            }
            if (!maxAllowance &&
                beforeAllowance != mToken.allowance(from.addr, actor.addr) + _amount) {
                spendAllowanceViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (_amount > mToken.allowance(from.addr, actor.addr) ||
                _amount > mToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            if ((mToken.isEarning(to.addr) && MAX_UINT112 < mToken.balanceOf(to.addr) + _amount) ||
                MAX_UINT112 < mToken.totalEarningSupply() + _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
                addExpectedError("InvalidUInt112()");
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
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 2);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 2);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        // get a snapshot of allowance values
        snapAllowanceValues(IToken(address(mToken)));

        _amount = bound(
            _amount,
            0,
            uint240((mToken.balanceOf(from.addr) >=  mToken.allowance(actor.addr, from.addr)) ?
                mToken.balanceOf(from.addr) :
                mToken.allowance(actor.addr, from.addr))
        );

        { // avoid stack too deep
            bytes32 digest = InvariantUtils.Get3009Digest(
                IToken(address(mToken)),
                from.addr,
                to.addr,
                _amount,
                _validAfter,
                _validBefore,
                bytes32(_nonce),
                mToken.TRANSFER_WITH_AUTHORIZATION_TYPEHASH()
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        startGas();
        try mToken.transferWithAuthorization(
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
            // ensure no allowances change
            if (allowanceDiff(IToken(address(mToken)))) {
                EIP3009AllowanceViolationCount++;
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
            if (nonceState[from.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (block.timestamp >= _validBefore) addExpectedError("AuthorizationExpired(uint256,uint256)");
            if (block.timestamp <= _validAfter) addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (_amount > mToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            if ((mToken.isEarning(to.addr) && MAX_UINT112 < mToken.balanceOf(to.addr) + _amount) ||
                MAX_UINT112 < mToken.totalEarningSupply() + _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
                addExpectedError("InvalidUInt112()");
            }
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
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 2);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 2);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        // get a snapshot of allowance values
        snapAllowanceValues(IToken(address(mToken)));

        _amount = bound(
            _amount,
            0,
            uint240((mToken.balanceOf(from.addr) >=  mToken.allowance(actor.addr, from.addr)) ?
                mToken.balanceOf(from.addr) :
                mToken.allowance(actor.addr, from.addr))
        );

        { // Stack too deep
            bytes32 digest = InvariantUtils.Get3009Digest(
                IToken(address(mToken)),
                from.addr,
                to.addr,
                _amount,
                _validAfter,
                _validBefore,
                bytes32(_nonce),
                mToken.TRANSFER_WITH_AUTHORIZATION_TYPEHASH()
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

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
        try mToken.transferWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            signature
        ) {
            stopGas();
            // ensure no allowances change
            if (allowanceDiff(IToken(address(mToken)))) {
                EIP3009AllowanceViolationCount++;
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
            if (nonceState[from.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (block.timestamp >= _validBefore) addExpectedError("AuthorizationExpired(uint256,uint256)");
            if (block.timestamp <= _validAfter) addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (_amount > mToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            if ((mToken.isEarning(to.addr) && MAX_UINT112 < mToken.balanceOf(to.addr) + _amount) ||
                MAX_UINT112 < mToken.totalEarningSupply() + _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
                addExpectedError("InvalidUInt112()");
            }
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
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 2);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 2);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        // get a snapshot of allowance values
        snapAllowanceValues(IToken(address(mToken)));

        _amount = bound(
            _amount,
            0,
            uint240((mToken.balanceOf(from.addr) >=  mToken.allowance(actor.addr, from.addr)) ?
                mToken.balanceOf(from.addr) :
                mToken.allowance(actor.addr, from.addr))
        );

        { // avoid stack too deep
            bytes32 digest = InvariantUtils.Get3009Digest(
                IToken(address(mToken)),
                from.addr,
                to.addr,
                _amount,
                _validAfter,
                _validBefore,
                bytes32(_nonce),
                mToken.TRANSFER_WITH_AUTHORIZATION_TYPEHASH()
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

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
        try mToken.transferWithAuthorization(
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

            // ensure no allowances change
            if (allowanceDiff(IToken(address(mToken)))) {
                EIP3009AllowanceViolationCount++;
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
            if (nonceState[from.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (block.timestamp >= _validBefore) addExpectedError("AuthorizationExpired(uint256,uint256)");
            if (block.timestamp <= _validAfter) addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (_amount > mToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            if ((mToken.isEarning(to.addr) && MAX_UINT112 < mToken.balanceOf(to.addr) + _amount) ||
                MAX_UINT112 < mToken.totalEarningSupply() + _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
                addExpectedError("InvalidUInt112()");
            }
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
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 2);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 2);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        // get a snapshot of allowance values
        snapAllowanceValues(IToken(address(mToken)));

        _amount = bound(
            _amount,
            0,
            uint240((mToken.balanceOf(from.addr) >=  mToken.allowance(actor.addr, from.addr)) ?
                mToken.balanceOf(from.addr) :
                mToken.allowance(actor.addr, from.addr))
        );

        { // Stack too deep
            bytes32 digest = InvariantUtils.Get3009Digest(
                IToken(address(mToken)),
                from.addr,
                to.addr,
                _amount,
                _validAfter,
                _validBefore,
                bytes32(_nonce),
                mToken.RECEIVE_WITH_AUTHORIZATION_TYPEHASH()
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        startGas();
        try mToken.receiveWithAuthorization(
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
            // ensure no allowances change
            if (allowanceDiff(IToken(address(mToken)))) {
                EIP3009AllowanceViolationCount++;
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
            if (nonceState[from.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (block.timestamp >= _validBefore) addExpectedError("AuthorizationExpired(uint256,uint256)");
            if (block.timestamp <= _validAfter) addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            if (actor.addr != to.addr) addExpectedError("CallerMustBePayee(address,address)");
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (_amount > mToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            if ((mToken.isEarning(to.addr) && MAX_UINT112 < mToken.balanceOf(to.addr) + _amount) ||
                MAX_UINT112 < mToken.totalEarningSupply() + _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
                addExpectedError("InvalidUInt112()");
            }
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
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 2);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 2);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        // get a snapshot of allowance values
        snapAllowanceValues(IToken(address(mToken)));

        _amount = bound(
            _amount,
            0,
            uint240((mToken.balanceOf(from.addr) >=  mToken.allowance(actor.addr, from.addr)) ?
                mToken.balanceOf(from.addr) :
                mToken.allowance(actor.addr, from.addr))
        );

        { // Stack too deep
            bytes32 digest = InvariantUtils.Get3009Digest(
                IToken(address(mToken)),
                from.addr,
                to.addr,
                _amount,
                _validAfter,
                _validBefore,
                bytes32(_nonce),
                mToken.RECEIVE_WITH_AUTHORIZATION_TYPEHASH()
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

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
        try mToken.receiveWithAuthorization(
            from.addr,
            to.addr,
            _amount,
            _validAfter,
            _validBefore,
            bytes32(_nonce),
            signature
        ) {
            stopGas();

            // ensure no allowances change
            if (allowanceDiff(IToken(address(mToken)))) {
                EIP3009AllowanceViolationCount++;
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
            if (nonceState[from.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (block.timestamp >= _validBefore) addExpectedError("AuthorizationExpired(uint256,uint256)");
            if (block.timestamp <= _validAfter) addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            if (actor.addr != to.addr) addExpectedError("CallerMustBePayee(address,address)");
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (_amount > mToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            if ((mToken.isEarning(to.addr) && MAX_UINT112 < mToken.balanceOf(to.addr) + _amount) ||
                MAX_UINT112 < mToken.totalEarningSupply() + _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
                addExpectedError("InvalidUInt112()");
            }
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
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory to = actors[bound(_toIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        _validAfter = bound(_validAfter, 0, block.timestamp * 2);
        _validBefore = bound(_validBefore, _validAfter, block.timestamp * 2);
        _nonce = bound(_nonce, 0, MAX_NONCE);

        // get a snapshot of allowance values
        snapAllowanceValues(IToken(address(mToken)));

        _amount = bound(
            _amount,
            0,
            uint240((mToken.balanceOf(from.addr) >=  mToken.allowance(actor.addr, from.addr)) ?
                mToken.balanceOf(from.addr) :
                mToken.allowance(actor.addr, from.addr))
        );

        { // Stack too deep
            bytes32 digest = InvariantUtils.Get3009Digest(
                IToken(address(mToken)),
                from.addr,
                to.addr,
                _amount,
                _validAfter,
                _validBefore,
                bytes32(_nonce),
                mToken.RECEIVE_WITH_AUTHORIZATION_TYPEHASH()
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

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
        try mToken.receiveWithAuthorization(
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
            // ensure no allowances change
            if (allowanceDiff(IToken(address(mToken)))) {
                EIP3009AllowanceViolationCount++;
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
            if (nonceState[from.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (block.timestamp >= _validBefore) addExpectedError("AuthorizationExpired(uint256,uint256)");
            if (block.timestamp <= _validAfter) addExpectedError("AuthorizationNotYetValid(uint256,uint256)");
            if (actor.addr != to.addr) addExpectedError("CallerMustBePayee(address,address)");
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (_amount > mToken.balanceOf(from.addr)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            if ((mToken.isEarning(to.addr) && MAX_UINT112 < mToken.balanceOf(to.addr) + _amount) ||
                MAX_UINT112 < mToken.totalEarningSupply() + _amount) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
                addExpectedError("InvalidUInt112()");
            }
            expectedError(_err);
        }
    }

    function cancelAuthorization(
        uint256 _actorIndex,
        uint256 _authorizerIndex,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory authorizer = actors[bound(_authorizerIndex, 0, actors.length - 1)];
        _nonce = bound(_nonce, 0, MAX_NONCE);

        { // Stack too deep
            bytes32 digest = InvariantUtils.Get3009CancelDigest(
                IToken(address(mToken)),
                authorizer.addr,
                bytes32(_nonce)
            );
            (sign.v, sign.r, sign.s) = vm.sign(authorizer.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        startGas();
        try mToken.cancelAuthorization(
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
            if (nonceState[authorizer.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (authorizer.addr != InvariantUtils.GetAddress(authorizer.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            expectedError(_err);
        }
    }

    function cancelAuthorizationWithSignature(
        uint256 _actorIndex,
        uint256 _authorizerIndex,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory authorizer = actors[bound(_authorizerIndex, 0, actors.length - 1)];
        _nonce = bound(_nonce, 0, MAX_NONCE);

        { // Stack too deep
            bytes32 digest = InvariantUtils.Get3009CancelDigest(
                IToken(address(mToken)),
                authorizer.addr,
                bytes32(_nonce)
            );
            (sign.v, sign.r, sign.s) = vm.sign(authorizer.key, digest);
        }

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
        try mToken.cancelAuthorization(
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
            if (nonceState[authorizer.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (authorizer.addr != InvariantUtils.GetAddress(authorizer.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            expectedError(_err);
        }
    }

    function cancelAuthorizationWithVS(
        uint256 _actorIndex,
        uint256 _authorizerIndex,
        uint256 _nonce
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory authorizer = actors[bound(_authorizerIndex, 0, actors.length - 1)];
        _nonce = bound(_nonce, 0, MAX_NONCE);

        { // Stack too deep
            bytes32 digest = InvariantUtils.Get3009CancelDigest(
                IToken(address(mToken)),
                authorizer.addr,
                bytes32(_nonce)
            );
            (sign.v, sign.r, sign.s) = vm.sign(authorizer.key, digest);
        }

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
        try mToken.cancelAuthorization(
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
            if (nonceState[authorizer.addr][bytes32(_nonce)]) {
                addExpectedError("AuthorizationAlreadyUsed(address,bytes32)");
            }
            if (authorizer.addr != InvariantUtils.GetAddress(authorizer.key) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
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
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory spender = actors[bound(_spenderIndex, 0, actors.length - 1)];
        _nonce = bound(
            _nonce,
            (mToken.nonces(from.addr) > 0) ? mToken.nonces(from.addr) - 1 : 0,
            mToken.nonces(from.addr) + 1
        );

        { // Stack too deep
            bytes32 digest = InvariantUtils.GetPermitDigest(
                IToken(address(mToken)),
                from.addr,
                spender.addr,
                _amount,
                _nonce,
                _deadline
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

        // 10% of the time release a signature chaos monkey
        if (bound(_actorIndex, 0, 9) == 0)  {
            sign.v = uint8(sign.v + bound(_actorIndex, 0, 2));
            sign.s = bytes32(_actorIndex);
        }

        startGas();
        try mToken.permit(
            from.addr,
            spender.addr,
            _amount,
            _deadline,
            sign.v,
            sign.r,
            sign.s
        ) {
            stopGas();
            if ((mToken.nonces(from.addr) - 1) != _nonce) {
                invalidNonce2612Count++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                _nonce != mToken.nonces(from.addr) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (block.timestamp > _deadline) addExpectedError("SignatureExpired(uint256,uint256)");
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
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Signature memory sign;
        InvariantUtils.Actor memory from = actors[bound(_fromIndex, 0, actors.length - 1)];
        InvariantUtils.Actor memory spender = actors[bound(_spenderIndex, 0, actors.length - 1)];
        _nonce = bound(
            _nonce,
            (mToken.nonces(from.addr) > 0) ? mToken.nonces(from.addr) - 1 : 0,
            mToken.nonces(from.addr) + 1
        );

        { // Stack too deep
            bytes32 digest = InvariantUtils.GetPermitDigest(
                IToken(address(mToken)),
                from.addr,
                spender.addr,
                _amount,
                _nonce,
                _deadline
            );
            (sign.v, sign.r, sign.s) = vm.sign(from.key, digest);
        }

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
        try mToken.permit(
            from.addr,
            spender.addr,
            _amount,
            _deadline,
            signature
        ) {
            stopGas();
            if ((mToken.nonces(from.addr) - 1) != _nonce) {
                invalidNonce2612Count++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (from.addr != InvariantUtils.GetAddress(from.key) ||
                _nonce != mToken.nonces(from.addr) ||
                bound(_actorIndex, 0, 9) == 0) {
                addExpectedError("InvalidSignature()");
                addExpectedError("SignerMismatch()");
            }
            if (block.timestamp > _deadline) addExpectedError("SignatureExpired(uint256,uint256)");
            expectedError(_err);
        }
    }

    function updateIndex(
        uint256 _actorIndex
    ) external resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        startGas();
        try mToken.updateIndex() {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            expectedError(_err);
        }
    }

    function mint(
        uint256 _actorIndex,
        uint256 _recipientIndex,
        uint256 _amount
    ) external resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, _minterGateway.addr, 75) {
        InvariantUtils.Actor memory recipient = actors[bound(_recipientIndex, 0, actors.length - 1)];
        // TODO: once Finding 8.1 is resolved we can switch back to this bound
        // _amount = bound(_amount, 0, MAX_UINT240);
        _amount = bound(_amount, 0, MAX_UINT112/2);

        startGas();
        try mToken.mint(recipient.addr, _amount) {
            stopGas();

            if (actor.addr != _minterGateway.addr) {
                minterGatewayViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != _minterGateway.addr) addExpectedError("NotMinterGateway()");
            if ((mToken.isEarning(recipient.addr) && MAX_UINT112 < mToken.balanceOf(recipient.addr) + _amount) ||
                 MAX_UINT112 < mToken.totalSupply() + _amount
                ){
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
                addExpectedError("InvalidUInt112()");
            }
            expectedError(_err);
        }
    }

    function burn(
        uint256 _actorIndex,
        uint256 _accountIndex,
        uint256 _amount
    ) external resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, _minterGateway.addr, 75) {
        InvariantUtils.Actor memory account = actors[bound(_accountIndex, 0, actors.length - 1)];
        _amount = bound(_amount, 0, MAX_UINT240);

        startGas();
        try mToken.burn(account.addr, _amount) {
            stopGas();
            if (actor.addr != _minterGateway.addr) {
                minterGatewayViolationCount++;
            }
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (actor.addr != _minterGateway.addr) addExpectedError("NotMinterGateway()");
            if (_amount > mToken.balanceOf(account.addr) ||
                _amount > mToken.totalSupply() ||
                (mToken.isEarning(account.addr) && _amount > MAX_UINT112)) {
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
                addExpectedError("InvalidUInt112()");
            }
            expectedError(_err);
        }
    }

    function startEarning(
        uint256 _actorIndex
    ) external resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        startGas();
        try mToken.startEarning() {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (TTGRegistrarReader.isEarnersListIgnored(_registrar.addr) ||
                !Registrar(_registrar.addr).listContains(TTGRegistrarReader.EARNERS_LIST, actor.addr)) {
                addExpectedError("NotApprovedEarner()");
            }
            expectedError(_err);
        }
    }

    function startEarningOnBehalfOf(
        uint256 _actorIndex,
        uint256 _accountIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Actor memory account = actors[bound(_accountIndex, 0, actors.length - 1)];

        startGas();
        try mToken.startEarningOnBehalfOf(account.addr) {
            stopGas();

            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (!mToken.hasAllowedEarningOnBehalf(account.addr)) addExpectedError("HasNotAllowedEarningOnBehalf()");
            if (TTGRegistrarReader.isEarnersListIgnored(_registrar.addr) ||
                !Registrar(_registrar.addr).listContains(TTGRegistrarReader.EARNERS_LIST, account.addr)) {
                addExpectedError("NotApprovedEarner()");
            }
            expectedError(_err);
        }
    }

    function stopEarning(
        uint256 _actorIndex
    ) external resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        startGas();
        try mToken.stopEarning() {
            stopGas();

            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            expectedError(_err);
        }
    }

    function stopEarningOnBehalfOf(
        uint256 _actorIndex,
        uint256 _accountIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        InvariantUtils.Actor memory account = actors[bound(_accountIndex, 0, actors.length - 1)];

        startGas();
        try mToken.stopEarningOnBehalfOf(account.addr) {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (TTGRegistrarReader.isEarnersListIgnored(_registrar.addr) ||
                TTGRegistrarReader.isApprovedEarner(_registrar.addr, account.addr)) {
                addExpectedError("IsApprovedEarner()");
            }
            expectedError(_err);
        }
    }

    function allowEarningOnBehalf(
        uint256 _actorIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        startGas();
        try mToken.allowEarningOnBehalf() {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            expectedError(_err);
        }
    }

    function disallowEarningOnBehalf(
        uint256 _actorIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        startGas();
        try mToken.disallowEarningOnBehalf() {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            expectedError(_err);
        }
    }

    // TTGRegistrar Functions
    function updateEarnerRateModel(
        uint256 _actorIndex,
        uint256 newEarnerRateModelRate
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        // changing the rate model address does not really matter in this context
        // we should update the value returned by the `MockRateModel` instead
        // TODO: fix this hack to swap the real rate model
        if (!testContract.integration()) {
            address earnerRateModel = TTGRegistrarReader.getEarnerRateModel(_registrar.addr);
            MockRateModel(earnerRateModel).setRate(newEarnerRateModelRate);
        }
    }

    function updateIsEarnersListIgnored(
        uint256 _actorIndex,
        bool _isIgnored
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        if (testContract.realRegistrar()) {
            try Registrar(_registrar.addr).setKey(
                TTGRegistrarReader.EARNERS_LIST_IGNORED,
                _isIgnored ? bytes32(uint256(1)) : bytes32(uint256(0))
            ) {
                // success
            } catch Error(string memory _err) {
                expectedError(_err);
            } catch (bytes memory _err) {
                addExpectedError("NotStandardOrEmergencyGovernor()");
                expectedError(_err);
            }
        } else {
            MockTTGRegistrar(_registrar.addr).updateConfig(
                TTGRegistrarReader.EARNERS_LIST_IGNORED,
                _isIgnored ? bytes32(uint256(1)) : bytes32(0)
            );
        }
    }

    function approveEarner(
        uint256 _actorIndex,
        uint256 _earnerIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint256 earnerIndex = bound(_earnerIndex, 0, actors.length - 1);

        if (testContract.realRegistrar()) {
            try Registrar(_registrar.addr).addToList(
                TTGRegistrarReader.EARNERS_LIST,
                actors[earnerIndex].addr
            ) {
                // success
            } catch Error(string memory _err) {
                expectedError(_err);
            } catch (bytes memory _err) {
                addExpectedError("NotStandardOrEmergencyGovernor()");
                expectedError(_err);
            }
        } else {
            MockTTGRegistrar(_registrar.addr).addToList(
                TTGRegistrarReader.EARNERS_LIST,
                actors[earnerIndex].addr
            );
        }
    }

    function disapproveEarner(
        uint256 _actorIndex,
        uint256 _earnerIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint256 earnerIndex = bound(_earnerIndex, 0, actors.length - 1);

        if (testContract.realRegistrar()) {
            try Registrar(_registrar.addr).removeFromList(
                TTGRegistrarReader.EARNERS_LIST,
                actors[earnerIndex].addr
            ) {
                // success
            } catch Error(string memory _err) {
                expectedError(_err);
            } catch (bytes memory _err) {
                addExpectedError("NotStandardOrEmergencyGovernor()");
                expectedError(_err);
            }
        } else {
            MockTTGRegistrar(_registrar.addr).removeFromList(
                TTGRegistrarReader.EARNERS_LIST,
                actors[earnerIndex].addr
            );
        }
    }
}
