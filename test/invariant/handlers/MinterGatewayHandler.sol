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
import { MinterGateway, TTGRegistrarReader, ContinuousIndexingMath, IMToken } from "../lib/Protocol.sol";
import { MockRateModel, MockTTGRegistrar } from "../lib/Protocol.sol";
import { Registrar } from "../lib/Ttg.sol";

contract MinterGatewaySignatureBuilder {
    MinterGateway public minterGateway;
    constructor(MinterGateway minterGateway_) {
        minterGateway = minterGateway_;
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return minterGateway.DOMAIN_SEPARATOR();
    }

    function _getDigest(bytes32 _hash) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR(),
                    _hash
                )
            );
    }
    /**
     * @dev   Returns the EIP-712 digest for updateCollateral method
     * @param minter_       The address of the minter
     * @param collateral_   The amount of collateral
     * @param retrievalIds_ The list of outstanding collateral retrieval IDs to resolve
     * @param metadataHash_ The hash of metadata of the collateral update, reserved for future informational use
     * @param timestamp_    The timestamp of the collateral update
     */
    function getUpdateCollateralDigest(
        address minter_,
        uint256 collateral_,
        uint256[] calldata retrievalIds_,
        bytes32 metadataHash_,
        uint256 timestamp_
    ) public view returns (bytes32) {
        return
            _getDigest(
                keccak256(
                    abi.encode(
                        minterGateway.UPDATE_COLLATERAL_TYPEHASH(),
                        minter_,
                        collateral_,
                        retrievalIds_,
                        metadataHash_,
                        timestamp_
                    )
                )
            );
    }
}

contract MinterGatewayMathHelper {

    function overflowsPrincipal(uint256 amount, uint256 inactiveTotal, uint256 activeTotal, uint128 index) external pure returns (bool) {
        return (
                (_getPrincipalAmountRoundedUp(uint240(amount), index) + activeTotal + _getPrincipalAmountRoundedUp(uint240(inactiveTotal), index))
                >= type(uint112).max
        );
    }

    function _getPrincipalAmountRoundedUp(uint240 amount, uint128 index ) internal pure returns (uint112) {
        return ContinuousIndexingMath.divideUp(amount, index);
    }

}

contract MinterGatewayHandler is BaseHandler {
    MinterGateway                 public minterGateway;
    MinterGatewaySignatureBuilder public signatureBuilder;
    MinterGatewayMathHelper       public mathHelper;
    Registrar              public ttgRegistrar;

    // global checks
    uint256 public collateralTotal;
    uint256 public pendingRetrievalsTotal;
    uint256 public retreivedTotal;
    uint256 public proposeRetrievalSuccessCount;
    uint256 public proposeMintSuccessCount;

    // total proposed to mint
    uint256 public proposeMintTotal;
    // total pending to mint
    uint256 public pendingMintTotal;
    // total canceled from mint
    uint256 public cancelMintTotal;
    // total minted
    uint256 public mintedTotal;
    // total burned
    uint256 public burnMTotal;

    mapping(address => uint256)  public mTokenBalance;
    mapping(address => uint48[]) public pendingRetrievals;

    // internal storage, mostly to bypass Stack too deep errors
    struct PreUpdateCollateral {
        uint256 collateral;
        uint256 pendingRetrievals;
        uint256 validatorThreshold;
    }
    PreUpdateCollateral public preUpdateCollateralValues;

    bytes4 onHappyPath;
    bool sigChaosMonkey;
    uint256 invalidSignatures;
    mapping (address => uint8) public invalidValidators;

    modifier resetHappyPath() {
        _;
        if (msg.sig == onHappyPath) {
            onHappyPath = bytes4(0);
        }
    }

    modifier resetSigChaos {
        _;
        sigChaosMonkey = false;
        invalidSignatures = 0;
        for (uint256 i = 0; i < actors.length; i++) {
            invalidValidators[actors[i].addr] = 0;
        }
    }

    constructor(
        address _testContract,
        MinterGateway _minterGateway,
        Registrar _ttgRegistrar
    ) BaseHandler(_testContract) {
        minterGateway = _minterGateway;
        ttgRegistrar = _ttgRegistrar;
        signatureBuilder = new MinterGatewaySignatureBuilder(minterGateway);
        mathHelper = new MinterGatewayMathHelper();
    }

    function init(
        uint256 _numOfActors
    ) external {
        addActors(_numOfActors);
        zero = addActor(address(0), "zero");
        token = addActor(address(minterGateway), "MinterGateway");
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

    function _embarkOnHappyPath(bool localCondition) internal returns (bool) {
        // did another function already set this?
        if (onHappyPath != bytes4(0)) return true;
        // if not, should we start a happy path?
        if (localCondition && bound(rand(), 0, 10) == 3) {
            onHappyPath = msg.sig;
            return true;
        }
        // embrace the chaos
        return false;
    }

    //
    // Testable functions
    //
    function updateCollateral(
        uint256 _actorIndex,
        uint256 _collateral
    ) public
      resetErrors
      leap(_actorIndex)
      useRandomMsgSender(_actorIndex)
      resetSigChaos
      resetHappyPath
    {
        uint256[] memory retrievalIds;
        address[] memory validators;
        uint256[] memory timestamps;
        bytes[]   memory signatures;

        // we add collateralOf when successes are called, but when we need to subtract past collateral
        // it might be expired, so we need to use rawCollateralOf
        preUpdateCollateralValues = PreUpdateCollateral(
            rawCollateralOf(actor.addr),
            minterGateway.totalPendingCollateralRetrievalOf(actor.addr),
            0 // validator threshold, only relevant if we are changing it in prepareSuccessfulUpdateCollateral
        );

        bool happyPath = !testContract.realRegistrar() &&
                         _embarkOnHappyPath(
                            !minterGateway.isDeactivatedMinter(actor.addr) &&
                            !minterGateway.isFrozenMinter(actor.addr)
                         );

        if (happyPath) {
            (
                _collateral,
                retrievalIds,
                validators,
                timestamps,
                signatures
            ) = _prepareSuccessfulUpdateCollateral(_collateral, _actorIndex);
        } else {
            retrievalIds = new uint256[](bound(rand(), 0, currentRetrievalNonce()));
            for(uint256 i = 0; i < retrievalIds.length && i < 10; i++) {
                retrievalIds[i] = bound(rand(), 0, currentRetrievalNonce() + 1);
            }
            validators   = new address[](bound(rand(), 0, 10));
            for(uint256 i = 0; i < validators.length; i++) {
                InvariantUtils.Actor memory validator = actors[bound(_actorIndex, 0, actors.length - 1)];
                if (!isValidValidator(validator)) {
                    invalidSignatures++;
                }
                if (!minterGateway.isValidatorApprovedByTTG(validator.addr)) {
                    invalidSignatures++;
                }
                validators[i] = validator.addr;
            }
            timestamps   = new uint256[](bound(rand(), 0, 10));
            for(uint256 i = 0; i < timestamps.length; i++) {
                // get random timestamps in the recent past
                timestamps[i] = bound(rand(), block.timestamp - 10000, block.timestamp);
            }
            // ensure validators and signature have the same length so we can use validators to
            // build signatures.  we still get to test mismatched arrays because timestamps can be
            // different
            signatures   = new bytes[](validators.length);
            for(uint256 i = 0; i < signatures.length; i++) {
                signatures[i] = _buildSignature(
                                    bound(rand(), 0, 10),
                                    actors[_findActorIndex(validators[i])],
                                    actor.addr,
                                    _collateral,
                                    retrievalIds,
                                    bytes32(0), // metadataHash
                                    (i < timestamps.length) ? timestamps[i] : block.timestamp - 1
                                );
            }
        }

        startGas();
        try minterGateway.updateCollateral(
            _collateral,
            retrievalIds,
            bytes32(0), // metadataHash
            validators,
            timestamps,
            signatures
        ) {
            stopGas();
            // success
            // updateCollateral replaces not adds to the collateral
            // Issue #80, removing pendingRetrievals from the collateralTotal because it is not guaranteed
            // collateral >= pendingRetrievals
            collateralTotal -= preUpdateCollateralValues.collateral /* - preUpdateCollateralValues.pendingRetrievals*/;
            // Issue #80, collateralOf excludes pendingRetrievals, so have to use the new _collateral value here
            // collateralTotal += minterGateway.collateralOf(actor.addr);
            collateralTotal += _collateral;
            if (retrievalIds.length > 0) {
                uint256 retreived = preUpdateCollateralValues.pendingRetrievals - minterGateway.totalPendingCollateralRetrievalOf(actor.addr);
                pendingRetrievalsTotal -= retreived;
                retreivedTotal += retreived;
                uint48[] memory oldRetrievals = pendingRetrievals[actor.addr];
                delete pendingRetrievals[actor.addr];
                for(uint256 i = 0; i < oldRetrievals.length; i++) {
                    bool toRemove = false;
                    for(uint256 j = 0; j < retrievalIds.length; j++) {
                        if (oldRetrievals[i] == retrievalIds[j]) {
                            toRemove = true;
                            break;
                        }
                    }
                    if (!toRemove) {
                        pendingRetrievals[actor.addr].push(oldRetrievals[i]);
                    }
                }
            }
            if (happyPath && preUpdateCollateralValues.validatorThreshold != 0) {
                updateCollateralThreshold(_actorIndex, preUpdateCollateralValues.validatorThreshold);
            }
            delete preUpdateCollateralValues;
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (!happyPath) {
                if (!(minterGateway.isActiveMinter(actor.addr)))  addExpectedError("InactiveMinter()");
                if (_collateral > uint256(type(uint112).max))   addExpectedError("InvalidUInt112()");
                if (_collateral > uint256(type(uint240).max))    addExpectedError("InvalidUInt240()");
                if (!(validators.length == timestamps.length && timestamps.length == signatures.length)) addExpectedError("SignatureArrayLengthsMismatch()");

                for (uint256 i = 0; i < validators.length; i++) {
                    // if (!(minterGateway.isValidatorApprovedByTTG(validators[i]))) addExpectedError("NotApprovedValidator()");
                    if (i > 0 && validators[i] <= validators[i - 1]) addExpectedError("InvalidSignatureOrder()");
                }

                if (
                    signatures.length < minterGateway.updateCollateralValidatorThreshold() ||
                    (invalidSignatures > 0)
                ) addExpectedError("NotEnoughValidSignatures(uint256,uint256)");
            }

            expectedError(_err);
        }
    }

    function proposeRetrieval(
        uint256 _actorIndex,
        uint256 _collateral
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        startGas();
        try minterGateway.proposeRetrieval(_collateral) returns(uint48 retreivalId) {
            stopGas();
            // success
            // Issue #80, no longer subtracting pendingRetrievals from collateralTotal
            // because it is not guaranteed that collateral >= pendingRetrievals
            // collateralTotal -= _collateral;
            pendingRetrievalsTotal += _collateral;
            proposeRetrievalSuccessCount++;
            pendingRetrievals[actor.addr].push(retreivalId);
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (!(minterGateway.isActiveMinter(actor.addr)))                addExpectedError("InactiveMinter()");
            if (_collateral > uint256(type(uint240).max))                  addExpectedError("InvalidUInt240()");
            if (_isUndercollateralizedCollateral(actor.addr, _collateral)) addExpectedError("Undercollateralized(uint256,uint256)");
            uint256 totalPendingCollateralRetrievalOf = minterGateway.totalPendingCollateralRetrievalOf(actor.addr);
            if (type(uint256).max - _collateral < totalPendingCollateralRetrievalOf) {
                // addition on the next line would overflow
                addExpectedError("RetrievalsExceedCollateral(uint240,uint240)");
            } else if(
                _collateral +
                totalPendingCollateralRetrievalOf >
                minterGateway.collateralOf(actor.addr)
            ) {
                addExpectedError("RetrievalsExceedCollateral(uint240,uint240)");
            }
            if (_collateral < type(uint240).max && type(uint240).max - _collateral < totalPendingCollateralRetrievalOf) {
                // totalPendingCollateral gets _collateral added to it, so we need to check for overflow
                addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            }
            expectedError(_err);
        }
    }

    function proposeMint(
        uint256 _actorIndex,
        uint256 _amount,
        uint256 _destinationIndex
    ) public
      resetErrors
      leap(_actorIndex)
      useRandomMsgSender(_actorIndex)
      resetHappyPath
    {
        uint256 destinationIndex = bound(_destinationIndex, 0, actors.length - 1);
        uint256 underCollateralizedBy = _isUndercollateralizedMToken(actor.addr, _amount);

        bool happyPath = !testContract.realRegistrar() &&
                         _embarkOnHappyPath(
                            !minterGateway.isDeactivatedMinter(actor.addr) &&
                            !minterGateway.isFrozenMinter(actor.addr)
                         );

        if (happyPath) {
            // setup and use a valid minter 1/3 of the time (deactivated minters can't be recovered)
            _amount = bound(_amount, 0, type(uint112).max);
            underCollateralizedBy = _isUndercollateralizedMToken(actor.addr, _amount);
            if (underCollateralizedBy > 0) {
                etchLeap();
                updateCollateral(_actorIndex, minterGateway.collateralOf(actor.addr) + underCollateralizedBy);
            }
            // reset the Prank to our actor
            changePrank(actor.addr);
            underCollateralizedBy = _isUndercollateralizedMToken(actor.addr, _amount);
        }

        (/*_mintId*/, /*createdAt*/, /*address destination_*/, uint256 previousProposeMint) = minterGateway.mintProposalOf(actor.addr);

        startGas();
        try minterGateway.proposeMint(
            _amount,
            actors[destinationIndex].addr // destination
        ) {
            stopGas();
            // success
            // user's can only have one proposeMint at a time
            proposeMintTotal -= previousProposeMint;
            pendingMintTotal -= previousProposeMint;
            // add new one
            proposeMintTotal += _amount;
            pendingMintTotal += _amount;
            proposeMintSuccessCount++;
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (!happyPath) {
                if (_amount > uint256(type(uint240).max))       addExpectedError("InvalidUInt240()");
                if (!(minterGateway.isActiveMinter(actor.addr))) addExpectedError("InactiveMinter()");
                if (minterGateway.isFrozenMinter(actor.addr))    addExpectedError("FrozenMinter()");
            }
            // Can potentially still be undercollateralized due to expiring collateral
            if(_isUndercollateralizedMToken(actor.addr, _amount) > 0) addExpectedError("Undercollateralized(uint256,uint256)");
            expectedError(_err);
        }
    }

    function mintM(
        uint256 _actorIndex,
        uint256 _mintId
    ) public
      resetErrors
      leap(_actorIndex)
      useRandomMsgSender(_actorIndex)
      resetHappyPath
    {
        uint240 amount;
        uint40 createdAt;
        (_mintId, createdAt, /*address destination_*/, amount) = minterGateway.mintProposalOf(actor.addr);
        uint240 activeAt = createdAt + minterGateway.mintDelay();

        bool happyPath = !testContract.realRegistrar() &&
                         _embarkOnHappyPath(
                            !minterGateway.isDeactivatedMinter(actor.addr) &&
                            !minterGateway.isFrozenMinter(actor.addr)
                         );
        if (happyPath) {
            // setup and use a valid minter 1/3 of the time (deactivated minters can't be recovered)
            etchLeap();
            // See Issue #77 for why we need to do this bounding
            amount = uint240(bound(rand(), 0, type(uint112).max));
            proposeMint(_actorIndex, amount, rand());
            etchLeap();

            changePrank(actor.addr);
            (_mintId, createdAt,, amount) = minterGateway.mintProposalOf(actor.addr);
            activeAt = createdAt + minterGateway.mintDelay();
            paelRange(minterGateway.mintDelay(), 0, minterGateway.mintDelay());
        }

        uint256 prevPrincipalOfTotalActiveOwedM = minterGateway.principalOfTotalActiveOwedM();

        startGas();
        try minterGateway.mintM(_mintId) returns (uint112 /*principalAmount*/, uint240 _amount) {
            stopGas();
            // success
            require(_amount == amount, "amounts do not match");
            require(prevPrincipalOfTotalActiveOwedM <= minterGateway.principalOfTotalActiveOwedM(), "principalOfTotalActiveOwedM not increased");
            mTokenBalance[actor.addr] += _amount;
            mintedTotal += _amount;
            pendingMintTotal -= _amount;
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (!happyPath) {
                if (!(minterGateway.isActiveMinter(actor.addr))) addExpectedError("InactiveMinter()");
                if (minterGateway.isFrozenMinter(actor.addr))    addExpectedError("FrozenMinter()");
                if(block.timestamp < activeAt)                   addExpectedError("PendingMintProposal(uint40)");
                if(amount > type(uint112).max)                   addExpectedError("InvalidUInt112()");
                (uint48 mintId , /*createdAt*/, /*address destination_*/, /*amount*/) = minterGateway.mintProposalOf(actor.addr);
                if (_mintId != mintId)                           addExpectedError("InvalidMintProposal()");
            }


            startGas();
            minterGateway.updateIndex();
            // rounding up might overflow uint112 in the test with large amounts or inactiveM
            try mathHelper.overflowsPrincipal(
                amount,
                minterGateway.totalInactiveOwedM(),
                uint256(minterGateway.principalOfTotalActiveOwedM()),
                minterGateway.currentIndex()
            ) returns (bool overflows) {
                stopGas();

                if (overflows) addExpectedError("OverflowsPrincipalOfTotalOwedM()");
            } catch {
            }

            // Related to Issue #88
            if (_willOverflowMTokenMint(actor.addr, amount)) addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
            // Can potentially still be undercollateralized due to expiring collateral
            if(_isUndercollateralizedMToken(actor.addr, amount) > 0) addExpectedError("Undercollateralized(uint256,uint256)");
            if(block.timestamp > activeAt + minterGateway.mintTTL()) addExpectedError("ExpiredMintProposal(uint40)");
            expectedError(_err);
        }
    }

    function _willOverflowMTokenMint(address addr, uint256 amount) internal view returns (bool) {
        IMToken mToken = IMToken(minterGateway.mToken());
        bool isEarning;
        uint256 balanceOf;
        uint256 totalSupply;
        // we have to try catch these because the mock MToken will not respond to these calls
        try mToken.isEarning(addr) returns (bool isEarning_) {
            isEarning = isEarning_;
        } catch { }
        try mToken.balanceOf(addr) returns (uint256 balanceOf_) {
            balanceOf = balanceOf_;
        } catch { }
        try mToken.totalSupply() returns (uint256 totalSupply_) {
            totalSupply = totalSupply_;
        } catch { }
        return (
            (isEarning && type(uint112).max < balanceOf + amount) ||
            type(uint112).max < totalSupply + amount
            );
    }

    function burnM_minterMax(
        uint256 _actorIndex,
        address _minter,
        uint256 _maxAmount
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        startGas();
        try minterGateway.burnM(
            _minter,
            _maxAmount
        ) returns(uint112 /* principalAmount */, uint240 amount) {
            stopGas();
            // success
            require(amount <= uint240(_maxAmount), "amount burned exceeds maxAmount");
            burnMTotal += amount;
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (_maxAmount > type(uint240).max) {
                addExpectedError("InvalidUInt240()");
            } else if (_maxAmount > type(uint112).max) {
                addExpectedError("InvalidUInt112()");
            } else {
                uint112 _maxPrincipalAmount = _getPrincipalAmountRoundedDown(uint240(_maxAmount));
                uint112 principalAmount = _min112(minterGateway.principalOfActiveOwedMOf(_minter), uint112(_maxPrincipalAmount));
                uint256 amountToRepay = _getPresentAmount(principalAmount);
                if (amountToRepay > _maxAmount) addExpectedError("ExceedsMaxRepayAmount(uint240,uint240)");
            }

            expectedError(_err);
        }
    }

    function burnM_minterPrincipalMax(
        uint256 _actorIndex,
        address _minter,
        uint256 _maxAmount,
        uint256 _maxPrincipalAmount
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {

        startGas();
        try minterGateway.burnM(
            _minter,
            _maxPrincipalAmount,
            _maxAmount
        ) returns(uint112 /* principalAmount */, uint240 amount) {
            stopGas();

            // success
            require(amount <= uint240(_maxAmount), "amount burned exceeds maxAmount");
            burnMTotal += amount;
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (_maxPrincipalAmount > uint256(type(uint112).max)) addExpectedError("InvalidUInt112()");
            if (_maxAmount > uint256(type(uint240).max))          addExpectedError("InvalidUInt240()");

            uint112 principalAmount = _min112(minterGateway.principalOfActiveOwedMOf(_minter), uint112(_maxPrincipalAmount));
            uint256 amountToRepay = _getPresentAmount(principalAmount);
            if (amountToRepay > _maxAmount) addExpectedError("ExceedsMaxRepayAmount(uint240,uint240)");
            expectedError(_err);
        }
    }

    function cancelMint(
        uint256 _actorIndex,
        address _minter,
        uint256 _mintId
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        (uint48 mintId, /*uint40 createdAt_*/, /*address destination_*/, uint240 amount_) = minterGateway.mintProposalOf(_minter);

        startGas();
        try minterGateway.cancelMint(
            _minter,
            _mintId
        ) {
            stopGas();

            // success
            cancelMintTotal += amount_;
            pendingMintTotal -= amount_;
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (!(minterGateway.isValidatorApprovedByTTG(actor.addr))) addExpectedError("NotApprovedValidator()");
            if (_mintId != mintId) addExpectedError("InvalidMintProposal()");
            expectedError(_err);
        }
    }

    function freezeMinter(
        uint256 _actorIndex,
        uint256 _minterIndex
    ) public
      resetErrors
      leap(_actorIndex)
      useRandomMsgSender(_actorIndex)
      resetHappyPath
    {
        address _minter = actors[bound(_minterIndex, 0, actors.length - 1)].addr;
        // no local conditions for happy path (see Issue #84)
        if (_embarkOnHappyPath(true)) {
            // approve minter
            approveMinter(_actorIndex, _minterIndex);
            // activate minter
            activateMinter(_actorIndex, _minterIndex);
            changePrank(actor.addr);
        }

        startGas();
        try minterGateway.freezeMinter(
            _minter
        ) {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (!(minterGateway.isValidatorApprovedByTTG(actor.addr))) addExpectedError("NotApprovedValidator()");
            expectedError(_err);
        }
    }

    function activateMinter(
        uint256 _actorIndex,
        uint256 _minterIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint256 minterIndex = bound(_minterIndex, 0, actors.length - 1);

        address minterAddr = actors[minterIndex].addr;

        startGas();
        try minterGateway.activateMinter(
            minterAddr
        ) {
            stopGas();
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (!(minterGateway.isMinterApproved(minterAddr)))    addExpectedError("NotApprovedMinter()");
            if (minterGateway.isDeactivatedMinter(minterAddr))    addExpectedError("DeactivatedMinter()");
            expectedError(_err);
        }
    }

    function deactivateMinter(
        uint256 _actorIndex,
        uint256 _minterIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint256 minterIndex = bound(_minterIndex, 0, actors.length - 1);
        // get the raw in case it is expired collateral
        uint256 collateral = rawCollateralOf(actors[minterIndex].addr);
        uint256 totalPendingRetrievals = minterGateway.totalPendingCollateralRetrievalOf(actors[minterIndex].addr);
        (/*_mintId*/, /*createdAt*/, /*address destination_*/, uint256 previousProposeMint) = minterGateway.mintProposalOf(actors[minterIndex].addr);

        address minterAddr = actors[minterIndex].addr;

        startGas();
        try minterGateway.deactivateMinter(
            minterAddr
        ) {
            stopGas();
            // success
            // Issue #80, removing totalPendingRetrievals from the collateralTotal because it is not guaranteed
            // collateral >= totalPendingRetrievals
            collateralTotal -= collateral /* - totalPendingRetrievals */;
            pendingRetrievalsTotal -= totalPendingRetrievals;
            proposeMintTotal -= previousProposeMint;
            pendingMintTotal -= previousProposeMint;
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            if (!(minterGateway.isActiveMinter(minterAddr))) addExpectedError("InactiveMinter()");
            if (minterGateway.isMinterApproved(minterAddr))  addExpectedError("StillApprovedMinter()");
            expectedError(_err);
        }
    }

    function updateIndex(
        uint256 _actorIndex
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        minterGateway.updateIndex();
    }

    // TTGRegistrar Functions
    function approveMinter(
        uint256 _actorIndex,
        uint256 _minterIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint256 minterIndex = bound(_minterIndex, 0, actors.length - 1);

        try ttgRegistrar.addToList(
            TTGRegistrarReader.MINTERS_LIST,
            actors[minterIndex].addr
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("NotStandardOrEmergencyGovernor()");
            expectedError(_err);
        }
    }

    function disapproveMinter(
        uint256 _actorIndex,
        uint256 _minterIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint256 minterIndex = bound(_minterIndex, 0, actors.length - 1);

        try ttgRegistrar.removeFromList(
            TTGRegistrarReader.MINTERS_LIST,
            actors[minterIndex].addr
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("NotStandardOrEmergencyGovernor()");
            expectedError(_err);
        }
    }

    function approveValidator(
        uint256 _actorIndex,
        uint256 _validatorIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint256 validatorIndex = bound(_validatorIndex, 0, actors.length - 1);

        try ttgRegistrar.addToList(
            TTGRegistrarReader.VALIDATORS_LIST,
            actors[validatorIndex].addr
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("NotStandardOrEmergencyGovernor()");
            expectedError(_err);
        }
    }

    function disapproveValidator(
        uint256 _actorIndex,
        uint256 _validatorIndex
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        uint256 validatorIndex = bound(_validatorIndex, 0, actors.length - 1);

        try ttgRegistrar.removeFromList(
            TTGRegistrarReader.VALIDATORS_LIST,
            actors[validatorIndex].addr
        ) {
            // success
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            addExpectedError("NotStandardOrEmergencyGovernor()");
            expectedError(_err);
        }
    }

    function updateCollateralInterval(
        uint256 _actorIndex,
        uint32  _interval
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        if (testContract.realRegistrar()) {
            try ttgRegistrar.setKey(TTGRegistrarReader.UPDATE_COLLATERAL_INTERVAL, bytes32(uint256(_interval))) {
                // success
            } catch Error(string memory _err) {
                expectedError(_err);
            } catch (bytes memory _err) {
                addExpectedError("NotStandardOrEmergencyGovernor()");
                expectedError(_err);
            }
        } else {
            MockTTGRegistrar(address(ttgRegistrar)).updateConfig(TTGRegistrarReader.UPDATE_COLLATERAL_INTERVAL, _interval);
        }
    }

    function updateCollateralThreshold(
        uint256 _actorIndex,
        uint256 _threshold
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        if (testContract.realRegistrar()) {
            try ttgRegistrar.setKey(TTGRegistrarReader.UPDATE_COLLATERAL_VALIDATOR_THRESHOLD, bytes32(_threshold)) {
                // success
            } catch Error(string memory _err) {
                expectedError(_err);
            } catch (bytes memory _err) {
                addExpectedError("NotStandardOrEmergencyGovernor()");
                expectedError(_err);
            }
        } else {
            MockTTGRegistrar(address(ttgRegistrar)).updateConfig(TTGRegistrarReader.UPDATE_COLLATERAL_VALIDATOR_THRESHOLD, _threshold);
        }
    }

    function updateMintRatio(
        uint256 _actorIndex,
        uint32  _ratio
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        // setting a min ratio of 1 to avoid divide by 0 errors in our _isUndercollateralizedBy function
        // ref: Issue #73, Issue #90
        uint256 ratio = bound(_ratio, 1, 10_000);
        // can be set to anything but MinterGateway caps at 10_000% (100 * uint32(10_000))
        if (testContract.realRegistrar()) {
            try ttgRegistrar.setKey(TTGRegistrarReader.MINT_RATIO, bytes32(ratio)) {
                // success
            } catch Error(string memory _err) {
                expectedError(_err);
            } catch (bytes memory _err) {
                addExpectedError("NotStandardOrEmergencyGovernor()");
                expectedError(_err);
            }
        } else {
            MockTTGRegistrar(address(ttgRegistrar)).updateConfig(TTGRegistrarReader.MINT_RATIO, uint32(ratio));
        }
    }

    function updateMintTTL(
        uint256 _actorIndex,
        uint32  _ttl
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        if (testContract.realRegistrar()) {
            try ttgRegistrar.setKey(TTGRegistrarReader.MINT_TTL, bytes32(uint256(_ttl))) {
                // success
            } catch Error(string memory _err) {
                expectedError(_err);
            } catch (bytes memory _err) {
                addExpectedError("NotStandardOrEmergencyGovernor()");
                expectedError(_err);
            }
        } else {
            MockTTGRegistrar(address(ttgRegistrar)).updateConfig(TTGRegistrarReader.MINT_TTL, _ttl);
        }
    }

    function updateMintFreezerTime(
        uint256 _actorIndex,
        uint32  _time
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        if (testContract.realRegistrar()) {
            try ttgRegistrar.setKey(TTGRegistrarReader.MINTER_FREEZE_TIME, bytes32(uint256(_time))) {
                // success
            } catch Error(string memory _err) {
                expectedError(_err);
            } catch (bytes memory _err) {
                addExpectedError("NotStandardOrEmergencyGovernor()");
                expectedError(_err);
            }
        } else {
            MockTTGRegistrar(address(ttgRegistrar)).updateConfig(TTGRegistrarReader.MINTER_FREEZE_TIME, _time);
        }
    }

    function updatePenaltyRate(
        uint256 _actorIndex,
        uint32  _penaltyRate
    ) public resetErrors leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        if (testContract.realRegistrar()) {
            try ttgRegistrar.setKey(TTGRegistrarReader.PENALTY_RATE, bytes32(uint256(_penaltyRate))) {
                // success
            } catch Error(string memory _err) {
                expectedError(_err);
            } catch (bytes memory _err) {
                addExpectedError("NotStandardOrEmergencyGovernor()");
                expectedError(_err);
            }
        } else {
            MockTTGRegistrar(address(ttgRegistrar)).updateConfig(TTGRegistrarReader.PENALTY_RATE, _penaltyRate);
        }
    }

    function updateRateModel(
        uint256 _actorIndex,
        uint256 newRateModelRate
    ) public leap(_actorIndex) useRandomMsgSender(_actorIndex) {
        // Expectation is that TTG will only set rates between 0 and 40_000
        newRateModelRate = bound(newRateModelRate, 0, 100_000);
        // changing the rate model address does not really matter in this context
        // we should update the value returned by the `MockRateModel` instead
        address rateModel = minterGateway.rateModel();
        // TODO: fix this hack to swap the real rate model
        if (!testContract.integration()) {
            MockRateModel(rateModel).setRate(newRateModelRate);
        }
    }

    ///////////////// HELPER FUNCTIONS /////////////////
    function mTokenBalanceOf(address addr) public view returns (uint256) {
        return mTokenBalance[addr];
    }

    function rawCollateralOf(address addr) public view returns (uint256 rawCollateral) {
        uint256 baseSlot = 4; // Minter States in slot 4
        bytes32 slot = keccak256(abi.encodePacked(uint256(uint160(addr)), baseSlot));
        (bytes32 bytes32MinterState0) = vm.load(address(minterGateway), slot);
        if (bytes32MinterState0 != bytes32(0)) {
            // Extracting uint240, shift right by 16 bits (265 - 240) to get our collateral value
            uint240 _rawCollateral = uint240(uint256(bytes32MinterState0) >> (256 - 240));
            rawCollateral = _rawCollateral;
        }
    }

    function rawPenalizedUntilTimestamp(address addr) public view returns (uint48 ts) {
        uint256 baseSlot = 6; // Minter States in slot 4 but span 3 slots
        bytes32 slot = keccak256(abi.encodePacked(uint256(uint160(addr)), baseSlot));
        (bytes32 bytes32MinterState2) = vm.load(address(minterGateway), slot);
        console.log("bytes32MinterState2:");
        console.logBytes32(bytes32MinterState2);
        if (bytes32MinterState2 != bytes32(0)) {
            // Extracting penalizedUntilTimestamp value
            ts = uint48(uint256(bytes32MinterState2) >> (256 - 80));
        }
    }

    function rawUpdateTimestamp(address addr) public view returns (uint48 ts) {
        uint256 baseSlot = 6; // Minter States in slot 4 but spans 3 slots
        bytes32 slot = keccak256(abi.encodePacked(uint256(uint160(addr)), baseSlot));
        (bytes32 bytes32MinterState2) = vm.load(address(minterGateway), slot);
        if (bytes32MinterState2 != bytes32(0)) {
            // Extracting updateTimestamp value
            ts = uint48(uint256(bytes32MinterState2) >> (256 - 40));
        }
    }

    function currentRetrievalNonce() public view returns (uint48 retreivalNonce) {
        // {"label":"_retrievalNonce","offset":20,"slot":"3","type":"t_uint48"}
        uint256 baseSlot = 3; // Minter States in slot 3
        (bytes32 bytes32RetrievalNonce) = vm.load(address(minterGateway), bytes32(baseSlot));
        retreivalNonce = uint48(uint256(bytes32RetrievalNonce) >> 160);
    }

    function currentMintNonce() public view returns (uint48 mintNonce) {
        // {"label":"_mintNonce","offset":14,"slot":"3","type":"t_uint48"}
        uint256 baseSlot = 3; // Minter States in slot 3
        (bytes32 bytes32MintNonce) = vm.load(address(minterGateway), bytes32(baseSlot));
        mintNonce = uint48(uint256(bytes32MintNonce) >> 112);
    }

    function _isUndercollateralizedCollateral(address addr, uint256 newCollateral) internal view returns (bool) {
        uint256 newTotalCollateral = minterGateway.collateralOf(addr) > newCollateral ? minterGateway.collateralOf(addr) - newCollateral : 0;
        uint256 newMaxAllowedM = newTotalCollateral * minterGateway.mintRatio() / 10_000;
        uint256 currentMOwed = minterGateway.activeOwedMOf(addr);
        return newMaxAllowedM < currentMOwed;
    }
    function _isUndercollateralizedMToken(address addr, uint256 newMToken) internal view returns (uint256 newCollateralNeeded) {
        // bail early if we're not going to be able to do the math
        if(newMToken > type(uint240).max) return newMToken;

        uint256 totalMOwed = minterGateway.activeOwedMOf(addr) + newMToken;
        uint256 totalCollateralNeeded = (totalMOwed * 10_000 / minterGateway.mintRatio()) + 1 /* rounding up */;

        newCollateralNeeded = totalCollateralNeeded > minterGateway.collateralOf(addr) ? totalCollateralNeeded - minterGateway.collateralOf(addr) : 0;
    }

    function _getPrincipalAmountRoundedDown(uint240 amount) internal view returns (uint112) {
        return ContinuousIndexingMath.divideDown(amount, minterGateway.currentIndex());
    }

    function _min112(uint112 a_, uint112 b_) internal pure returns (uint112) {
        return a_ < b_ ? a_ : b_;
    }

    function _getPresentAmount(uint112 principalAmount) internal view returns (uint240) {
        return ContinuousIndexingMath.multiplyUp(principalAmount, minterGateway.currentIndex());
    }

    function _buildSignature(
        uint256 chaos,
        InvariantUtils.Actor memory signer,
        address minter_,
        uint256 collateral_,
        uint256[] memory retrievalIds_,
        bytes32 metadataHash_,
        uint256 timestamp_
    ) internal returns (bytes memory signature) {
        // build signature
        InvariantUtils.Signature memory sign;
        bytes32 digest = signatureBuilder.getUpdateCollateralDigest(
            minter_,
            collateral_,
            retrievalIds_,
            metadataHash_,
            timestamp_
        );

        (sign.v, sign.r, sign.s) = vm.sign(signer.key, digest);
        // 10% of the time release a signature chaos monkey
        if (chaos == 0)  {
            sigChaosMonkey = true;
            invalidSignatures++;
            sign.v = uint8(sign.v + bound(rand(), 0, 2));
            sign.s = bytes32(rand());
        }
        signature = abi.encodePacked(sign.r, sign.s, sign.v);
    }

    function _prepareSuccessfulUpdateCollateral(
        uint256 _collateral,
        uint256 _actorIndex
    ) internal returns (
        uint256 collateral,
        uint256[] memory retrievalIds,
        address[] memory validators,
        uint256[] memory timestamps,
        bytes[] memory signatures
    ) {
        // setup and use a valid minter 1/3 of the time (deactivated minters can't be recovered)
        uint256 minterIndex = _findActorIndex(actor.addr);
        etchLeap();
        InvariantUtils.Actor memory minter = actor;
        approveMinter(rand(), minterIndex);
        etchLeap();
        activateMinter(rand(), minterIndex);
        preUpdateCollateralValues.validatorThreshold = minterGateway.updateCollateralValidatorThreshold();
        uint256 numSig = bound(rand(), 0, 3);
        updateCollateralThreshold(_actorIndex, numSig);
        etchLeap();
        // reset the actor to minter and Prank to our actor
        actor = minter;
        changePrank(actor.addr);
        collateral = bound(_collateral, 0, type(uint112).max);
        retrievalIds = new uint256[](pendingRetrievals[actor.addr].length <= 3 ? pendingRetrievals[actor.addr].length : 3);
        // populate up to 3 retrievalIds
        for(uint256 i = 0; i < retrievalIds.length; i++) {
            retrievalIds[i] = pendingRetrievals[actor.addr][i];
        }
        validators = new address[](numSig);
        timestamps = new uint256[](numSig);
        signatures = new bytes[](numSig);
        for (uint256 i = 0; i < numSig;) {
            InvariantUtils.Actor memory potentialValidator;
            potentialValidator = actors[bound(rand(), 0, actors.length - 1)];

            if (isValidValidator(potentialValidator)) {
                invalidValidators[potentialValidator.addr] = 1;
                validators[i] = potentialValidator.addr;
                approveValidator(_actorIndex, _findActorIndex(potentialValidator.addr));
                etchLeap();
                timestamps[i] = block.timestamp - i;
                i++;
            }
        }
        changePrank(actor.addr);
        validators = _sortAsc(validators);
        for (uint256 i = 0; i < numSig; i++) {
            signatures[i] = _buildSignature(
                1, // we don't want chaos on this path so !0
                actors[_findActorIndex(validators[i])],
                actor.addr,
                collateral,
                retrievalIds,
                bytes32(0), // metadataHash
                timestamps[i]
            );
        }
    }

    function isValidValidator(InvariantUtils.Actor memory validator) public view returns (bool) {
        if (validator.addr != InvariantUtils.GetAddress(validator.key)) return false;
        return invalidValidators[validator.addr] == 0;
    }

    function _sortAsc(address[] memory _addresses) internal pure returns (address[] memory) {
        address[] memory addresses = _addresses;
        for (uint256 i = 0; i < addresses.length; i++) {
            for (uint256 j = i + 1; j < addresses.length; j++) {
                if (addresses[i] > addresses[j]) {
                    address temp = addresses[i];
                    addresses[i] = addresses[j];
                    addresses[j] = temp;
                }
            }
        }
        return addresses;
    }

}
