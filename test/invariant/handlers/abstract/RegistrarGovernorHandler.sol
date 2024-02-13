
pragma solidity ^0.8.23;

import "./ThresholdGovernorHandler.sol";

import { MinterRateModel, SplitEarnerRateModel, StableEarnerRateModel } from "../../lib/Protocol.sol";

interface IRegistrarGovernor {
    function addToList(bytes32 list, address account) external;

    function removeFromList(bytes32 list, address account) external;

    function removeFromAndAddToList(bytes32 list, address accountToRemove, address accountToAdd) external;

    function setKey(bytes32 key, bytes32 value) external;
}

abstract contract RegistrarGovernorHandler is ThresholdGovernorHandler {

    // These are the list keys expected by TTGRegistrarReader
    // We want some successful calls to use these keys
    bytes32[3] public listKeys = [
        bytes32("earners"), // EARNERS_LIST
        bytes32("minters"), // MINTERS_LIST
        bytes32("validators") // VALIDATORS_LIST
    ];

    // These are the set keys expected by TTGRegistrarReader
    // to have bytes32 values
    bytes32[1] public keysBytes32 = [
        bytes32("earners_list_ignored") // EARNERS_LIST_IGNORED
    ];

    // These are the set keys expected by TTGRegistrarReader
    // to have uint256 values
    bytes32[9] public keysUint256 = [
        bytes32("base_earner_rate"), // BASE_EARNER_RATE
        bytes32("base_minter_rate"), // BASE_MINTER_RATE
        bytes32("mint_delay"), // MINT_DELAY
        bytes32("minter_freeze_time"), // MINTER_FREEZE_TIME
        bytes32("mint_ttl"), // MINT_TTL
        bytes32("mint_ratio"), // MINT_RATIO
        bytes32("updateCollateral_interval"), // UPDATE_COLLATERAL_INTERVAL
        bytes32("updateCollateral_threshold"), // UPDATE_COLLATERAL_VALIDATOR_THRESHOLD
        bytes32("penalty_rate") // PENALTY_RATE
    ];

    // These are the set keys expected by TTGRegistrarReader
    // to have address values
    bytes32[2] public keysAddress = [
        bytes32("earner_rate_model"), // EARNER_RATE_MODEL
        bytes32("minter_rate_model")  // MINTER_RATE_MODEL
    ];

    address[4] public rateModels;

    constructor() {}

    function _initRateModels(address registrar) public {
        rateModels[0] = address(new MinterRateModel(registrar));
        rateModels[1] = address(new MinterRateModel(registrar));
        rateModels[2] = address(new MinterRateModel(registrar));
        rateModels[3] = address(new MinterRateModel(registrar));
    }

    function _initRateModels(address registrar, address minterGateway) public {
        rateModels[0] = address(new MinterRateModel(registrar));
        rateModels[1] = address(new MinterRateModel(registrar));
        rateModels[2] = address(new SplitEarnerRateModel(minterGateway));
        rateModels[3] = address(new StableEarnerRateModel(minterGateway));
    }

    function addToList(
        uint256 _actorIndex,
        bytes32 list,
        address account
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, governor, 33) {

        if (rand() % 100 < 75) {
            // 75% chance of using a valid list key
            list = listKeys[bound(rand(), 0, listKeys.length - 1)];
        }

        if (rand() % 100 < 50) {
            // 50% chance of using a valid address
            account = actors[bound(_actorIndex, 0, actors.length - 1)].addr;
        }

        startGas();
        try IRegistrarGovernor(governor).addToList(
            list,
            account
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

    function removeFromList(
        uint256 _actorIndex,
        bytes32 list,
        address account
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, governor, 33) {

        if (rand() % 100 < 75) {
            // 75% chance of using a valid list key
            list = listKeys[bound(rand(), 0, listKeys.length - 1)];
        }

        if (rand() % 100 < 50) {
            // 50% chance of using a valid address
            account = actors[bound(_actorIndex, 0, actors.length - 1)].addr;
        }

        startGas();
        try IRegistrarGovernor(governor).removeFromList(
            list,
            account
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

    function removeFromAndAddToList(
        uint256 _actorIndex,
        bytes32 list,
        address accountToRemove,
        address accountToAdd
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, governor, 33) {

        if (rand() % 100 < 75) {
            // 75% chance of using a valid list key
            list = listKeys[bound(rand(), 0, listKeys.length - 1)];
        }

        if (rand() % 100 < 50) {
            // 50% chance of using valid addresses
            accountToRemove = actors[bound(_actorIndex, 0, actors.length - 1)].addr;
            accountToAdd = actors[bound(_actorIndex, 0, actors.length - 1)].addr;
        }

        startGas();
        try IRegistrarGovernor(governor).removeFromAndAddToList(
            list,
            accountToRemove,
            accountToAdd
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

    function setKeyBytes32(
        uint256 _actorIndex,
        bytes32 key,
        bytes32 value
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, governor, 33) {

        if (rand() % 100 < 75) {
            // 75% chance of using a valid list key
            // there is only one so we can just use the first one
            key = keysBytes32[0];
        }

        if (rand() % 100 < 50) {
            // 50% chance of using valid addresses
            // if the earners_list_ignored is set to anything but 0, it will be ignored
            // so 50% of the time we will set it to 0 to turn the list on
            value = bytes32(0);
        }

        startGas();
        try IRegistrarGovernor(governor).setKey(
            key,
            value
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

    function setKeyUint256(
        uint256 _actorIndex,
        bytes32 key,
        uint256 value
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, governor, 33) {

        if (rand() % 100 < 75) {
            // 75% chance of using a valid list key
            key = keysUint256[bound(rand(), 0, keysUint256.length - 1)];
        }

        if (key == "base_earner_rate") {
            value = bound(value, 0, 40_000);
        } else if (key == "base_minter_rate") {
            value = bound(value, 0, 40_000);
        } else if (key == "mint_delay") {
            value = bound(value, 1, 10 * 365 days);
        } else if (key == "minter_freeze_time") {
            value = bound(value, 0, 10 * 365 days);
        } else if (key == "mint_ttl") {
            value = bound(value, 1, 10 * 365 days);
        } else if (key == "mint_ratio") {
            // See Issue #73
            value = bound(value, 1, 10_000);
        } else if (key == "updateCollateral_interval") {
            if (rand() % 100 < 50) {
                // 50% chance of using between 1 hour and 24 hours
                value = bound(value, 1 hours, 24 hours);
            } else {
                // 50% chance of using a valid address
                value = bound(value, 1, 10 * 365 days);
            }
        } else if (key == "updateCollateral_threshold") {
            value = bound(value, 0, 1_000);
        } else if (key == "penalty_rate") {
            value = bound(value, 0, 20_000);
        }

        startGas();
        try IRegistrarGovernor(governor).setKey(
            key,
            bytes32(value)
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

    function setKeyAddress(
        uint256 _actorIndex,
        bytes32 key,
        address value
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, governor, 33) {

        if (rand() % 100 < 75) {
            // 75% chance of using a valid list key
            key = keysAddress[bound(rand(), 0, keysAddress.length - 1)];
        }

        if (rand() % 100 < 50) {
            // 50% chance of using valid addresses
            // However, we do not distinguish between minter and earner rate models
            value = rateModels[bound(_actorIndex, 0, rateModels.length - 1)];
        }

        startGas();
        try IRegistrarGovernor(governor).setKey(
            key,
            bytes32(uint256(uint160(value)))
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
