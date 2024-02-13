
pragma solidity ^0.8.23;

import "./base/BaseHandler.sol";
import { Registrar } from "../lib/Ttg.sol";

contract RegistrarHandler is BaseHandler {
    Registrar public registrar;

    uint256 public notStandardOrEmergencyGovernorViolationCount;

    bytes32[] _keys;
    bytes32[] _values;
    uint256   _keynum;

    constructor(
        address _testContract,
        Registrar _registrar
    ) BaseHandler(_testContract) {
        registrar = _registrar;
    }

    function init() external {
        addActors();
        zero = addActor(address(0), "zero");
        token = addActor(address(registrar), "registrar");
        addActor(registrar.standardGovernor(), "standardGovernor");
        addActor(registrar.emergencyGovernor(), "emergencyGovernor");

        validateActors();
    }

    function init(
        InvariantUtils.Actor[] memory _actors,
        InvariantUtils.Actor[] memory _receivers
    ) external {
        for(uint256 i = 0; i < _receivers.length; i++) {
            actors.push(_receivers[i]);

            if (_receivers[i].addr == registrar.standardGovernor()) {
                // we want the standardGovernor to be able to call the Registrar
                msgSenders.push(_receivers[i]);
            }

            if (_receivers[i].addr == registrar.emergencyGovernor()) {
                // we want the emergencyGovernor to be able to call the Registrar
                msgSenders.push(_receivers[i]);
            }

            if (_receivers[i].addr == registrar.zeroGovernor()) {
                // we want the zeroGovernor to be able to call the Registrar
                // though it should fail if it tries
                msgSenders.push(_receivers[i]);
            }
        }

        validateActors(actors);

        for(uint256 i = 0; i < _actors.length; i++) {
            msgSenders.push(_actors[i]);
        }

        validateActors(msgSenders);

    }

    function getKeys() external view returns (bytes32[] memory) {
        return _keys;
    }

    function getValues() external view returns (bytes32[] memory) {
        return _values;
    }

    //
    // Testable functions
    //
    function addToList(
        uint256 _actorIndex,
        bytes32 _list,
        address _account
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, registrar.standardGovernor(), 50) {

        if (actor.addr != registrar.standardGovernor() &&
            actor.addr != registrar.emergencyGovernor()) {
                addExpectedError("NotStandardOrEmergencyGovernor()");
        }

        startGas();
        try registrar.addToList(_list, _account) {
            stopGas();

            require(registrar.listContains(_list, _account));

            if (actor.addr != registrar.standardGovernor() &&
                actor.addr != registrar.emergencyGovernor()) {
                    notStandardOrEmergencyGovernorViolationCount++;
            }

            _keys.push(_list);
            _values.push(bytes32(uint256(uint160(_account))));
            _keynum++;

        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            expectedError(_err);
        }
    }


    function removeFromList(
        uint256 _actorIndex,
        bytes32 _list,
        address _account
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, registrar.standardGovernor(), 50) {

        if (actor.addr != registrar.standardGovernor() &&
            actor.addr != registrar.emergencyGovernor()) {
                addExpectedError("NotStandardOrEmergencyGovernor()");
        }

        uint256 klen = _keys.length;
        require(klen == _values.length);
        if (klen > 0) {
            for (uint256 i = 0; i < klen; i++) {
                bytes32 _val = registrar.get(_keys[i]);
                if (_val == _values[i]) {
                    InvariantUtils.removeArrayElement(_keys, i);
                    InvariantUtils.removeArrayElement(_values, i);
                    _keynum--;
                    break;
                }
            }
        }

        startGas();
        try registrar.removeFromList(_list, _account) {
            stopGas();

            if (actor.addr != registrar.standardGovernor() &&
                actor.addr != registrar.emergencyGovernor()) {
                    notStandardOrEmergencyGovernorViolationCount++;
            }

            require(!registrar.listContains(_list, _account));
        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            expectedError(_err);
        }
    }

    function setKey(
        uint256 _actorIndex,
        bytes32 _key,
        bytes32 _value
    ) public resetErrors leap(_actorIndex) useRandomMsgSenderWeighted(_actorIndex, registrar.standardGovernor(), 50) {

        if (actor.addr != registrar.standardGovernor() &&
            actor.addr != registrar.emergencyGovernor()) {
                addExpectedError("NotStandardOrEmergencyGovernor()");
        }

        startGas();
        try registrar.setKey(_key, _value) {
            stopGas();

            if (actor.addr != registrar.standardGovernor() &&
                actor.addr != registrar.emergencyGovernor()) {
                    notStandardOrEmergencyGovernorViolationCount++;
            }

            _keys.push(_key);
            _values.push(_value);
            _keynum++;

        } catch Error(string memory _err) {
            expectedError(_err);
        } catch (bytes memory _err) {
            expectedError(_err);
        }
    }

}
