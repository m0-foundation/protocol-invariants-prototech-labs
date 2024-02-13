pragma solidity ^0.8.23;

import {Test, console, console2} from "forge-std/Test.sol";

import { InvariantUtils, IToken } from "../../lib/InvariantUtils.sol";

import { PureEpochs } from "../../lib/Ttg.sol";

interface ITest {
    function currentTimestamp() external view returns (uint256);
    function setCurrentTimestamp(uint256) external;
    function currentBlock() external view returns (uint256);
    function setCurrentBlock(uint256) external;
    function integration() external view returns (bool);
    function realRegistrar() external view returns (bool);
    function poke(address,address,address) external;
}

abstract contract BaseHandler is Test {
    uint256 public seed;

    ITest internal testContract;

    InvariantUtils.Actor[] public actors;
    InvariantUtils.Actor[] public msgSenders;
    InvariantUtils.Actor internal actor;

    InvariantUtils.Actor internal zero;
    InvariantUtils.Actor internal token;

    uint256 public gasUsed = 1; // Start at 1 to warm slot
    uint256 public gasViolations = 0;
    uint256 public constant MAX_GAS = 15_000_000;

    struct ErrorTypes {
        bytes32 errString;
        bytes32  errBytes;
    }
    ErrorTypes[] internal expectedErrors;

    uint256 public maxLeap = uint256(
        vm.envOr("MAX_LEAP", uint256(12 hours))
    );

    uint256 public constant VARIANCE        = 0;                                 // 0 stop prevent revert bug
    uint256 public constant MAX_UINT240     = type(uint240).max + VARIANCE;      // go a little over
    uint256 public constant MAX_UINT112     = type(uint112).max + VARIANCE;      // go a little over
    uint256 public constant MAX_NONCE       = 3;                                 // per actor
    uint256 public constant BLOCKTIME       = 13;                                // 13 second blocktime
    uint256 public constant BASE_BLOCK      = 15537393;                          // the merge
    uint256 public constant BASE_TIMESTAMP  = 1663224162;                        // ts at merge
    uint256 public constant MAX_TIMESTAMP   = BASE_TIMESTAMP + 150 * 365 days;   // 150 years in the future
    uint256 public constant EPOCH_PERIOD    = 15 days;                           // Epoch period is 15 days

    uint256 constant a = 1664525;
    uint256 constant c = 1013904223;
    uint256 constant m = 2**32;

    // modifiers
    modifier useRandomMsgSender(uint256 _actorIndex) {
        InvariantUtils.Actor memory guy = msgSenders[bound(_actorIndex, 0, msgSenders.length - 1)];

        actor.addr = guy.addr;
        actor.key = guy.key;

        if (seed == 0) {
            setSeed(_actorIndex);
        }

        // if prank already started in test then use change prank to change actor
        try vm.startPrank(actor.addr) {
        } catch {
            changePrank(actor.addr);
        }

        _;

        vm.stopPrank();
    }

    // @param _actorIndex: the index of the random actor to use
    // @param _favored:    the address of the favored actor to use
    // @param _weight:     the weight, in percent, of the actor to use
    modifier useRandomMsgSenderWeighted(uint256 _actorIndex, address _favored, uint256 _weight) {
        if (seed == 0) {
            setSeed(_actorIndex);
        }

        InvariantUtils.Actor memory guy;

        // If the roll is less than the weight, use the favored actor
        if (rand() % 100 < _weight) {
            for (uint i = 0; i < msgSenders.length; i++) {
                console.log("Actor: ", msgSenders[i].addr, "Favored: ", _favored);
                if (msgSenders[i].addr == _favored) {
                    guy = msgSenders[i];
                    break;
                }
            }
        } else {
            guy = msgSenders[bound(_actorIndex, 0, msgSenders.length - 1)];
        }

        actor.addr = guy.addr;
        actor.key = guy.key;

        // if prank already started in test then use change prank to change actor
        try vm.startPrank(actor.addr) {
        } catch {
            changePrank(actor.addr);
        }

        _;

        vm.stopPrank();
    }

    modifier leap(uint256 _rand) {
        if (testContract.currentTimestamp() < BASE_TIMESTAMP) {
            vm.warp(BASE_TIMESTAMP);
            vm.roll(BASE_BLOCK);
            _;
            etchLeap();
        } else {
            {   // Stack too deep
                // the max leap in seconds based on the max timestamp and the depth
                uint256 _leap = bound(_rand, 0, maxLeap);
                if(testContract.currentTimestamp() + _leap < block.timestamp) revert("MOVING BACKWARDS");
                vm.warp(testContract.currentTimestamp() + _leap);
                vm.roll(testContract.currentBlock() + (_leap / BLOCKTIME));
            }
            _;
            etchLeap();
        }
    }

    modifier leapRange(uint256 _rand, uint256 _min, uint256 _max) {
        if (testContract.currentTimestamp() < BASE_TIMESTAMP) {
            vm.warp(BASE_TIMESTAMP);
            vm.roll(BASE_BLOCK);
            _;
            etchLeap();
        } else {
            {   // Stack too deep
                // the max leap in seconds based on the max timestamp and the depth
                uint256 _leap = bound(_rand, _min, _max);
                vm.warp(testContract.currentTimestamp() + _leap);
                vm.roll(testContract.currentBlock() + (_leap / BLOCKTIME));
            }
            _;
            etchLeap();
        }
    }

    modifier resetErrors() {
        _;
        delete expectedErrors;
    }

    constructor (address _testContract) {
        testContract = ITest(_testContract);
    }

    function pael(uint256 _actorIndex) leap(_actorIndex) public {
        // just use this to call the leap modifier
    }

    function paelRange(uint256 _actorIndex, uint256 _min, uint256 _max) leapRange(_actorIndex, _min, _max) public {
        // just use this to call the leapRange modifier
    }

    function etchLeap() public {
        testContract.setCurrentTimestamp(block.timestamp);
        testContract.setCurrentBlock(block.number);
    }

    function leapExact(uint256 _seconds) public leapRange(0, _seconds, _seconds) {
        // Jump to the exact number of seconds
    }

    function setMaxLeap(uint256 _seconds) public {
        maxLeap = _seconds;
    }
    function addActors() public {
        addActors(uint256(vm.envOr("NUM_OF_ACTORS", uint256(10))));
    }

    function addActors(uint256 _numOfActors) public {
        InvariantUtils.Actor memory guy;

        for(uint256 i = 0; i < _numOfActors; i++) {
            guy = addActor(string(abi.encodePacked("Actor", vm.toString(i))));
        }
    }

    function addActor(address _addr, string memory _tag) public returns (InvariantUtils.Actor memory guy) {
        (guy.addr, guy.key) = makeAddrAndKey(_tag);
        guy.addr = _addr;
        if (guy.addr != address(0)) {
            msgSenders.push(guy);
        }
        actors.push(guy);
    }

    function addActor(string memory _tag) public returns (InvariantUtils.Actor memory guy) {
        (guy.addr, guy.key) = makeAddrAndKey(_tag);
        if (guy.addr != address(0)) {
            msgSenders.push(guy);
        }
        actors.push(guy);
    }

    function addActor(InvariantUtils.Actor memory _guy) public {
        if (_guy.addr != address(0)) {
            msgSenders.push(_guy);
        }
        actors.push(_guy);
    }

    function addActor(address _addr) public returns (InvariantUtils.Actor memory guy) {
        guy = addActor(_addr, vm.toString(_addr));
    }

    function getActor(string memory _tag) public returns (InvariantUtils.Actor memory guy) {
        (guy.addr, guy.key) = makeAddrAndKey(_tag);
        uint256 _numActors = actors.length;
        for (uint256 i = 0; i < _numActors; i++) {
            if (actors[i].addr == guy.addr) {
                guy = actors[i];
            }
        }
    }

    // Ensure there are no duplicate actors in the _actors array
    function validateActors() public view {
        validateActors(actors);
    }

    function validateActors(InvariantUtils.Actor[] memory _actors) public pure {
        uint256 actorCount = _actors.length;

        for (uint256 i = 0; i < actorCount; i++) {
            for (uint256 j = 0; j < actorCount; j++) {
                if (i != j) {
                    require(
                        _actors[i].addr != _actors[j].addr,
                        "BaseHandler: Duplicate Actor"
                    );
                }
            }
        }
    }

    function getActorsCount() external view returns(uint256) {
        return actors.length;
    }

    function getMsgSendersCount() external view returns(uint256) {
        return msgSenders.length;
    }

    //
    // Gas measurement functions
    //
    function startGas() internal {
        gasUsed = gasleft();
    }

    function stopGas() internal returns (uint256 _gasUsed) {
        uint256 checkpoint = gasleft();
        // Subtract 100 to account for the warm SLOAD in startGas
        _gasUsed = gasUsed - checkpoint - 100;

        if (_gasUsed > MAX_GAS) {
            gasViolations++;
        }

        console.log("Gas Used: ", _gasUsed);
    }

    // Used for unparameterized errors or when the parameter output of an expected error is not specific.
    //   Example usage:
    //
    //    addExpectedError("InvalidSignature()");
    //    addExpectedError("SignatureExpired(uint256,uint256)");
    //
    function addExpectedError(string memory _err) internal {
        ErrorTypes memory _xerr;
        _xerr.errString = keccak256(abi.encodePacked(_err));
        _xerr.errBytes  = bytes4(keccak256(bytes(_err)));
        expectedErrors.push(_xerr);
    }

    //  Used when needed to match an exact parameter set for a specific error.
    //    Example usage:
    //
    //    addExpectedErrorBytes32(keccak256(abi.encodeWithSignature("Panic(uint256)", 0x11)));
    //
    function addExpectedErrorBytes32(bytes32 _err) internal {
        ErrorTypes memory _xerr;
        _xerr.errString = _err;
        _xerr.errBytes  = _err;
        expectedErrors.push(_xerr);
    }

    function expectedError(string memory _err) internal view {
        bytes32 err = keccak256(abi.encodePacked(_err));
        bool _valid;

        uint256 errLen = expectedErrors.length;
        for (uint256 i = 0; i < errLen; i++) {
            if (err == expectedErrors[i].errString) {
                _valid = true;
            }
        }

        if (!_valid) {
            console.log("Unhandled Error:");
            console.log(_err);
        }
        require(_valid, "Unexpected revert error");
    }

    function expectedError(bytes memory _err) internal view {
        bool _valid;

        bytes4  errBytes4  = bytes4(bytes32(_err));
        bytes32 errBytes32 = keccak256(_err);
        uint256 errLen = expectedErrors.length;

        for (uint256 i = 0; i < errLen; i++) {
            if (errBytes4   == bytes4(expectedErrors[i].errBytes) ||
                errBytes32  == expectedErrors[i].errBytes) {
                    _valid = true;
            }
        }

        if (!_valid) {
            console.log("Unhandled Error:");
            console.logBytes(_err);
        }
        require(_valid, "Unexpected revert error");
    }

    function setSeed(uint256 _seed) internal {
        seed = bound(_seed, 0, (type(uint256).max / a) - c);
    }

    function rand() public returns (uint256) {
        seed = (a * seed + c) % m;
        return seed;
    }

    function random256(uint256 _seed) internal pure returns (uint256 _rand) {
        _seed = bound(_seed, 0, (type(uint256).max / a) - c);
        _rand = (a * _seed + c) % m;
    }

    function _findActorIndex(address _addr) internal view returns (uint256) {
        uint256 len = actors.length;
        for (uint256 i = 0; i < len; i++) {
            if (actors[i].addr == _addr) {
                return i;
            }
        }
        revert("Actor not found");
    }

    function clock() public view returns (uint256) {
        return PureEpochs.currentEpoch();
    }

    function isVotingEpoch() public view returns (bool) {
        return isVotingEpoch(clock());
    }

    function isVotingEpoch(uint256 _epoch) public pure returns (bool) {
        return _epoch % 2 == 1; // Voting epochs are odd numbered.
    }

    function isTransferEpoch() public view returns (bool) {
        return isTransferEpoch(clock());
    }

    function isTransferEpoch(uint256 _epoch) public pure returns (bool) {
        return _epoch % 2 == 0; // Transfer epochs are even numbered.
    }

    function timestamp() public view returns (uint256) {
        return block.timestamp;
    }
}
