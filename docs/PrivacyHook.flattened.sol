// SPDX-License-Identifier: MIT
pragma solidity <0.9.0 >=0.8.19 >=0.8.25 ^0.8.0 ^0.8.20 ^0.8.24 ^0.8.25;

// node_modules/@uniswap/v4-core/src/types/BeforeSwapDelta.sol

// Return type of the beforeSwap hook.
// Upper 128 bits is the delta in specified tokens. Lower 128 bits is delta in unspecified tokens (to match the afterSwap hook)
type BeforeSwapDelta is int256;

// Creates a BeforeSwapDelta from specified and unspecified
function toBeforeSwapDelta(int128 deltaSpecified, int128 deltaUnspecified)
    pure
    returns (BeforeSwapDelta beforeSwapDelta)
{
    assembly ("memory-safe") {
        beforeSwapDelta := or(shl(128, deltaSpecified), and(sub(shl(128, 1), 1), deltaUnspecified))
    }
}

/// @notice Library for getting the specified and unspecified deltas from the BeforeSwapDelta type
library BeforeSwapDeltaLibrary {
    /// @notice A BeforeSwapDelta of 0
    BeforeSwapDelta public constant ZERO_DELTA = BeforeSwapDelta.wrap(0);

    /// extracts int128 from the upper 128 bits of the BeforeSwapDelta
    /// returned by beforeSwap
    function getSpecifiedDelta(BeforeSwapDelta delta) internal pure returns (int128 deltaSpecified) {
        assembly ("memory-safe") {
            deltaSpecified := sar(128, delta)
        }
    }

    /// extracts int128 from the lower 128 bits of the BeforeSwapDelta
    /// returned by beforeSwap and afterSwap
    function getUnspecifiedDelta(BeforeSwapDelta delta) internal pure returns (int128 deltaUnspecified) {
        assembly ("memory-safe") {
            deltaUnspecified := signextend(15, delta)
        }
    }
}

// node_modules/@openzeppelin/contracts/utils/Context.sol

// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}

// node_modules/@uniswap/v4-core/src/libraries/CustomRevert.sol

/// @title Library for reverting with custom errors efficiently
/// @notice Contains functions for reverting with custom errors with different argument types efficiently
/// @dev To use this library, declare `using CustomRevert for bytes4;` and replace `revert CustomError()` with
/// `CustomError.selector.revertWith()`
/// @dev The functions may tamper with the free memory pointer but it is fine since the call context is exited immediately
library CustomRevert {
    /// @dev ERC-7751 error for wrapping bubbled up reverts
    error WrappedError(address target, bytes4 selector, bytes reason, bytes details);

    /// @dev Reverts with the selector of a custom error in the scratch space
    function revertWith(bytes4 selector) internal pure {
        assembly ("memory-safe") {
            mstore(0, selector)
            revert(0, 0x04)
        }
    }

    /// @dev Reverts with a custom error with an address argument in the scratch space
    function revertWith(bytes4 selector, address addr) internal pure {
        assembly ("memory-safe") {
            mstore(0, selector)
            mstore(0x04, and(addr, 0xffffffffffffffffffffffffffffffffffffffff))
            revert(0, 0x24)
        }
    }

    /// @dev Reverts with a custom error with an int24 argument in the scratch space
    function revertWith(bytes4 selector, int24 value) internal pure {
        assembly ("memory-safe") {
            mstore(0, selector)
            mstore(0x04, signextend(2, value))
            revert(0, 0x24)
        }
    }

    /// @dev Reverts with a custom error with a uint160 argument in the scratch space
    function revertWith(bytes4 selector, uint160 value) internal pure {
        assembly ("memory-safe") {
            mstore(0, selector)
            mstore(0x04, and(value, 0xffffffffffffffffffffffffffffffffffffffff))
            revert(0, 0x24)
        }
    }

    /// @dev Reverts with a custom error with two int24 arguments
    function revertWith(bytes4 selector, int24 value1, int24 value2) internal pure {
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            mstore(fmp, selector)
            mstore(add(fmp, 0x04), signextend(2, value1))
            mstore(add(fmp, 0x24), signextend(2, value2))
            revert(fmp, 0x44)
        }
    }

    /// @dev Reverts with a custom error with two uint160 arguments
    function revertWith(bytes4 selector, uint160 value1, uint160 value2) internal pure {
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            mstore(fmp, selector)
            mstore(add(fmp, 0x04), and(value1, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(fmp, 0x24), and(value2, 0xffffffffffffffffffffffffffffffffffffffff))
            revert(fmp, 0x44)
        }
    }

    /// @dev Reverts with a custom error with two address arguments
    function revertWith(bytes4 selector, address value1, address value2) internal pure {
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            mstore(fmp, selector)
            mstore(add(fmp, 0x04), and(value1, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(fmp, 0x24), and(value2, 0xffffffffffffffffffffffffffffffffffffffff))
            revert(fmp, 0x44)
        }
    }

    /// @notice bubble up the revert message returned by a call and revert with a wrapped ERC-7751 error
    /// @dev this method can be vulnerable to revert data bombs
    function bubbleUpAndRevertWith(
        address revertingContract,
        bytes4 revertingFunctionSelector,
        bytes4 additionalContext
    ) internal pure {
        bytes4 wrappedErrorSelector = WrappedError.selector;
        assembly ("memory-safe") {
            // Ensure the size of the revert data is a multiple of 32 bytes
            let encodedDataSize := mul(div(add(returndatasize(), 31), 32), 32)

            let fmp := mload(0x40)

            // Encode wrapped error selector, address, function selector, offset, additional context, size, revert reason
            mstore(fmp, wrappedErrorSelector)
            mstore(add(fmp, 0x04), and(revertingContract, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(
                add(fmp, 0x24),
                and(revertingFunctionSelector, 0xffffffff00000000000000000000000000000000000000000000000000000000)
            )
            // offset revert reason
            mstore(add(fmp, 0x44), 0x80)
            // offset additional context
            mstore(add(fmp, 0x64), add(0xa0, encodedDataSize))
            // size revert reason
            mstore(add(fmp, 0x84), returndatasize())
            // revert reason
            returndatacopy(add(fmp, 0xa4), 0, returndatasize())
            // size additional context
            mstore(add(fmp, add(0xa4, encodedDataSize)), 0x04)
            // additional context
            mstore(
                add(fmp, add(0xc4, encodedDataSize)),
                and(additionalContext, 0xffffffff00000000000000000000000000000000000000000000000000000000)
            )
            revert(fmp, add(0xe4, encodedDataSize))
        }
    }
}

// node_modules/@fhenixprotocol/cofhe-contracts/ICofhe.sol

struct EncryptedInput {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEbool {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint8 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint16 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint32 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint64 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint128 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

struct InEuint256 {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}
struct InEaddress {
    uint256 ctHash;
    uint8 securityZone;
    uint8 utype;
    bytes signature;
}

// Order is set as in fheos/precompiles/types/types.go
enum FunctionId {
    _0,             // 0 - GetNetworkKey
    _1,             // 1 - Verify
    cast,           // 2
    sealoutput,     // 3
    select,         // 4 - select
    _5,             // 5 - req
    decrypt,        // 6
    sub,            // 7
    add,            // 8
    xor,            // 9
    and,            // 10
    or,             // 11
    not,            // 12
    div,            // 13
    rem,            // 14
    mul,            // 15
    shl,            // 16
    shr,            // 17
    gte,            // 18
    lte,            // 19
    lt,             // 20
    gt,             // 21
    min,            // 22
    max,            // 23
    eq,             // 24
    ne,             // 25
    trivialEncrypt, // 26
    random,         // 27
    rol,            // 28
    ror,            // 29
    square,         // 30
    _31             // 31
}

interface ITaskManager {
    function createTask(uint8 returnType, FunctionId funcId, uint256[] memory encryptedInputs, uint256[] memory extraInputs) external returns (uint256);

    function createDecryptTask(uint256 ctHash, address requestor) external;
    function verifyInput(EncryptedInput memory input, address sender) external returns (uint256);

    function allow(uint256 ctHash, address account) external;
    function isAllowed(uint256 ctHash, address account) external returns (bool);
    function allowGlobal(uint256 ctHash) external;
    function allowTransient(uint256 ctHash, address account) external;
    function getDecryptResultSafe(uint256 ctHash) external view returns (uint256, bool);
    function getDecryptResult(uint256 ctHash) external view returns (uint256);
}

library Utils {
    // Values used to communicate types to the runtime.
    // Must match values defined in warp-drive protobufs for everything to
    uint8 internal constant EUINT8_TFHE = 2;
    uint8 internal constant EUINT16_TFHE = 3;
    uint8 internal constant EUINT32_TFHE = 4;
    uint8 internal constant EUINT64_TFHE = 5;
    uint8 internal constant EUINT128_TFHE = 6;
    uint8 internal constant EUINT256_TFHE = 8;
    uint8 internal constant EADDRESS_TFHE = 7;
    uint8 internal constant EBOOL_TFHE = 0;

    function functionIdToString(FunctionId _functionId) internal pure returns (string memory) {
        if (_functionId == FunctionId.cast) return "cast";
        if (_functionId == FunctionId.sealoutput) return "sealOutput";
        if (_functionId == FunctionId.select) return "select";
        if (_functionId == FunctionId.decrypt) return "decrypt";
        if (_functionId == FunctionId.sub) return "sub";
        if (_functionId == FunctionId.add) return "add";
        if (_functionId == FunctionId.xor) return "xor";
        if (_functionId == FunctionId.and) return "and";
        if (_functionId == FunctionId.or) return "or";
        if (_functionId == FunctionId.not) return "not";
        if (_functionId == FunctionId.div) return "div";
        if (_functionId == FunctionId.rem) return "rem";
        if (_functionId == FunctionId.mul) return "mul";
        if (_functionId == FunctionId.shl) return "shl";
        if (_functionId == FunctionId.shr) return "shr";
        if (_functionId == FunctionId.gte) return "gte";
        if (_functionId == FunctionId.lte) return "lte";
        if (_functionId == FunctionId.lt) return "lt";
        if (_functionId == FunctionId.gt) return "gt";
        if (_functionId == FunctionId.min) return "min";
        if (_functionId == FunctionId.max) return "max";
        if (_functionId == FunctionId.eq) return "eq";
        if (_functionId == FunctionId.ne) return "ne";
        if (_functionId == FunctionId.trivialEncrypt) return "trivialEncrypt";
        if (_functionId == FunctionId.random) return "random";
        if (_functionId == FunctionId.rol) return "rol";
        if (_functionId == FunctionId.ror) return "ror";
        if (_functionId == FunctionId.square) return "square";

        return "";
    }

    function inputFromEbool(InEbool memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EBOOL_TFHE,
            signature: input.signature
        });
    }

    function inputFromEuint8(InEuint8 memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EUINT8_TFHE,
            signature: input.signature
        });
    }

    function inputFromEuint16(InEuint16 memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EUINT16_TFHE,
            signature: input.signature
        });
    }

    function inputFromEuint32(InEuint32 memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EUINT32_TFHE,
            signature: input.signature
        });
    }

    function inputFromEuint64(InEuint64 memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EUINT64_TFHE,
            signature: input.signature
        });
    }

    function inputFromEuint128(InEuint128 memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EUINT128_TFHE,
            signature: input.signature
        });
    }

    function inputFromEuint256(InEuint256 memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EUINT256_TFHE,
            signature: input.signature
        });
    }

    function inputFromEaddress(InEaddress memory input) internal pure returns (EncryptedInput memory) {
        return EncryptedInput({
            ctHash: input.ctHash,
            securityZone: input.securityZone,
            utype: EADDRESS_TFHE,
            signature: input.signature
        });
    }
}

// node_modules/@openzeppelin/contracts/token/ERC20/IERC20.sol

// OpenZeppelin Contracts (last updated v5.1.0) (token/ERC20/IERC20.sol)

/**
 * @dev Interface of the ERC-20 standard as defined in the ERC.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

// node_modules/@uniswap/v4-core/src/interfaces/external/IERC20Minimal.sol

/// @title Minimal ERC20 interface for Uniswap
/// @notice Contains a subset of the full ERC20 interface that is used in Uniswap V3
interface IERC20Minimal {
    /// @notice Returns an account's balance in the token
    /// @param account The account for which to look up the number of tokens it has, i.e. its balance
    /// @return The number of tokens held by the account
    function balanceOf(address account) external view returns (uint256);

    /// @notice Transfers the amount of token from the `msg.sender` to the recipient
    /// @param recipient The account that will receive the amount transferred
    /// @param amount The number of tokens to send from the sender to the recipient
    /// @return Returns true for a successful transfer, false for an unsuccessful transfer
    function transfer(address recipient, uint256 amount) external returns (bool);

    /// @notice Returns the current allowance given to a spender by an owner
    /// @param owner The account of the token owner
    /// @param spender The account of the token spender
    /// @return The current allowance granted by `owner` to `spender`
    function allowance(address owner, address spender) external view returns (uint256);

    /// @notice Sets the allowance of a spender from the `msg.sender` to the value `amount`
    /// @param spender The account which will be allowed to spend a given amount of the owners tokens
    /// @param amount The amount of tokens allowed to be used by `spender`
    /// @return Returns true for a successful approval, false for unsuccessful
    function approve(address spender, uint256 amount) external returns (bool);

    /// @notice Transfers `amount` tokens from `sender` to `recipient` up to the allowance given to the `msg.sender`
    /// @param sender The account from which the transfer will be initiated
    /// @param recipient The recipient of the transfer
    /// @param amount The amount of the transfer
    /// @return Returns true for a successful transfer, false for unsuccessful
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /// @notice Event emitted when tokens are transferred from one address to another, either via `#transfer` or `#transferFrom`.
    /// @param from The account from which the tokens were sent, i.e. the balance decreased
    /// @param to The account to which the tokens were sent, i.e. the balance increased
    /// @param value The amount of tokens that were transferred
    event Transfer(address indexed from, address indexed to, uint256 value);

    /// @notice Event emitted when the approval amount for the spender of a given owner's tokens changes.
    /// @param owner The account that approved spending of its tokens
    /// @param spender The account for which the spending allowance was modified
    /// @param value The new allowance from the owner to the spender
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

// node_modules/@uniswap/v4-core/src/interfaces/external/IERC6909Claims.sol

/// @notice Interface for claims over a contract balance, wrapped as a ERC6909
interface IERC6909Claims {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event OperatorSet(address indexed owner, address indexed operator, bool approved);

    event Approval(address indexed owner, address indexed spender, uint256 indexed id, uint256 amount);

    event Transfer(address caller, address indexed from, address indexed to, uint256 indexed id, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                 FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Owner balance of an id.
    /// @param owner The address of the owner.
    /// @param id The id of the token.
    /// @return amount The balance of the token.
    function balanceOf(address owner, uint256 id) external view returns (uint256 amount);

    /// @notice Spender allowance of an id.
    /// @param owner The address of the owner.
    /// @param spender The address of the spender.
    /// @param id The id of the token.
    /// @return amount The allowance of the token.
    function allowance(address owner, address spender, uint256 id) external view returns (uint256 amount);

    /// @notice Checks if a spender is approved by an owner as an operator
    /// @param owner The address of the owner.
    /// @param spender The address of the spender.
    /// @return approved The approval status.
    function isOperator(address owner, address spender) external view returns (bool approved);

    /// @notice Transfers an amount of an id from the caller to a receiver.
    /// @param receiver The address of the receiver.
    /// @param id The id of the token.
    /// @param amount The amount of the token.
    /// @return bool True, always, unless the function reverts
    function transfer(address receiver, uint256 id, uint256 amount) external returns (bool);

    /// @notice Transfers an amount of an id from a sender to a receiver.
    /// @param sender The address of the sender.
    /// @param receiver The address of the receiver.
    /// @param id The id of the token.
    /// @param amount The amount of the token.
    /// @return bool True, always, unless the function reverts
    function transferFrom(address sender, address receiver, uint256 id, uint256 amount) external returns (bool);

    /// @notice Approves an amount of an id to a spender.
    /// @param spender The address of the spender.
    /// @param id The id of the token.
    /// @param amount The amount of the token.
    /// @return bool True, always
    function approve(address spender, uint256 id, uint256 amount) external returns (bool);

    /// @notice Sets or removes an operator for the caller.
    /// @param operator The address of the operator.
    /// @param approved The approval status.
    /// @return bool True, always
    function setOperator(address operator, bool approved) external returns (bool);
}

// node_modules/@uniswap/v4-core/src/interfaces/IExtsload.sol

/// @notice Interface for functions to access any storage slot in a contract
interface IExtsload {
    /// @notice Called by external contracts to access granular pool state
    /// @param slot Key of slot to sload
    /// @return value The value of the slot as bytes32
    function extsload(bytes32 slot) external view returns (bytes32 value);

    /// @notice Called by external contracts to access granular pool state
    /// @param startSlot Key of slot to start sloading from
    /// @param nSlots Number of slots to load into return value
    /// @return values List of loaded values.
    function extsload(bytes32 startSlot, uint256 nSlots) external view returns (bytes32[] memory values);

    /// @notice Called by external contracts to access sparse pool state
    /// @param slots List of slots to SLOAD from.
    /// @return values List of loaded values.
    function extsload(bytes32[] calldata slots) external view returns (bytes32[] memory values);
}

// node_modules/@uniswap/v4-core/src/interfaces/IExttload.sol

/// @notice Interface for functions to access any transient storage slot in a contract
interface IExttload {
    /// @notice Called by external contracts to access transient storage of the contract
    /// @param slot Key of slot to tload
    /// @return value The value of the slot as bytes32
    function exttload(bytes32 slot) external view returns (bytes32 value);

    /// @notice Called by external contracts to access sparse transient pool state
    /// @param slots List of slots to tload
    /// @return values List of loaded values
    function exttload(bytes32[] calldata slots) external view returns (bytes32[] memory values);
}

// node_modules/@openzeppelin/contracts/utils/Panic.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/Panic.sol)

/**
 * @dev Helper library for emitting standardized panic codes.
 *
 * ```solidity
 * contract Example {
 *      using Panic for uint256;
 *
 *      // Use any of the declared internal constants
 *      function foo() { Panic.GENERIC.panic(); }
 *
 *      // Alternatively
 *      function foo() { Panic.panic(Panic.GENERIC); }
 * }
 * ```
 *
 * Follows the list from https://github.com/ethereum/solidity/blob/v0.8.24/libsolutil/ErrorCodes.h[libsolutil].
 *
 * _Available since v5.1._
 */
// slither-disable-next-line unused-state
library Panic {
    /// @dev generic / unspecified error
    uint256 internal constant GENERIC = 0x00;
    /// @dev used by the assert() builtin
    uint256 internal constant ASSERT = 0x01;
    /// @dev arithmetic underflow or overflow
    uint256 internal constant UNDER_OVERFLOW = 0x11;
    /// @dev division or modulo by zero
    uint256 internal constant DIVISION_BY_ZERO = 0x12;
    /// @dev enum conversion error
    uint256 internal constant ENUM_CONVERSION_ERROR = 0x21;
    /// @dev invalid encoding in storage
    uint256 internal constant STORAGE_ENCODING_ERROR = 0x22;
    /// @dev empty array pop
    uint256 internal constant EMPTY_ARRAY_POP = 0x31;
    /// @dev array out of bounds access
    uint256 internal constant ARRAY_OUT_OF_BOUNDS = 0x32;
    /// @dev resource error (too large allocation or too large array)
    uint256 internal constant RESOURCE_ERROR = 0x41;
    /// @dev calling invalid internal function
    uint256 internal constant INVALID_INTERNAL_FUNCTION = 0x51;

    /// @dev Reverts with a panic code. Recommended to use with
    /// the internal constants with predefined codes.
    function panic(uint256 code) internal pure {
        assembly ("memory-safe") {
            mstore(0x00, 0x4e487b71)
            mstore(0x20, code)
            revert(0x1c, 0x24)
        }
    }
}

// node_modules/@uniswap/v4-core/src/libraries/ParseBytes.sol

/// @notice Parses bytes returned from hooks and the byte selector used to check return selectors from hooks.
/// @dev parseSelector also is used to parse the expected selector
/// For parsing hook returns, note that all hooks return either bytes4 or (bytes4, 32-byte-delta) or (bytes4, 32-byte-delta, uint24).
library ParseBytes {
    function parseSelector(bytes memory result) internal pure returns (bytes4 selector) {
        // equivalent: (selector,) = abi.decode(result, (bytes4, int256));
        assembly ("memory-safe") {
            selector := mload(add(result, 0x20))
        }
    }

    function parseFee(bytes memory result) internal pure returns (uint24 lpFee) {
        // equivalent: (,, lpFee) = abi.decode(result, (bytes4, int256, uint24));
        assembly ("memory-safe") {
            lpFee := mload(add(result, 0x60))
        }
    }

    function parseReturnDelta(bytes memory result) internal pure returns (int256 hookReturn) {
        // equivalent: (, hookReturnDelta) = abi.decode(result, (bytes4, int256));
        assembly ("memory-safe") {
            hookReturn := mload(add(result, 0x40))
        }
    }
}

// node_modules/@openzeppelin/contracts/utils/math/SafeCast.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/math/SafeCast.sol)
// This file was procedurally generated from scripts/generate/templates/SafeCast.js.

/**
 * @dev Wrappers over Solidity's uintXX/intXX/bool casting operators with added overflow
 * checks.
 *
 * Downcasting from uint256/int256 in Solidity does not revert on overflow. This can
 * easily result in undesired exploitation or bugs, since developers usually
 * assume that overflows raise errors. `SafeCast` restores this intuition by
 * reverting the transaction when such an operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeCast_0 {
    /**
     * @dev Value doesn't fit in an uint of `bits` size.
     */
    error SafeCastOverflowedUintDowncast(uint8 bits, uint256 value);

    /**
     * @dev An int value doesn't fit in an uint of `bits` size.
     */
    error SafeCastOverflowedIntToUint(int256 value);

    /**
     * @dev Value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedIntDowncast(uint8 bits, int256 value);

    /**
     * @dev An uint value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedUintToInt(uint256 value);

    /**
     * @dev Returns the downcasted uint248 from uint256, reverting on
     * overflow (when the input is greater than largest uint248).
     *
     * Counterpart to Solidity's `uint248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toUint248(uint256 value) internal pure returns (uint248) {
        if (value > type(uint248).max) {
            revert SafeCastOverflowedUintDowncast(248, value);
        }
        return uint248(value);
    }

    /**
     * @dev Returns the downcasted uint240 from uint256, reverting on
     * overflow (when the input is greater than largest uint240).
     *
     * Counterpart to Solidity's `uint240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toUint240(uint256 value) internal pure returns (uint240) {
        if (value > type(uint240).max) {
            revert SafeCastOverflowedUintDowncast(240, value);
        }
        return uint240(value);
    }

    /**
     * @dev Returns the downcasted uint232 from uint256, reverting on
     * overflow (when the input is greater than largest uint232).
     *
     * Counterpart to Solidity's `uint232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toUint232(uint256 value) internal pure returns (uint232) {
        if (value > type(uint232).max) {
            revert SafeCastOverflowedUintDowncast(232, value);
        }
        return uint232(value);
    }

    /**
     * @dev Returns the downcasted uint224 from uint256, reverting on
     * overflow (when the input is greater than largest uint224).
     *
     * Counterpart to Solidity's `uint224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toUint224(uint256 value) internal pure returns (uint224) {
        if (value > type(uint224).max) {
            revert SafeCastOverflowedUintDowncast(224, value);
        }
        return uint224(value);
    }

    /**
     * @dev Returns the downcasted uint216 from uint256, reverting on
     * overflow (when the input is greater than largest uint216).
     *
     * Counterpart to Solidity's `uint216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toUint216(uint256 value) internal pure returns (uint216) {
        if (value > type(uint216).max) {
            revert SafeCastOverflowedUintDowncast(216, value);
        }
        return uint216(value);
    }

    /**
     * @dev Returns the downcasted uint208 from uint256, reverting on
     * overflow (when the input is greater than largest uint208).
     *
     * Counterpart to Solidity's `uint208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toUint208(uint256 value) internal pure returns (uint208) {
        if (value > type(uint208).max) {
            revert SafeCastOverflowedUintDowncast(208, value);
        }
        return uint208(value);
    }

    /**
     * @dev Returns the downcasted uint200 from uint256, reverting on
     * overflow (when the input is greater than largest uint200).
     *
     * Counterpart to Solidity's `uint200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toUint200(uint256 value) internal pure returns (uint200) {
        if (value > type(uint200).max) {
            revert SafeCastOverflowedUintDowncast(200, value);
        }
        return uint200(value);
    }

    /**
     * @dev Returns the downcasted uint192 from uint256, reverting on
     * overflow (when the input is greater than largest uint192).
     *
     * Counterpart to Solidity's `uint192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toUint192(uint256 value) internal pure returns (uint192) {
        if (value > type(uint192).max) {
            revert SafeCastOverflowedUintDowncast(192, value);
        }
        return uint192(value);
    }

    /**
     * @dev Returns the downcasted uint184 from uint256, reverting on
     * overflow (when the input is greater than largest uint184).
     *
     * Counterpart to Solidity's `uint184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toUint184(uint256 value) internal pure returns (uint184) {
        if (value > type(uint184).max) {
            revert SafeCastOverflowedUintDowncast(184, value);
        }
        return uint184(value);
    }

    /**
     * @dev Returns the downcasted uint176 from uint256, reverting on
     * overflow (when the input is greater than largest uint176).
     *
     * Counterpart to Solidity's `uint176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toUint176(uint256 value) internal pure returns (uint176) {
        if (value > type(uint176).max) {
            revert SafeCastOverflowedUintDowncast(176, value);
        }
        return uint176(value);
    }

    /**
     * @dev Returns the downcasted uint168 from uint256, reverting on
     * overflow (when the input is greater than largest uint168).
     *
     * Counterpart to Solidity's `uint168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toUint168(uint256 value) internal pure returns (uint168) {
        if (value > type(uint168).max) {
            revert SafeCastOverflowedUintDowncast(168, value);
        }
        return uint168(value);
    }

    /**
     * @dev Returns the downcasted uint160 from uint256, reverting on
     * overflow (when the input is greater than largest uint160).
     *
     * Counterpart to Solidity's `uint160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toUint160(uint256 value) internal pure returns (uint160) {
        if (value > type(uint160).max) {
            revert SafeCastOverflowedUintDowncast(160, value);
        }
        return uint160(value);
    }

    /**
     * @dev Returns the downcasted uint152 from uint256, reverting on
     * overflow (when the input is greater than largest uint152).
     *
     * Counterpart to Solidity's `uint152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toUint152(uint256 value) internal pure returns (uint152) {
        if (value > type(uint152).max) {
            revert SafeCastOverflowedUintDowncast(152, value);
        }
        return uint152(value);
    }

    /**
     * @dev Returns the downcasted uint144 from uint256, reverting on
     * overflow (when the input is greater than largest uint144).
     *
     * Counterpart to Solidity's `uint144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toUint144(uint256 value) internal pure returns (uint144) {
        if (value > type(uint144).max) {
            revert SafeCastOverflowedUintDowncast(144, value);
        }
        return uint144(value);
    }

    /**
     * @dev Returns the downcasted uint136 from uint256, reverting on
     * overflow (when the input is greater than largest uint136).
     *
     * Counterpart to Solidity's `uint136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toUint136(uint256 value) internal pure returns (uint136) {
        if (value > type(uint136).max) {
            revert SafeCastOverflowedUintDowncast(136, value);
        }
        return uint136(value);
    }

    /**
     * @dev Returns the downcasted uint128 from uint256, reverting on
     * overflow (when the input is greater than largest uint128).
     *
     * Counterpart to Solidity's `uint128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toUint128(uint256 value) internal pure returns (uint128) {
        if (value > type(uint128).max) {
            revert SafeCastOverflowedUintDowncast(128, value);
        }
        return uint128(value);
    }

    /**
     * @dev Returns the downcasted uint120 from uint256, reverting on
     * overflow (when the input is greater than largest uint120).
     *
     * Counterpart to Solidity's `uint120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toUint120(uint256 value) internal pure returns (uint120) {
        if (value > type(uint120).max) {
            revert SafeCastOverflowedUintDowncast(120, value);
        }
        return uint120(value);
    }

    /**
     * @dev Returns the downcasted uint112 from uint256, reverting on
     * overflow (when the input is greater than largest uint112).
     *
     * Counterpart to Solidity's `uint112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toUint112(uint256 value) internal pure returns (uint112) {
        if (value > type(uint112).max) {
            revert SafeCastOverflowedUintDowncast(112, value);
        }
        return uint112(value);
    }

    /**
     * @dev Returns the downcasted uint104 from uint256, reverting on
     * overflow (when the input is greater than largest uint104).
     *
     * Counterpart to Solidity's `uint104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toUint104(uint256 value) internal pure returns (uint104) {
        if (value > type(uint104).max) {
            revert SafeCastOverflowedUintDowncast(104, value);
        }
        return uint104(value);
    }

    /**
     * @dev Returns the downcasted uint96 from uint256, reverting on
     * overflow (when the input is greater than largest uint96).
     *
     * Counterpart to Solidity's `uint96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toUint96(uint256 value) internal pure returns (uint96) {
        if (value > type(uint96).max) {
            revert SafeCastOverflowedUintDowncast(96, value);
        }
        return uint96(value);
    }

    /**
     * @dev Returns the downcasted uint88 from uint256, reverting on
     * overflow (when the input is greater than largest uint88).
     *
     * Counterpart to Solidity's `uint88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toUint88(uint256 value) internal pure returns (uint88) {
        if (value > type(uint88).max) {
            revert SafeCastOverflowedUintDowncast(88, value);
        }
        return uint88(value);
    }

    /**
     * @dev Returns the downcasted uint80 from uint256, reverting on
     * overflow (when the input is greater than largest uint80).
     *
     * Counterpart to Solidity's `uint80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toUint80(uint256 value) internal pure returns (uint80) {
        if (value > type(uint80).max) {
            revert SafeCastOverflowedUintDowncast(80, value);
        }
        return uint80(value);
    }

    /**
     * @dev Returns the downcasted uint72 from uint256, reverting on
     * overflow (when the input is greater than largest uint72).
     *
     * Counterpart to Solidity's `uint72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toUint72(uint256 value) internal pure returns (uint72) {
        if (value > type(uint72).max) {
            revert SafeCastOverflowedUintDowncast(72, value);
        }
        return uint72(value);
    }

    /**
     * @dev Returns the downcasted uint64 from uint256, reverting on
     * overflow (when the input is greater than largest uint64).
     *
     * Counterpart to Solidity's `uint64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toUint64(uint256 value) internal pure returns (uint64) {
        if (value > type(uint64).max) {
            revert SafeCastOverflowedUintDowncast(64, value);
        }
        return uint64(value);
    }

    /**
     * @dev Returns the downcasted uint56 from uint256, reverting on
     * overflow (when the input is greater than largest uint56).
     *
     * Counterpart to Solidity's `uint56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toUint56(uint256 value) internal pure returns (uint56) {
        if (value > type(uint56).max) {
            revert SafeCastOverflowedUintDowncast(56, value);
        }
        return uint56(value);
    }

    /**
     * @dev Returns the downcasted uint48 from uint256, reverting on
     * overflow (when the input is greater than largest uint48).
     *
     * Counterpart to Solidity's `uint48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toUint48(uint256 value) internal pure returns (uint48) {
        if (value > type(uint48).max) {
            revert SafeCastOverflowedUintDowncast(48, value);
        }
        return uint48(value);
    }

    /**
     * @dev Returns the downcasted uint40 from uint256, reverting on
     * overflow (when the input is greater than largest uint40).
     *
     * Counterpart to Solidity's `uint40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toUint40(uint256 value) internal pure returns (uint40) {
        if (value > type(uint40).max) {
            revert SafeCastOverflowedUintDowncast(40, value);
        }
        return uint40(value);
    }

    /**
     * @dev Returns the downcasted uint32 from uint256, reverting on
     * overflow (when the input is greater than largest uint32).
     *
     * Counterpart to Solidity's `uint32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toUint32(uint256 value) internal pure returns (uint32) {
        if (value > type(uint32).max) {
            revert SafeCastOverflowedUintDowncast(32, value);
        }
        return uint32(value);
    }

    /**
     * @dev Returns the downcasted uint24 from uint256, reverting on
     * overflow (when the input is greater than largest uint24).
     *
     * Counterpart to Solidity's `uint24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toUint24(uint256 value) internal pure returns (uint24) {
        if (value > type(uint24).max) {
            revert SafeCastOverflowedUintDowncast(24, value);
        }
        return uint24(value);
    }

    /**
     * @dev Returns the downcasted uint16 from uint256, reverting on
     * overflow (when the input is greater than largest uint16).
     *
     * Counterpart to Solidity's `uint16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toUint16(uint256 value) internal pure returns (uint16) {
        if (value > type(uint16).max) {
            revert SafeCastOverflowedUintDowncast(16, value);
        }
        return uint16(value);
    }

    /**
     * @dev Returns the downcasted uint8 from uint256, reverting on
     * overflow (when the input is greater than largest uint8).
     *
     * Counterpart to Solidity's `uint8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toUint8(uint256 value) internal pure returns (uint8) {
        if (value > type(uint8).max) {
            revert SafeCastOverflowedUintDowncast(8, value);
        }
        return uint8(value);
    }

    /**
     * @dev Converts a signed int256 into an unsigned uint256.
     *
     * Requirements:
     *
     * - input must be greater than or equal to 0.
     */
    function toUint256(int256 value) internal pure returns (uint256) {
        if (value < 0) {
            revert SafeCastOverflowedIntToUint(value);
        }
        return uint256(value);
    }

    /**
     * @dev Returns the downcasted int248 from int256, reverting on
     * overflow (when the input is less than smallest int248 or
     * greater than largest int248).
     *
     * Counterpart to Solidity's `int248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toInt248(int256 value) internal pure returns (int248 downcasted) {
        downcasted = int248(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(248, value);
        }
    }

    /**
     * @dev Returns the downcasted int240 from int256, reverting on
     * overflow (when the input is less than smallest int240 or
     * greater than largest int240).
     *
     * Counterpart to Solidity's `int240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toInt240(int256 value) internal pure returns (int240 downcasted) {
        downcasted = int240(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(240, value);
        }
    }

    /**
     * @dev Returns the downcasted int232 from int256, reverting on
     * overflow (when the input is less than smallest int232 or
     * greater than largest int232).
     *
     * Counterpart to Solidity's `int232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toInt232(int256 value) internal pure returns (int232 downcasted) {
        downcasted = int232(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(232, value);
        }
    }

    /**
     * @dev Returns the downcasted int224 from int256, reverting on
     * overflow (when the input is less than smallest int224 or
     * greater than largest int224).
     *
     * Counterpart to Solidity's `int224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toInt224(int256 value) internal pure returns (int224 downcasted) {
        downcasted = int224(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(224, value);
        }
    }

    /**
     * @dev Returns the downcasted int216 from int256, reverting on
     * overflow (when the input is less than smallest int216 or
     * greater than largest int216).
     *
     * Counterpart to Solidity's `int216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toInt216(int256 value) internal pure returns (int216 downcasted) {
        downcasted = int216(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(216, value);
        }
    }

    /**
     * @dev Returns the downcasted int208 from int256, reverting on
     * overflow (when the input is less than smallest int208 or
     * greater than largest int208).
     *
     * Counterpart to Solidity's `int208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toInt208(int256 value) internal pure returns (int208 downcasted) {
        downcasted = int208(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(208, value);
        }
    }

    /**
     * @dev Returns the downcasted int200 from int256, reverting on
     * overflow (when the input is less than smallest int200 or
     * greater than largest int200).
     *
     * Counterpart to Solidity's `int200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toInt200(int256 value) internal pure returns (int200 downcasted) {
        downcasted = int200(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(200, value);
        }
    }

    /**
     * @dev Returns the downcasted int192 from int256, reverting on
     * overflow (when the input is less than smallest int192 or
     * greater than largest int192).
     *
     * Counterpart to Solidity's `int192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toInt192(int256 value) internal pure returns (int192 downcasted) {
        downcasted = int192(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(192, value);
        }
    }

    /**
     * @dev Returns the downcasted int184 from int256, reverting on
     * overflow (when the input is less than smallest int184 or
     * greater than largest int184).
     *
     * Counterpart to Solidity's `int184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toInt184(int256 value) internal pure returns (int184 downcasted) {
        downcasted = int184(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(184, value);
        }
    }

    /**
     * @dev Returns the downcasted int176 from int256, reverting on
     * overflow (when the input is less than smallest int176 or
     * greater than largest int176).
     *
     * Counterpart to Solidity's `int176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toInt176(int256 value) internal pure returns (int176 downcasted) {
        downcasted = int176(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(176, value);
        }
    }

    /**
     * @dev Returns the downcasted int168 from int256, reverting on
     * overflow (when the input is less than smallest int168 or
     * greater than largest int168).
     *
     * Counterpart to Solidity's `int168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toInt168(int256 value) internal pure returns (int168 downcasted) {
        downcasted = int168(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(168, value);
        }
    }

    /**
     * @dev Returns the downcasted int160 from int256, reverting on
     * overflow (when the input is less than smallest int160 or
     * greater than largest int160).
     *
     * Counterpart to Solidity's `int160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toInt160(int256 value) internal pure returns (int160 downcasted) {
        downcasted = int160(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(160, value);
        }
    }

    /**
     * @dev Returns the downcasted int152 from int256, reverting on
     * overflow (when the input is less than smallest int152 or
     * greater than largest int152).
     *
     * Counterpart to Solidity's `int152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toInt152(int256 value) internal pure returns (int152 downcasted) {
        downcasted = int152(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(152, value);
        }
    }

    /**
     * @dev Returns the downcasted int144 from int256, reverting on
     * overflow (when the input is less than smallest int144 or
     * greater than largest int144).
     *
     * Counterpart to Solidity's `int144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toInt144(int256 value) internal pure returns (int144 downcasted) {
        downcasted = int144(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(144, value);
        }
    }

    /**
     * @dev Returns the downcasted int136 from int256, reverting on
     * overflow (when the input is less than smallest int136 or
     * greater than largest int136).
     *
     * Counterpart to Solidity's `int136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toInt136(int256 value) internal pure returns (int136 downcasted) {
        downcasted = int136(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(136, value);
        }
    }

    /**
     * @dev Returns the downcasted int128 from int256, reverting on
     * overflow (when the input is less than smallest int128 or
     * greater than largest int128).
     *
     * Counterpart to Solidity's `int128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toInt128(int256 value) internal pure returns (int128 downcasted) {
        downcasted = int128(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(128, value);
        }
    }

    /**
     * @dev Returns the downcasted int120 from int256, reverting on
     * overflow (when the input is less than smallest int120 or
     * greater than largest int120).
     *
     * Counterpart to Solidity's `int120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toInt120(int256 value) internal pure returns (int120 downcasted) {
        downcasted = int120(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(120, value);
        }
    }

    /**
     * @dev Returns the downcasted int112 from int256, reverting on
     * overflow (when the input is less than smallest int112 or
     * greater than largest int112).
     *
     * Counterpart to Solidity's `int112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toInt112(int256 value) internal pure returns (int112 downcasted) {
        downcasted = int112(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(112, value);
        }
    }

    /**
     * @dev Returns the downcasted int104 from int256, reverting on
     * overflow (when the input is less than smallest int104 or
     * greater than largest int104).
     *
     * Counterpart to Solidity's `int104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toInt104(int256 value) internal pure returns (int104 downcasted) {
        downcasted = int104(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(104, value);
        }
    }

    /**
     * @dev Returns the downcasted int96 from int256, reverting on
     * overflow (when the input is less than smallest int96 or
     * greater than largest int96).
     *
     * Counterpart to Solidity's `int96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toInt96(int256 value) internal pure returns (int96 downcasted) {
        downcasted = int96(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(96, value);
        }
    }

    /**
     * @dev Returns the downcasted int88 from int256, reverting on
     * overflow (when the input is less than smallest int88 or
     * greater than largest int88).
     *
     * Counterpart to Solidity's `int88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toInt88(int256 value) internal pure returns (int88 downcasted) {
        downcasted = int88(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(88, value);
        }
    }

    /**
     * @dev Returns the downcasted int80 from int256, reverting on
     * overflow (when the input is less than smallest int80 or
     * greater than largest int80).
     *
     * Counterpart to Solidity's `int80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toInt80(int256 value) internal pure returns (int80 downcasted) {
        downcasted = int80(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(80, value);
        }
    }

    /**
     * @dev Returns the downcasted int72 from int256, reverting on
     * overflow (when the input is less than smallest int72 or
     * greater than largest int72).
     *
     * Counterpart to Solidity's `int72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toInt72(int256 value) internal pure returns (int72 downcasted) {
        downcasted = int72(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(72, value);
        }
    }

    /**
     * @dev Returns the downcasted int64 from int256, reverting on
     * overflow (when the input is less than smallest int64 or
     * greater than largest int64).
     *
     * Counterpart to Solidity's `int64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toInt64(int256 value) internal pure returns (int64 downcasted) {
        downcasted = int64(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(64, value);
        }
    }

    /**
     * @dev Returns the downcasted int56 from int256, reverting on
     * overflow (when the input is less than smallest int56 or
     * greater than largest int56).
     *
     * Counterpart to Solidity's `int56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toInt56(int256 value) internal pure returns (int56 downcasted) {
        downcasted = int56(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(56, value);
        }
    }

    /**
     * @dev Returns the downcasted int48 from int256, reverting on
     * overflow (when the input is less than smallest int48 or
     * greater than largest int48).
     *
     * Counterpart to Solidity's `int48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toInt48(int256 value) internal pure returns (int48 downcasted) {
        downcasted = int48(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(48, value);
        }
    }

    /**
     * @dev Returns the downcasted int40 from int256, reverting on
     * overflow (when the input is less than smallest int40 or
     * greater than largest int40).
     *
     * Counterpart to Solidity's `int40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toInt40(int256 value) internal pure returns (int40 downcasted) {
        downcasted = int40(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(40, value);
        }
    }

    /**
     * @dev Returns the downcasted int32 from int256, reverting on
     * overflow (when the input is less than smallest int32 or
     * greater than largest int32).
     *
     * Counterpart to Solidity's `int32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toInt32(int256 value) internal pure returns (int32 downcasted) {
        downcasted = int32(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(32, value);
        }
    }

    /**
     * @dev Returns the downcasted int24 from int256, reverting on
     * overflow (when the input is less than smallest int24 or
     * greater than largest int24).
     *
     * Counterpart to Solidity's `int24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toInt24(int256 value) internal pure returns (int24 downcasted) {
        downcasted = int24(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(24, value);
        }
    }

    /**
     * @dev Returns the downcasted int16 from int256, reverting on
     * overflow (when the input is less than smallest int16 or
     * greater than largest int16).
     *
     * Counterpart to Solidity's `int16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toInt16(int256 value) internal pure returns (int16 downcasted) {
        downcasted = int16(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(16, value);
        }
    }

    /**
     * @dev Returns the downcasted int8 from int256, reverting on
     * overflow (when the input is less than smallest int8 or
     * greater than largest int8).
     *
     * Counterpart to Solidity's `int8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toInt8(int256 value) internal pure returns (int8 downcasted) {
        downcasted = int8(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(8, value);
        }
    }

    /**
     * @dev Converts an unsigned uint256 into a signed int256.
     *
     * Requirements:
     *
     * - input must be less than or equal to maxInt256.
     */
    function toInt256(uint256 value) internal pure returns (int256) {
        // Note: Unsafe cast below is okay because `type(int256).max` is guaranteed to be positive
        if (value > uint256(type(int256).max)) {
            revert SafeCastOverflowedUintToInt(value);
        }
        return int256(value);
    }

    /**
     * @dev Cast a boolean (false or true) to a uint256 (0 or 1) with no jump.
     */
    function toUint(bool b) internal pure returns (uint256 u) {
        assembly ("memory-safe") {
            u := iszero(iszero(b))
        }
    }
}

// node_modules/@openzeppelin/contracts/interfaces/draft-IERC6093.sol

// OpenZeppelin Contracts (last updated v5.1.0) (interfaces/draft-IERC6093.sol)

/**
 * @dev Standard ERC-20 Errors
 * Interface of the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] custom errors for ERC-20 tokens.
 */
interface IERC20Errors {
    /**
     * @dev Indicates an error related to the current `balance` of a `sender`. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     * @param balance Current balance for the interacting account.
     * @param needed Minimum amount required to perform a transfer.
     */
    error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);

    /**
     * @dev Indicates a failure with the token `sender`. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     */
    error ERC20InvalidSender(address sender);

    /**
     * @dev Indicates a failure with the token `receiver`. Used in transfers.
     * @param receiver Address to which tokens are being transferred.
     */
    error ERC20InvalidReceiver(address receiver);

    /**
     * @dev Indicates a failure with the `spender`’s `allowance`. Used in transfers.
     * @param spender Address that may be allowed to operate on tokens without being their owner.
     * @param allowance Amount of tokens a `spender` is allowed to operate with.
     * @param needed Minimum amount required to perform a transfer.
     */
    error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed);

    /**
     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.
     * @param approver Address initiating an approval operation.
     */
    error ERC20InvalidApprover(address approver);

    /**
     * @dev Indicates a failure with the `spender` to be approved. Used in approvals.
     * @param spender Address that may be allowed to operate on tokens without being their owner.
     */
    error ERC20InvalidSpender(address spender);
}

/**
 * @dev Standard ERC-721 Errors
 * Interface of the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] custom errors for ERC-721 tokens.
 */
interface IERC721Errors {
    /**
     * @dev Indicates that an address can't be an owner. For example, `address(0)` is a forbidden owner in ERC-20.
     * Used in balance queries.
     * @param owner Address of the current owner of a token.
     */
    error ERC721InvalidOwner(address owner);

    /**
     * @dev Indicates a `tokenId` whose `owner` is the zero address.
     * @param tokenId Identifier number of a token.
     */
    error ERC721NonexistentToken(uint256 tokenId);

    /**
     * @dev Indicates an error related to the ownership over a particular token. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     * @param tokenId Identifier number of a token.
     * @param owner Address of the current owner of a token.
     */
    error ERC721IncorrectOwner(address sender, uint256 tokenId, address owner);

    /**
     * @dev Indicates a failure with the token `sender`. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     */
    error ERC721InvalidSender(address sender);

    /**
     * @dev Indicates a failure with the token `receiver`. Used in transfers.
     * @param receiver Address to which tokens are being transferred.
     */
    error ERC721InvalidReceiver(address receiver);

    /**
     * @dev Indicates a failure with the `operator`’s approval. Used in transfers.
     * @param operator Address that may be allowed to operate on tokens without being their owner.
     * @param tokenId Identifier number of a token.
     */
    error ERC721InsufficientApproval(address operator, uint256 tokenId);

    /**
     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.
     * @param approver Address initiating an approval operation.
     */
    error ERC721InvalidApprover(address approver);

    /**
     * @dev Indicates a failure with the `operator` to be approved. Used in approvals.
     * @param operator Address that may be allowed to operate on tokens without being their owner.
     */
    error ERC721InvalidOperator(address operator);
}

/**
 * @dev Standard ERC-1155 Errors
 * Interface of the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] custom errors for ERC-1155 tokens.
 */
interface IERC1155Errors {
    /**
     * @dev Indicates an error related to the current `balance` of a `sender`. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     * @param balance Current balance for the interacting account.
     * @param needed Minimum amount required to perform a transfer.
     * @param tokenId Identifier number of a token.
     */
    error ERC1155InsufficientBalance(address sender, uint256 balance, uint256 needed, uint256 tokenId);

    /**
     * @dev Indicates a failure with the token `sender`. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     */
    error ERC1155InvalidSender(address sender);

    /**
     * @dev Indicates a failure with the token `receiver`. Used in transfers.
     * @param receiver Address to which tokens are being transferred.
     */
    error ERC1155InvalidReceiver(address receiver);

    /**
     * @dev Indicates a failure with the `operator`’s approval. Used in transfers.
     * @param operator Address that may be allowed to operate on tokens without being their owner.
     * @param owner Address of the current owner of a token.
     */
    error ERC1155MissingApprovalForAll(address operator, address owner);

    /**
     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.
     * @param approver Address initiating an approval operation.
     */
    error ERC1155InvalidApprover(address approver);

    /**
     * @dev Indicates a failure with the `operator` to be approved. Used in approvals.
     * @param operator Address that may be allowed to operate on tokens without being their owner.
     */
    error ERC1155InvalidOperator(address operator);

    /**
     * @dev Indicates an array length mismatch between ids and values in a safeBatchTransferFrom operation.
     * Used in batch transfers.
     * @param idsLength Length of the array of token identifiers
     * @param valuesLength Length of the array of token amounts
     */
    error ERC1155InvalidArrayLength(uint256 idsLength, uint256 valuesLength);
}

// node_modules/@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol

// OpenZeppelin Contracts (last updated v5.1.0) (token/ERC20/extensions/IERC20Metadata.sol)

/**
 * @dev Interface for the optional metadata functions from the ERC-20 standard.
 */
interface IERC20Metadata is IERC20 {
    /**
     * @dev Returns the name of the token.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the symbol of the token.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the decimals places of the token.
     */
    function decimals() external view returns (uint8);
}

// node_modules/@uniswap/v4-core/src/libraries/LPFeeLibrary.sol

/// @notice Library of helper functions for a pools LP fee
library LPFeeLibrary {
    using LPFeeLibrary for uint24;
    using CustomRevert for bytes4;

    /// @notice Thrown when the static or dynamic fee on a pool exceeds 100%.
    error LPFeeTooLarge(uint24 fee);

    /// @notice An lp fee of exactly 0b1000000... signals a dynamic fee pool. This isn't a valid static fee as it is > MAX_LP_FEE
    uint24 public constant DYNAMIC_FEE_FLAG = 0x800000;

    /// @notice the second bit of the fee returned by beforeSwap is used to signal if the stored LP fee should be overridden in this swap
    // only dynamic-fee pools can return a fee via the beforeSwap hook
    uint24 public constant OVERRIDE_FEE_FLAG = 0x400000;

    /// @notice mask to remove the override fee flag from a fee returned by the beforeSwaphook
    uint24 public constant REMOVE_OVERRIDE_MASK = 0xBFFFFF;

    /// @notice the lp fee is represented in hundredths of a bip, so the max is 100%
    uint24 public constant MAX_LP_FEE = 1000000;

    /// @notice returns true if a pool's LP fee signals that the pool has a dynamic fee
    /// @param self The fee to check
    /// @return bool True of the fee is dynamic
    function isDynamicFee(uint24 self) internal pure returns (bool) {
        return self == DYNAMIC_FEE_FLAG;
    }

    /// @notice returns true if an LP fee is valid, aka not above the maximum permitted fee
    /// @param self The fee to check
    /// @return bool True of the fee is valid
    function isValid(uint24 self) internal pure returns (bool) {
        return self <= MAX_LP_FEE;
    }

    /// @notice validates whether an LP fee is larger than the maximum, and reverts if invalid
    /// @param self The fee to validate
    function validate(uint24 self) internal pure {
        if (!self.isValid()) LPFeeTooLarge.selector.revertWith(self);
    }

    /// @notice gets and validates the initial LP fee for a pool. Dynamic fee pools have an initial fee of 0.
    /// @dev if a dynamic fee pool wants a non-0 initial fee, it should call `updateDynamicLPFee` in the afterInitialize hook
    /// @param self The fee to get the initial LP from
    /// @return initialFee 0 if the fee is dynamic, otherwise the fee (if valid)
    function getInitialLPFee(uint24 self) internal pure returns (uint24) {
        // the initial fee for a dynamic fee pool is 0
        if (self.isDynamicFee()) return 0;
        self.validate();
        return self;
    }

    /// @notice returns true if the fee has the override flag set (2nd highest bit of the uint24)
    /// @param self The fee to check
    /// @return bool True of the fee has the override flag set
    function isOverride(uint24 self) internal pure returns (bool) {
        return self & OVERRIDE_FEE_FLAG != 0;
    }

    /// @notice returns a fee with the override flag removed
    /// @param self The fee to remove the override flag from
    /// @return fee The fee without the override flag set
    function removeOverrideFlag(uint24 self) internal pure returns (uint24) {
        return self & REMOVE_OVERRIDE_MASK;
    }

    /// @notice Removes the override flag and validates the fee (reverts if the fee is too large)
    /// @param self The fee to remove the override flag from, and then validate
    /// @return fee The fee without the override flag set (if valid)
    function removeOverrideFlagAndValidate(uint24 self) internal pure returns (uint24 fee) {
        fee = self.removeOverrideFlag();
        fee.validate();
    }
}

// node_modules/@uniswap/v4-core/src/libraries/SafeCast.sol

/// @title Safe casting methods
/// @notice Contains methods for safely casting between types
library SafeCast_1 {
    using CustomRevert for bytes4;

    error SafeCastOverflow();

    /// @notice Cast a uint256 to a uint160, revert on overflow
    /// @param x The uint256 to be downcasted
    /// @return y The downcasted integer, now type uint160
    function toUint160(uint256 x) internal pure returns (uint160 y) {
        y = uint160(x);
        if (y != x) SafeCastOverflow.selector.revertWith();
    }

    /// @notice Cast a uint256 to a uint128, revert on overflow
    /// @param x The uint256 to be downcasted
    /// @return y The downcasted integer, now type uint128
    function toUint128(uint256 x) internal pure returns (uint128 y) {
        y = uint128(x);
        if (x != y) SafeCastOverflow.selector.revertWith();
    }

    /// @notice Cast a int128 to a uint128, revert on overflow or underflow
    /// @param x The int128 to be casted
    /// @return y The casted integer, now type uint128
    function toUint128(int128 x) internal pure returns (uint128 y) {
        if (x < 0) SafeCastOverflow.selector.revertWith();
        y = uint128(x);
    }

    /// @notice Cast a int256 to a int128, revert on overflow or underflow
    /// @param x The int256 to be downcasted
    /// @return y The downcasted integer, now type int128
    function toInt128(int256 x) internal pure returns (int128 y) {
        y = int128(x);
        if (y != x) SafeCastOverflow.selector.revertWith();
    }

    /// @notice Cast a uint256 to a int256, revert on overflow
    /// @param x The uint256 to be casted
    /// @return y The casted integer, now type int256
    function toInt256(uint256 x) internal pure returns (int256 y) {
        y = int256(x);
        if (y < 0) SafeCastOverflow.selector.revertWith();
    }

    /// @notice Cast a uint256 to a int128, revert on overflow
    /// @param x The uint256 to be downcasted
    /// @return The downcasted integer, now type int128
    function toInt128(uint256 x) internal pure returns (int128) {
        if (x >= 1 << 127) SafeCastOverflow.selector.revertWith();
        return int128(int256(x));
    }
}

// node_modules/@openzeppelin/contracts/utils/math/SignedMath.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/math/SignedMath.sol)

/**
 * @dev Standard signed math utilities missing in the Solidity language.
 */
library SignedMath {
    /**
     * @dev Branchless ternary evaluation for `a ? b : c`. Gas costs are constant.
     *
     * IMPORTANT: This function may reduce bytecode size and consume less gas when used standalone.
     * However, the compiler may optimize Solidity ternary operations (i.e. `a ? b : c`) to only compute
     * one branch when needed, making this function more expensive.
     */
    function ternary(bool condition, int256 a, int256 b) internal pure returns (int256) {
        unchecked {
            // branchless ternary works because:
            // b ^ (a ^ b) == a
            // b ^ 0 == b
            return b ^ ((a ^ b) * int256(SafeCast_0.toUint(condition)));
        }
    }

    /**
     * @dev Returns the largest of two signed numbers.
     */
    function max(int256 a, int256 b) internal pure returns (int256) {
        return ternary(a > b, a, b);
    }

    /**
     * @dev Returns the smallest of two signed numbers.
     */
    function min(int256 a, int256 b) internal pure returns (int256) {
        return ternary(a < b, a, b);
    }

    /**
     * @dev Returns the average of two signed numbers without overflow.
     * The result is rounded towards zero.
     */
    function average(int256 a, int256 b) internal pure returns (int256) {
        // Formula from the book "Hacker's Delight"
        int256 x = (a & b) + ((a ^ b) >> 1);
        return x + (int256(uint256(x) >> 255) & (a ^ b));
    }

    /**
     * @dev Returns the absolute unsigned value of a signed value.
     */
    function abs(int256 n) internal pure returns (uint256) {
        unchecked {
            // Formula from the "Bit Twiddling Hacks" by Sean Eron Anderson.
            // Since `n` is a signed integer, the generated bytecode will use the SAR opcode to perform the right shift,
            // taking advantage of the most significant (or "sign" bit) in two's complement representation.
            // This opcode adds new most significant bits set to the value of the previous most significant bit. As a result,
            // the mask will either be `bytes32(0)` (if n is positive) or `~bytes32(0)` (if n is negative).
            int256 mask = n >> 255;

            // A `bytes32(0)` mask leaves the input unchanged, while a `~bytes32(0)` mask complements it.
            return uint256((n + mask) ^ mask);
        }
    }
}

// node_modules/@uniswap/v4-core/src/types/BalanceDelta.sol

/// @dev Two `int128` values packed into a single `int256` where the upper 128 bits represent the amount0
/// and the lower 128 bits represent the amount1.
type BalanceDelta is int256;

using {add as +, sub as -, eq as ==, neq as !=} for BalanceDelta global;
using BalanceDeltaLibrary for BalanceDelta global;
using SafeCast_1 for int256;

function toBalanceDelta(int128 _amount0, int128 _amount1) pure returns (BalanceDelta balanceDelta) {
    assembly ("memory-safe") {
        balanceDelta := or(shl(128, _amount0), and(sub(shl(128, 1), 1), _amount1))
    }
}

function add(BalanceDelta a, BalanceDelta b) pure returns (BalanceDelta) {
    int256 res0;
    int256 res1;
    assembly ("memory-safe") {
        let a0 := sar(128, a)
        let a1 := signextend(15, a)
        let b0 := sar(128, b)
        let b1 := signextend(15, b)
        res0 := add(a0, b0)
        res1 := add(a1, b1)
    }
    return toBalanceDelta(res0.toInt128(), res1.toInt128());
}

function sub(BalanceDelta a, BalanceDelta b) pure returns (BalanceDelta) {
    int256 res0;
    int256 res1;
    assembly ("memory-safe") {
        let a0 := sar(128, a)
        let a1 := signextend(15, a)
        let b0 := sar(128, b)
        let b1 := signextend(15, b)
        res0 := sub(a0, b0)
        res1 := sub(a1, b1)
    }
    return toBalanceDelta(res0.toInt128(), res1.toInt128());
}

function eq(BalanceDelta a, BalanceDelta b) pure returns (bool) {
    return BalanceDelta.unwrap(a) == BalanceDelta.unwrap(b);
}

function neq(BalanceDelta a, BalanceDelta b) pure returns (bool) {
    return BalanceDelta.unwrap(a) != BalanceDelta.unwrap(b);
}

/// @notice Library for getting the amount0 and amount1 deltas from the BalanceDelta type
library BalanceDeltaLibrary {
    /// @notice A BalanceDelta of 0
    BalanceDelta public constant ZERO_DELTA = BalanceDelta.wrap(0);

    function amount0(BalanceDelta balanceDelta) internal pure returns (int128 _amount0) {
        assembly ("memory-safe") {
            _amount0 := sar(128, balanceDelta)
        }
    }

    function amount1(BalanceDelta balanceDelta) internal pure returns (int128 _amount1) {
        assembly ("memory-safe") {
            _amount1 := signextend(15, balanceDelta)
        }
    }
}

// node_modules/@uniswap/v4-core/src/types/Currency.sol

type Currency is address;

using {greaterThan as >, lessThan as <, greaterThanOrEqualTo as >=, equals as ==} for Currency global;
using CurrencyLibrary for Currency global;

function equals(Currency currency, Currency other) pure returns (bool) {
    return Currency.unwrap(currency) == Currency.unwrap(other);
}

function greaterThan(Currency currency, Currency other) pure returns (bool) {
    return Currency.unwrap(currency) > Currency.unwrap(other);
}

function lessThan(Currency currency, Currency other) pure returns (bool) {
    return Currency.unwrap(currency) < Currency.unwrap(other);
}

function greaterThanOrEqualTo(Currency currency, Currency other) pure returns (bool) {
    return Currency.unwrap(currency) >= Currency.unwrap(other);
}

/// @title CurrencyLibrary
/// @dev This library allows for transferring and holding native tokens and ERC20 tokens
library CurrencyLibrary {
    /// @notice Additional context for ERC-7751 wrapped error when a native transfer fails
    error NativeTransferFailed();

    /// @notice Additional context for ERC-7751 wrapped error when an ERC20 transfer fails
    error ERC20TransferFailed();

    /// @notice A constant to represent the native currency
    Currency public constant ADDRESS_ZERO = Currency.wrap(address(0));

    function transfer(Currency currency, address to, uint256 amount) internal {
        // altered from https://github.com/transmissions11/solmate/blob/44a9963d4c78111f77caa0e65d677b8b46d6f2e6/src/utils/SafeTransferLib.sol
        // modified custom error selectors

        bool success;
        if (currency.isAddressZero()) {
            assembly ("memory-safe") {
                // Transfer the ETH and revert if it fails.
                success := call(gas(), to, amount, 0, 0, 0, 0)
            }
            // revert with NativeTransferFailed, containing the bubbled up error as an argument
            if (!success) {
                CustomRevert.bubbleUpAndRevertWith(to, bytes4(0), NativeTransferFailed.selector);
            }
        } else {
            assembly ("memory-safe") {
                // Get a pointer to some free memory.
                let fmp := mload(0x40)

                // Write the abi-encoded calldata into memory, beginning with the function selector.
                mstore(fmp, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
                mstore(add(fmp, 4), and(to, 0xffffffffffffffffffffffffffffffffffffffff)) // Append and mask the "to" argument.
                mstore(add(fmp, 36), amount) // Append the "amount" argument. Masking not required as it's a full 32 byte type.

                success :=
                    and(
                        // Set success to whether the call reverted, if not we check it either
                        // returned exactly 1 (can't just be non-zero data), or had no return data.
                        or(and(eq(mload(0), 1), gt(returndatasize(), 31)), iszero(returndatasize())),
                        // We use 68 because the length of our calldata totals up like so: 4 + 32 * 2.
                        // We use 0 and 32 to copy up to 32 bytes of return data into the scratch space.
                        // Counterintuitively, this call must be positioned second to the or() call in the
                        // surrounding and() call or else returndatasize() will be zero during the computation.
                        call(gas(), currency, 0, fmp, 68, 0, 32)
                    )

                // Now clean the memory we used
                mstore(fmp, 0) // 4 byte `selector` and 28 bytes of `to` were stored here
                mstore(add(fmp, 0x20), 0) // 4 bytes of `to` and 28 bytes of `amount` were stored here
                mstore(add(fmp, 0x40), 0) // 4 bytes of `amount` were stored here
            }
            // revert with ERC20TransferFailed, containing the bubbled up error as an argument
            if (!success) {
                CustomRevert.bubbleUpAndRevertWith(
                    Currency.unwrap(currency), IERC20Minimal.transfer.selector, ERC20TransferFailed.selector
                );
            }
        }
    }

    function balanceOfSelf(Currency currency) internal view returns (uint256) {
        if (currency.isAddressZero()) {
            return address(this).balance;
        } else {
            return IERC20Minimal(Currency.unwrap(currency)).balanceOf(address(this));
        }
    }

    function balanceOf(Currency currency, address owner) internal view returns (uint256) {
        if (currency.isAddressZero()) {
            return owner.balance;
        } else {
            return IERC20Minimal(Currency.unwrap(currency)).balanceOf(owner);
        }
    }

    function isAddressZero(Currency currency) internal pure returns (bool) {
        return Currency.unwrap(currency) == Currency.unwrap(ADDRESS_ZERO);
    }

    function toId(Currency currency) internal pure returns (uint256) {
        return uint160(Currency.unwrap(currency));
    }

    // If the upper 12 bytes are non-zero, they will be zero-ed out
    // Therefore, fromId() and toId() are not inverses of each other
    function fromId(uint256 id) internal pure returns (Currency) {
        return Currency.wrap(address(uint160(id)));
    }
}

// node_modules/@openzeppelin/contracts/utils/math/Math.sol

// OpenZeppelin Contracts (last updated v5.3.0) (utils/math/Math.sol)

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    enum Rounding {
        Floor, // Toward negative infinity
        Ceil, // Toward positive infinity
        Trunc, // Toward zero
        Expand // Away from zero
    }

    /**
     * @dev Return the 512-bit addition of two uint256.
     *
     * The result is stored in two 256 variables such that sum = high * 2²⁵⁶ + low.
     */
    function add512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        assembly ("memory-safe") {
            low := add(a, b)
            high := lt(low, a)
        }
    }

    /**
     * @dev Return the 512-bit multiplication of two uint256.
     *
     * The result is stored in two 256 variables such that product = high * 2²⁵⁶ + low.
     */
    function mul512(uint256 a, uint256 b) internal pure returns (uint256 high, uint256 low) {
        // 512-bit multiply [high low] = x * y. Compute the product mod 2²⁵⁶ and mod 2²⁵⁶ - 1, then use
        // the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
        // variables such that product = high * 2²⁵⁶ + low.
        assembly ("memory-safe") {
            let mm := mulmod(a, b, not(0))
            low := mul(a, b)
            high := sub(sub(mm, low), lt(mm, low))
        }
    }

    /**
     * @dev Returns the addition of two unsigned integers, with a success flag (no overflow).
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a + b;
            success = c >= a;
            result = c * SafeCast_0.toUint(success);
        }
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, with a success flag (no overflow).
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a - b;
            success = c <= a;
            result = c * SafeCast_0.toUint(success);
        }
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with a success flag (no overflow).
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            uint256 c = a * b;
            assembly ("memory-safe") {
                // Only true when the multiplication doesn't overflow
                // (c / a == b) || (a == 0)
                success := or(eq(div(c, a), b), iszero(a))
            }
            // equivalent to: success ? c : 0
            result = c * SafeCast_0.toUint(success);
        }
    }

    /**
     * @dev Returns the division of two unsigned integers, with a success flag (no division by zero).
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                // The `DIV` opcode returns zero when the denominator is 0.
                result := div(a, b)
            }
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a success flag (no division by zero).
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool success, uint256 result) {
        unchecked {
            success = b > 0;
            assembly ("memory-safe") {
                // The `MOD` opcode returns zero when the denominator is 0.
                result := mod(a, b)
            }
        }
    }

    /**
     * @dev Unsigned saturating addition, bounds to `2²⁵⁶ - 1` instead of overflowing.
     */
    function saturatingAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryAdd(a, b);
        return ternary(success, result, type(uint256).max);
    }

    /**
     * @dev Unsigned saturating subtraction, bounds to zero instead of overflowing.
     */
    function saturatingSub(uint256 a, uint256 b) internal pure returns (uint256) {
        (, uint256 result) = trySub(a, b);
        return result;
    }

    /**
     * @dev Unsigned saturating multiplication, bounds to `2²⁵⁶ - 1` instead of overflowing.
     */
    function saturatingMul(uint256 a, uint256 b) internal pure returns (uint256) {
        (bool success, uint256 result) = tryMul(a, b);
        return ternary(success, result, type(uint256).max);
    }

    /**
     * @dev Branchless ternary evaluation for `a ? b : c`. Gas costs are constant.
     *
     * IMPORTANT: This function may reduce bytecode size and consume less gas when used standalone.
     * However, the compiler may optimize Solidity ternary operations (i.e. `a ? b : c`) to only compute
     * one branch when needed, making this function more expensive.
     */
    function ternary(bool condition, uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            // branchless ternary works because:
            // b ^ (a ^ b) == a
            // b ^ 0 == b
            return b ^ ((a ^ b) * SafeCast_0.toUint(condition));
        }
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a > b, a, b);
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return ternary(a < b, a, b);
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow.
        return (a & b) + (a ^ b) / 2;
    }

    /**
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds towards infinity instead
     * of rounding towards zero.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) {
            // Guarantee the same behavior as in a regular Solidity division.
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }

        // The following calculation ensures accurate ceiling division without overflow.
        // Since a is non-zero, (a - 1) / b will not overflow.
        // The largest possible result occurs when (a - 1) / b is type(uint256).max,
        // but the largest value we can obtain is type(uint256).max - 1, which happens
        // when a = type(uint256).max and b = 1.
        unchecked {
            return SafeCast_0.toUint(a > 0) * ((a - 1) / b + 1);
        }
    }

    /**
     * @dev Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or
     * denominator == 0.
     *
     * Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv) with further edits by
     * Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);

            // Handle non-overflow cases, 256 by 256 division.
            if (high == 0) {
                // Solidity will revert if denominator == 0, unlike the div opcode on its own.
                // The surrounding unchecked block does not change this fact.
                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.
                return low / denominator;
            }

            // Make sure the result is less than 2²⁵⁶. Also prevents denominator == 0.
            if (denominator <= high) {
                Panic.panic(ternary(denominator == 0, Panic.DIVISION_BY_ZERO, Panic.UNDER_OVERFLOW));
            }

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [high low].
            uint256 remainder;
            assembly ("memory-safe") {
                // Compute remainder using mulmod.
                remainder := mulmod(x, y, denominator)

                // Subtract 256 bit number from 512 bit number.
                high := sub(high, gt(remainder, low))
                low := sub(low, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator.
            // Always >= 1. See https://cs.stackexchange.com/q/138556/92363.

            uint256 twos = denominator & (0 - denominator);
            assembly ("memory-safe") {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [high low] by twos.
                low := div(low, twos)

                // Flip twos such that it is 2²⁵⁶ / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from high into low.
            low |= high * twos;

            // Invert denominator mod 2²⁵⁶. Now that denominator is an odd number, it has an inverse modulo 2²⁵⁶ such
            // that denominator * inv ≡ 1 mod 2²⁵⁶. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv ≡ 1 mod 2⁴.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also
            // works in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2¹⁶
            inverse *= 2 - denominator * inverse; // inverse mod 2³²
            inverse *= 2 - denominator * inverse; // inverse mod 2⁶⁴
            inverse *= 2 - denominator * inverse; // inverse mod 2¹²⁸
            inverse *= 2 - denominator * inverse; // inverse mod 2²⁵⁶

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2²⁵⁶. Since the preconditions guarantee that the outcome is
            // less than 2²⁵⁶, this is the final result. We don't need to compute the high bits of the result and high
            // is no longer required.
            result = low * inverse;
            return result;
        }
    }

    /**
     * @dev Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        return mulDiv(x, y, denominator) + SafeCast_0.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, denominator) > 0);
    }

    /**
     * @dev Calculates floor(x * y >> n) with full precision. Throws if result overflows a uint256.
     */
    function mulShr(uint256 x, uint256 y, uint8 n) internal pure returns (uint256 result) {
        unchecked {
            (uint256 high, uint256 low) = mul512(x, y);
            if (high >= 1 << n) {
                Panic.panic(Panic.UNDER_OVERFLOW);
            }
            return (high << (256 - n)) | (low >> n);
        }
    }

    /**
     * @dev Calculates x * y >> n with full precision, following the selected rounding direction.
     */
    function mulShr(uint256 x, uint256 y, uint8 n, Rounding rounding) internal pure returns (uint256) {
        return mulShr(x, y, n) + SafeCast_0.toUint(unsignedRoundsUp(rounding) && mulmod(x, y, 1 << n) > 0);
    }

    /**
     * @dev Calculate the modular multiplicative inverse of a number in Z/nZ.
     *
     * If n is a prime, then Z/nZ is a field. In that case all elements are inversible, except 0.
     * If n is not a prime, then Z/nZ is not a field, and some elements might not be inversible.
     *
     * If the input value is not inversible, 0 is returned.
     *
     * NOTE: If you know for sure that n is (big) a prime, it may be cheaper to use Fermat's little theorem and get the
     * inverse using `Math.modExp(a, n - 2, n)`. See {invModPrime}.
     */
    function invMod(uint256 a, uint256 n) internal pure returns (uint256) {
        unchecked {
            if (n == 0) return 0;

            // The inverse modulo is calculated using the Extended Euclidean Algorithm (iterative version)
            // Used to compute integers x and y such that: ax + ny = gcd(a, n).
            // When the gcd is 1, then the inverse of a modulo n exists and it's x.
            // ax + ny = 1
            // ax = 1 + (-y)n
            // ax ≡ 1 (mod n) # x is the inverse of a modulo n

            // If the remainder is 0 the gcd is n right away.
            uint256 remainder = a % n;
            uint256 gcd = n;

            // Therefore the initial coefficients are:
            // ax + ny = gcd(a, n) = n
            // 0a + 1n = n
            int256 x = 0;
            int256 y = 1;

            while (remainder != 0) {
                uint256 quotient = gcd / remainder;

                (gcd, remainder) = (
                    // The old remainder is the next gcd to try.
                    remainder,
                    // Compute the next remainder.
                    // Can't overflow given that (a % gcd) * (gcd // (a % gcd)) <= gcd
                    // where gcd is at most n (capped to type(uint256).max)
                    gcd - remainder * quotient
                );

                (x, y) = (
                    // Increment the coefficient of a.
                    y,
                    // Decrement the coefficient of n.
                    // Can overflow, but the result is casted to uint256 so that the
                    // next value of y is "wrapped around" to a value between 0 and n - 1.
                    x - y * int256(quotient)
                );
            }

            if (gcd != 1) return 0; // No inverse exists.
            return ternary(x < 0, n - uint256(-x), uint256(x)); // Wrap the result if it's negative.
        }
    }

    /**
     * @dev Variant of {invMod}. More efficient, but only works if `p` is known to be a prime greater than `2`.
     *
     * From https://en.wikipedia.org/wiki/Fermat%27s_little_theorem[Fermat's little theorem], we know that if p is
     * prime, then `a**(p-1) ≡ 1 mod p`. As a consequence, we have `a * a**(p-2) ≡ 1 mod p`, which means that
     * `a**(p-2)` is the modular multiplicative inverse of a in Fp.
     *
     * NOTE: this function does NOT check that `p` is a prime greater than `2`.
     */
    function invModPrime(uint256 a, uint256 p) internal view returns (uint256) {
        unchecked {
            return Math.modExp(a, p - 2, p);
        }
    }

    /**
     * @dev Returns the modular exponentiation of the specified base, exponent and modulus (b ** e % m)
     *
     * Requirements:
     * - modulus can't be zero
     * - underlying staticcall to precompile must succeed
     *
     * IMPORTANT: The result is only valid if the underlying call succeeds. When using this function, make
     * sure the chain you're using it on supports the precompiled contract for modular exponentiation
     * at address 0x05 as specified in https://eips.ethereum.org/EIPS/eip-198[EIP-198]. Otherwise,
     * the underlying function will succeed given the lack of a revert, but the result may be incorrectly
     * interpreted as 0.
     */
    function modExp(uint256 b, uint256 e, uint256 m) internal view returns (uint256) {
        (bool success, uint256 result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    /**
     * @dev Returns the modular exponentiation of the specified base, exponent and modulus (b ** e % m).
     * It includes a success flag indicating if the operation succeeded. Operation will be marked as failed if trying
     * to operate modulo 0 or if the underlying precompile reverted.
     *
     * IMPORTANT: The result is only valid if the success flag is true. When using this function, make sure the chain
     * you're using it on supports the precompiled contract for modular exponentiation at address 0x05 as specified in
     * https://eips.ethereum.org/EIPS/eip-198[EIP-198]. Otherwise, the underlying function will succeed given the lack
     * of a revert, but the result may be incorrectly interpreted as 0.
     */
    function tryModExp(uint256 b, uint256 e, uint256 m) internal view returns (bool success, uint256 result) {
        if (m == 0) return (false, 0);
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            // | Offset    | Content    | Content (Hex)                                                      |
            // |-----------|------------|--------------------------------------------------------------------|
            // | 0x00:0x1f | size of b  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x20:0x3f | size of e  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x40:0x5f | size of m  | 0x0000000000000000000000000000000000000000000000000000000000000020 |
            // | 0x60:0x7f | value of b | 0x<.............................................................b> |
            // | 0x80:0x9f | value of e | 0x<.............................................................e> |
            // | 0xa0:0xbf | value of m | 0x<.............................................................m> |
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), 0x20)
            mstore(add(ptr, 0x40), 0x20)
            mstore(add(ptr, 0x60), b)
            mstore(add(ptr, 0x80), e)
            mstore(add(ptr, 0xa0), m)

            // Given the result < m, it's guaranteed to fit in 32 bytes,
            // so we can use the memory scratch space located at offset 0.
            success := staticcall(gas(), 0x05, ptr, 0xc0, 0x00, 0x20)
            result := mload(0x00)
        }
    }

    /**
     * @dev Variant of {modExp} that supports inputs of arbitrary length.
     */
    function modExp(bytes memory b, bytes memory e, bytes memory m) internal view returns (bytes memory) {
        (bool success, bytes memory result) = tryModExp(b, e, m);
        if (!success) {
            Panic.panic(Panic.DIVISION_BY_ZERO);
        }
        return result;
    }

    /**
     * @dev Variant of {tryModExp} that supports inputs of arbitrary length.
     */
    function tryModExp(
        bytes memory b,
        bytes memory e,
        bytes memory m
    ) internal view returns (bool success, bytes memory result) {
        if (_zeroBytes(m)) return (false, new bytes(0));

        uint256 mLen = m.length;

        // Encode call args in result and move the free memory pointer
        result = abi.encodePacked(b.length, e.length, mLen, b, e, m);

        assembly ("memory-safe") {
            let dataPtr := add(result, 0x20)
            // Write result on top of args to avoid allocating extra memory.
            success := staticcall(gas(), 0x05, dataPtr, mload(result), dataPtr, mLen)
            // Overwrite the length.
            // result.length > returndatasize() is guaranteed because returndatasize() == m.length
            mstore(result, mLen)
            // Set the memory pointer after the returned data.
            mstore(0x40, add(dataPtr, mLen))
        }
    }

    /**
     * @dev Returns whether the provided byte array is zero.
     */
    function _zeroBytes(bytes memory byteArray) private pure returns (bool) {
        for (uint256 i = 0; i < byteArray.length; ++i) {
            if (byteArray[i] != 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded
     * towards zero.
     *
     * This method is based on Newton's method for computing square roots; the algorithm is restricted to only
     * using integer operations.
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        unchecked {
            // Take care of easy edge cases when a == 0 or a == 1
            if (a <= 1) {
                return a;
            }

            // In this function, we use Newton's method to get a root of `f(x) := x² - a`. It involves building a
            // sequence x_n that converges toward sqrt(a). For each iteration x_n, we also define the error between
            // the current value as `ε_n = | x_n - sqrt(a) |`.
            //
            // For our first estimation, we consider `e` the smallest power of 2 which is bigger than the square root
            // of the target. (i.e. `2**(e-1) ≤ sqrt(a) < 2**e`). We know that `e ≤ 128` because `(2¹²⁸)² = 2²⁵⁶` is
            // bigger than any uint256.
            //
            // By noticing that
            // `2**(e-1) ≤ sqrt(a) < 2**e → (2**(e-1))² ≤ a < (2**e)² → 2**(2*e-2) ≤ a < 2**(2*e)`
            // we can deduce that `e - 1` is `log2(a) / 2`. We can thus compute `x_n = 2**(e-1)` using a method similar
            // to the msb function.
            uint256 aa = a;
            uint256 xn = 1;

            if (aa >= (1 << 128)) {
                aa >>= 128;
                xn <<= 64;
            }
            if (aa >= (1 << 64)) {
                aa >>= 64;
                xn <<= 32;
            }
            if (aa >= (1 << 32)) {
                aa >>= 32;
                xn <<= 16;
            }
            if (aa >= (1 << 16)) {
                aa >>= 16;
                xn <<= 8;
            }
            if (aa >= (1 << 8)) {
                aa >>= 8;
                xn <<= 4;
            }
            if (aa >= (1 << 4)) {
                aa >>= 4;
                xn <<= 2;
            }
            if (aa >= (1 << 2)) {
                xn <<= 1;
            }

            // We now have x_n such that `x_n = 2**(e-1) ≤ sqrt(a) < 2**e = 2 * x_n`. This implies ε_n ≤ 2**(e-1).
            //
            // We can refine our estimation by noticing that the middle of that interval minimizes the error.
            // If we move x_n to equal 2**(e-1) + 2**(e-2), then we reduce the error to ε_n ≤ 2**(e-2).
            // This is going to be our x_0 (and ε_0)
            xn = (3 * xn) >> 1; // ε_0 := | x_0 - sqrt(a) | ≤ 2**(e-2)

            // From here, Newton's method give us:
            // x_{n+1} = (x_n + a / x_n) / 2
            //
            // One should note that:
            // x_{n+1}² - a = ((x_n + a / x_n) / 2)² - a
            //              = ((x_n² + a) / (2 * x_n))² - a
            //              = (x_n⁴ + 2 * a * x_n² + a²) / (4 * x_n²) - a
            //              = (x_n⁴ + 2 * a * x_n² + a² - 4 * a * x_n²) / (4 * x_n²)
            //              = (x_n⁴ - 2 * a * x_n² + a²) / (4 * x_n²)
            //              = (x_n² - a)² / (2 * x_n)²
            //              = ((x_n² - a) / (2 * x_n))²
            //              ≥ 0
            // Which proves that for all n ≥ 1, sqrt(a) ≤ x_n
            //
            // This gives us the proof of quadratic convergence of the sequence:
            // ε_{n+1} = | x_{n+1} - sqrt(a) |
            //         = | (x_n + a / x_n) / 2 - sqrt(a) |
            //         = | (x_n² + a - 2*x_n*sqrt(a)) / (2 * x_n) |
            //         = | (x_n - sqrt(a))² / (2 * x_n) |
            //         = | ε_n² / (2 * x_n) |
            //         = ε_n² / | (2 * x_n) |
            //
            // For the first iteration, we have a special case where x_0 is known:
            // ε_1 = ε_0² / | (2 * x_0) |
            //     ≤ (2**(e-2))² / (2 * (2**(e-1) + 2**(e-2)))
            //     ≤ 2**(2*e-4) / (3 * 2**(e-1))
            //     ≤ 2**(e-3) / 3
            //     ≤ 2**(e-3-log2(3))
            //     ≤ 2**(e-4.5)
            //
            // For the following iterations, we use the fact that, 2**(e-1) ≤ sqrt(a) ≤ x_n:
            // ε_{n+1} = ε_n² / | (2 * x_n) |
            //         ≤ (2**(e-k))² / (2 * 2**(e-1))
            //         ≤ 2**(2*e-2*k) / 2**e
            //         ≤ 2**(e-2*k)
            xn = (xn + a / xn) >> 1; // ε_1 := | x_1 - sqrt(a) | ≤ 2**(e-4.5)  -- special case, see above
            xn = (xn + a / xn) >> 1; // ε_2 := | x_2 - sqrt(a) | ≤ 2**(e-9)    -- general case with k = 4.5
            xn = (xn + a / xn) >> 1; // ε_3 := | x_3 - sqrt(a) | ≤ 2**(e-18)   -- general case with k = 9
            xn = (xn + a / xn) >> 1; // ε_4 := | x_4 - sqrt(a) | ≤ 2**(e-36)   -- general case with k = 18
            xn = (xn + a / xn) >> 1; // ε_5 := | x_5 - sqrt(a) | ≤ 2**(e-72)   -- general case with k = 36
            xn = (xn + a / xn) >> 1; // ε_6 := | x_6 - sqrt(a) | ≤ 2**(e-144)  -- general case with k = 72

            // Because e ≤ 128 (as discussed during the first estimation phase), we know have reached a precision
            // ε_6 ≤ 2**(e-144) < 1. Given we're operating on integers, then we can ensure that xn is now either
            // sqrt(a) or sqrt(a) + 1.
            return xn - SafeCast_0.toUint(xn > a / xn);
        }
    }

    /**
     * @dev Calculates sqrt(a), following the selected rounding direction.
     */
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + SafeCast_0.toUint(unsignedRoundsUp(rounding) && result * result < a);
        }
    }

    /**
     * @dev Return the log in base 2 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log2(uint256 x) internal pure returns (uint256 r) {
        // If value has upper 128 bits set, log2 result is at least 128
        r = SafeCast_0.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        // If upper 64 bits of 128-bit half set, add 64 to result
        r |= SafeCast_0.toUint((x >> r) > 0xffffffffffffffff) << 6;
        // If upper 32 bits of 64-bit half set, add 32 to result
        r |= SafeCast_0.toUint((x >> r) > 0xffffffff) << 5;
        // If upper 16 bits of 32-bit half set, add 16 to result
        r |= SafeCast_0.toUint((x >> r) > 0xffff) << 4;
        // If upper 8 bits of 16-bit half set, add 8 to result
        r |= SafeCast_0.toUint((x >> r) > 0xff) << 3;
        // If upper 4 bits of 8-bit half set, add 4 to result
        r |= SafeCast_0.toUint((x >> r) > 0xf) << 2;

        // Shifts value right by the current result and use it as an index into this lookup table:
        //
        // | x (4 bits) |  index  | table[index] = MSB position |
        // |------------|---------|-----------------------------|
        // |    0000    |    0    |        table[0] = 0         |
        // |    0001    |    1    |        table[1] = 0         |
        // |    0010    |    2    |        table[2] = 1         |
        // |    0011    |    3    |        table[3] = 1         |
        // |    0100    |    4    |        table[4] = 2         |
        // |    0101    |    5    |        table[5] = 2         |
        // |    0110    |    6    |        table[6] = 2         |
        // |    0111    |    7    |        table[7] = 2         |
        // |    1000    |    8    |        table[8] = 3         |
        // |    1001    |    9    |        table[9] = 3         |
        // |    1010    |   10    |        table[10] = 3        |
        // |    1011    |   11    |        table[11] = 3        |
        // |    1100    |   12    |        table[12] = 3        |
        // |    1101    |   13    |        table[13] = 3        |
        // |    1110    |   14    |        table[14] = 3        |
        // |    1111    |   15    |        table[15] = 3        |
        //
        // The lookup table is represented as a 32-byte value with the MSB positions for 0-15 in the last 16 bytes.
        assembly ("memory-safe") {
            r := or(r, byte(shr(r, x), 0x0000010102020202030303030303030300000000000000000000000000000000))
        }
    }

    /**
     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + SafeCast_0.toUint(unsignedRoundsUp(rounding) && 1 << result < value);
        }
    }

    /**
     * @dev Return the log in base 10 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + SafeCast_0.toUint(unsignedRoundsUp(rounding) && 10 ** result < value);
        }
    }

    /**
     * @dev Return the log in base 256 of a positive value rounded towards zero.
     * Returns 0 if given 0.
     *
     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.
     */
    function log256(uint256 x) internal pure returns (uint256 r) {
        // If value has upper 128 bits set, log2 result is at least 128
        r = SafeCast_0.toUint(x > 0xffffffffffffffffffffffffffffffff) << 7;
        // If upper 64 bits of 128-bit half set, add 64 to result
        r |= SafeCast_0.toUint((x >> r) > 0xffffffffffffffff) << 6;
        // If upper 32 bits of 64-bit half set, add 32 to result
        r |= SafeCast_0.toUint((x >> r) > 0xffffffff) << 5;
        // If upper 16 bits of 32-bit half set, add 16 to result
        r |= SafeCast_0.toUint((x >> r) > 0xffff) << 4;
        // Add 1 if upper 8 bits of 16-bit half set, and divide accumulated result by 8
        return (r >> 3) | SafeCast_0.toUint((x >> r) > 0xff);
    }

    /**
     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + SafeCast_0.toUint(unsignedRoundsUp(rounding) && 1 << (result << 3) < value);
        }
    }

    /**
     * @dev Returns whether a provided rounding mode is considered rounding up for unsigned integers.
     */
    function unsignedRoundsUp(Rounding rounding) internal pure returns (bool) {
        return uint8(rounding) % 2 == 1;
    }
}

// node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol

// OpenZeppelin Contracts (last updated v5.3.0) (token/ERC20/ERC20.sol)

/**
 * @dev Implementation of the {IERC20} interface.
 *
 * This implementation is agnostic to the way tokens are created. This means
 * that a supply mechanism has to be added in a derived contract using {_mint}.
 *
 * TIP: For a detailed writeup see our guide
 * https://forum.openzeppelin.com/t/how-to-implement-erc20-supply-mechanisms/226[How
 * to implement supply mechanisms].
 *
 * The default value of {decimals} is 18. To change this, you should override
 * this function so it returns a different value.
 *
 * We have followed general OpenZeppelin Contracts guidelines: functions revert
 * instead returning `false` on failure. This behavior is nonetheless
 * conventional and does not conflict with the expectations of ERC-20
 * applications.
 */
abstract contract ERC20 is Context, IERC20, IERC20Metadata, IERC20Errors {
    mapping(address account => uint256) private _balances;

    mapping(address account => mapping(address spender => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;

    /**
     * @dev Sets the values for {name} and {symbol}.
     *
     * Both values are immutable: they can only be set once during construction.
     */
    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    /**
     * @dev Returns the name of the token.
     */
    function name() public view virtual returns (string memory) {
        return _name;
    }

    /**
     * @dev Returns the symbol of the token, usually a shorter version of the
     * name.
     */
    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    /**
     * @dev Returns the number of decimals used to get its user representation.
     * For example, if `decimals` equals `2`, a balance of `505` tokens should
     * be displayed to a user as `5.05` (`505 / 10 ** 2`).
     *
     * Tokens usually opt for a value of 18, imitating the relationship between
     * Ether and Wei. This is the default value returned by this function, unless
     * it's overridden.
     *
     * NOTE: This information is only used for _display_ purposes: it in
     * no way affects any of the arithmetic of the contract, including
     * {IERC20-balanceOf} and {IERC20-transfer}.
     */
    function decimals() public view virtual returns (uint8) {
        return 18;
    }

    /**
     * @dev See {IERC20-totalSupply}.
     */
    function totalSupply() public view virtual returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev See {IERC20-balanceOf}.
     */
    function balanceOf(address account) public view virtual returns (uint256) {
        return _balances[account];
    }

    /**
     * @dev See {IERC20-transfer}.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - the caller must have a balance of at least `value`.
     */
    function transfer(address to, uint256 value) public virtual returns (bool) {
        address owner = _msgSender();
        _transfer(owner, to, value);
        return true;
    }

    /**
     * @dev See {IERC20-allowance}.
     */
    function allowance(address owner, address spender) public view virtual returns (uint256) {
        return _allowances[owner][spender];
    }

    /**
     * @dev See {IERC20-approve}.
     *
     * NOTE: If `value` is the maximum `uint256`, the allowance is not updated on
     * `transferFrom`. This is semantically equivalent to an infinite approval.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function approve(address spender, uint256 value) public virtual returns (bool) {
        address owner = _msgSender();
        _approve(owner, spender, value);
        return true;
    }

    /**
     * @dev See {IERC20-transferFrom}.
     *
     * Skips emitting an {Approval} event indicating an allowance update. This is not
     * required by the ERC. See {xref-ERC20-_approve-address-address-uint256-bool-}[_approve].
     *
     * NOTE: Does not update the allowance if the current allowance
     * is the maximum `uint256`.
     *
     * Requirements:
     *
     * - `from` and `to` cannot be the zero address.
     * - `from` must have a balance of at least `value`.
     * - the caller must have allowance for ``from``'s tokens of at least
     * `value`.
     */
    function transferFrom(address from, address to, uint256 value) public virtual returns (bool) {
        address spender = _msgSender();
        _spendAllowance(from, spender, value);
        _transfer(from, to, value);
        return true;
    }

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to`.
     *
     * This internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead.
     */
    function _transfer(address from, address to, uint256 value) internal {
        if (from == address(0)) {
            revert ERC20InvalidSender(address(0));
        }
        if (to == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }
        _update(from, to, value);
    }

    /**
     * @dev Transfers a `value` amount of tokens from `from` to `to`, or alternatively mints (or burns) if `from`
     * (or `to`) is the zero address. All customizations to transfers, mints, and burns should be done by overriding
     * this function.
     *
     * Emits a {Transfer} event.
     */
    function _update(address from, address to, uint256 value) internal virtual {
        if (from == address(0)) {
            // Overflow check required: The rest of the code assumes that totalSupply never overflows
            _totalSupply += value;
        } else {
            uint256 fromBalance = _balances[from];
            if (fromBalance < value) {
                revert ERC20InsufficientBalance(from, fromBalance, value);
            }
            unchecked {
                // Overflow not possible: value <= fromBalance <= totalSupply.
                _balances[from] = fromBalance - value;
            }
        }

        if (to == address(0)) {
            unchecked {
                // Overflow not possible: value <= totalSupply or value <= fromBalance <= totalSupply.
                _totalSupply -= value;
            }
        } else {
            unchecked {
                // Overflow not possible: balance + value is at most totalSupply, which we know fits into a uint256.
                _balances[to] += value;
            }
        }

        emit Transfer(from, to, value);
    }

    /**
     * @dev Creates a `value` amount of tokens and assigns them to `account`, by transferring it from address(0).
     * Relies on the `_update` mechanism
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead.
     */
    function _mint(address account, uint256 value) internal {
        if (account == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }
        _update(address(0), account, value);
    }

    /**
     * @dev Destroys a `value` amount of tokens from `account`, lowering the total supply.
     * Relies on the `_update` mechanism.
     *
     * Emits a {Transfer} event with `to` set to the zero address.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead
     */
    function _burn(address account, uint256 value) internal {
        if (account == address(0)) {
            revert ERC20InvalidSender(address(0));
        }
        _update(account, address(0), value);
    }

    /**
     * @dev Sets `value` as the allowance of `spender` over the `owner`'s tokens.
     *
     * This internal function is equivalent to `approve`, and can be used to
     * e.g. set automatic allowances for certain subsystems, etc.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `owner` cannot be the zero address.
     * - `spender` cannot be the zero address.
     *
     * Overrides to this logic should be done to the variant with an additional `bool emitEvent` argument.
     */
    function _approve(address owner, address spender, uint256 value) internal {
        _approve(owner, spender, value, true);
    }

    /**
     * @dev Variant of {_approve} with an optional flag to enable or disable the {Approval} event.
     *
     * By default (when calling {_approve}) the flag is set to true. On the other hand, approval changes made by
     * `_spendAllowance` during the `transferFrom` operation set the flag to false. This saves gas by not emitting any
     * `Approval` event during `transferFrom` operations.
     *
     * Anyone who wishes to continue emitting `Approval` events on the`transferFrom` operation can force the flag to
     * true using the following override:
     *
     * ```solidity
     * function _approve(address owner, address spender, uint256 value, bool) internal virtual override {
     *     super._approve(owner, spender, value, true);
     * }
     * ```
     *
     * Requirements are the same as {_approve}.
     */
    function _approve(address owner, address spender, uint256 value, bool emitEvent) internal virtual {
        if (owner == address(0)) {
            revert ERC20InvalidApprover(address(0));
        }
        if (spender == address(0)) {
            revert ERC20InvalidSpender(address(0));
        }
        _allowances[owner][spender] = value;
        if (emitEvent) {
            emit Approval(owner, spender, value);
        }
    }

    /**
     * @dev Updates `owner`'s allowance for `spender` based on spent `value`.
     *
     * Does not update the allowance value in case of infinite allowance.
     * Revert if not enough allowance is available.
     *
     * Does not emit an {Approval} event.
     */
    function _spendAllowance(address owner, address spender, uint256 value) internal virtual {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance < type(uint256).max) {
            if (currentAllowance < value) {
                revert ERC20InsufficientAllowance(spender, currentAllowance, value);
            }
            unchecked {
                _approve(owner, spender, currentAllowance - value, false);
            }
        }
    }
}

// node_modules/@openzeppelin/contracts/utils/Strings.sol

// OpenZeppelin Contracts (last updated v5.3.0) (utils/Strings.sol)

/**
 * @dev String operations.
 */
library Strings {
    using SafeCast_0 for *;

    bytes16 private constant HEX_DIGITS = "0123456789abcdef";
    uint8 private constant ADDRESS_LENGTH = 20;
    uint256 private constant SPECIAL_CHARS_LOOKUP =
        (1 << 0x08) | // backspace
            (1 << 0x09) | // tab
            (1 << 0x0a) | // newline
            (1 << 0x0c) | // form feed
            (1 << 0x0d) | // carriage return
            (1 << 0x22) | // double quote
            (1 << 0x5c); // backslash

    /**
     * @dev The `value` string doesn't fit in the specified `length`.
     */
    error StringsInsufficientHexLength(uint256 value, uint256 length);

    /**
     * @dev The string being parsed contains characters that are not in scope of the given base.
     */
    error StringsInvalidChar();

    /**
     * @dev The string being parsed is not a properly formatted address.
     */
    error StringsInvalidAddressFormat();

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = Math.log10(value) + 1;
            string memory buffer = new string(length);
            uint256 ptr;
            assembly ("memory-safe") {
                ptr := add(buffer, add(32, length))
            }
            while (true) {
                ptr--;
                assembly ("memory-safe") {
                    mstore8(ptr, byte(mod(value, 10), HEX_DIGITS))
                }
                value /= 10;
                if (value == 0) break;
            }
            return buffer;
        }
    }

    /**
     * @dev Converts a `int256` to its ASCII `string` decimal representation.
     */
    function toStringSigned(int256 value) internal pure returns (string memory) {
        return string.concat(value < 0 ? "-" : "", toString(SignedMath.abs(value)));
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        unchecked {
            return toHexString(value, Math.log256(value) + 1);
        }
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        uint256 localValue = value;
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = HEX_DIGITS[localValue & 0xf];
            localValue >>= 4;
        }
        if (localValue != 0) {
            revert StringsInsufficientHexLength(value, length);
        }
        return string(buffer);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal
     * representation.
     */
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), ADDRESS_LENGTH);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its checksummed ASCII `string` hexadecimal
     * representation, according to EIP-55.
     */
    function toChecksumHexString(address addr) internal pure returns (string memory) {
        bytes memory buffer = bytes(toHexString(addr));

        // hash the hex part of buffer (skip length + 2 bytes, length 40)
        uint256 hashValue;
        assembly ("memory-safe") {
            hashValue := shr(96, keccak256(add(buffer, 0x22), 40))
        }

        for (uint256 i = 41; i > 1; --i) {
            // possible values for buffer[i] are 48 (0) to 57 (9) and 97 (a) to 102 (f)
            if (hashValue & 0xf > 7 && uint8(buffer[i]) > 96) {
                // case shift by xoring with 0x20
                buffer[i] ^= 0x20;
            }
            hashValue >>= 4;
        }
        return string(buffer);
    }

    /**
     * @dev Returns true if the two strings are equal.
     */
    function equal(string memory a, string memory b) internal pure returns (bool) {
        return bytes(a).length == bytes(b).length && keccak256(bytes(a)) == keccak256(bytes(b));
    }

    /**
     * @dev Parse a decimal string and returns the value as a `uint256`.
     *
     * Requirements:
     * - The string must be formatted as `[0-9]*`
     * - The result must fit into an `uint256` type
     */
    function parseUint(string memory input) internal pure returns (uint256) {
        return parseUint(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseUint-string} that parses a substring of `input` located between position `begin` (included) and
     * `end` (excluded).
     *
     * Requirements:
     * - The substring must be formatted as `[0-9]*`
     * - The result must fit into an `uint256` type
     */
    function parseUint(string memory input, uint256 begin, uint256 end) internal pure returns (uint256) {
        (bool success, uint256 value) = tryParseUint(input, begin, end);
        if (!success) revert StringsInvalidChar();
        return value;
    }

    /**
     * @dev Variant of {parseUint-string} that returns false if the parsing fails because of an invalid character.
     *
     * NOTE: This function will revert if the result does not fit in a `uint256`.
     */
    function tryParseUint(string memory input) internal pure returns (bool success, uint256 value) {
        return _tryParseUintUncheckedBounds(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseUint-string-uint256-uint256} that returns false if the parsing fails because of an invalid
     * character.
     *
     * NOTE: This function will revert if the result does not fit in a `uint256`.
     */
    function tryParseUint(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, uint256 value) {
        if (end > bytes(input).length || begin > end) return (false, 0);
        return _tryParseUintUncheckedBounds(input, begin, end);
    }

    /**
     * @dev Implementation of {tryParseUint-string-uint256-uint256} that does not check bounds. Caller should make sure that
     * `begin <= end <= input.length`. Other inputs would result in undefined behavior.
     */
    function _tryParseUintUncheckedBounds(
        string memory input,
        uint256 begin,
        uint256 end
    ) private pure returns (bool success, uint256 value) {
        bytes memory buffer = bytes(input);

        uint256 result = 0;
        for (uint256 i = begin; i < end; ++i) {
            uint8 chr = _tryParseChr(bytes1(_unsafeReadBytesOffset(buffer, i)));
            if (chr > 9) return (false, 0);
            result *= 10;
            result += chr;
        }
        return (true, result);
    }

    /**
     * @dev Parse a decimal string and returns the value as a `int256`.
     *
     * Requirements:
     * - The string must be formatted as `[-+]?[0-9]*`
     * - The result must fit in an `int256` type.
     */
    function parseInt(string memory input) internal pure returns (int256) {
        return parseInt(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseInt-string} that parses a substring of `input` located between position `begin` (included) and
     * `end` (excluded).
     *
     * Requirements:
     * - The substring must be formatted as `[-+]?[0-9]*`
     * - The result must fit in an `int256` type.
     */
    function parseInt(string memory input, uint256 begin, uint256 end) internal pure returns (int256) {
        (bool success, int256 value) = tryParseInt(input, begin, end);
        if (!success) revert StringsInvalidChar();
        return value;
    }

    /**
     * @dev Variant of {parseInt-string} that returns false if the parsing fails because of an invalid character or if
     * the result does not fit in a `int256`.
     *
     * NOTE: This function will revert if the absolute value of the result does not fit in a `uint256`.
     */
    function tryParseInt(string memory input) internal pure returns (bool success, int256 value) {
        return _tryParseIntUncheckedBounds(input, 0, bytes(input).length);
    }

    uint256 private constant ABS_MIN_INT256 = 2 ** 255;

    /**
     * @dev Variant of {parseInt-string-uint256-uint256} that returns false if the parsing fails because of an invalid
     * character or if the result does not fit in a `int256`.
     *
     * NOTE: This function will revert if the absolute value of the result does not fit in a `uint256`.
     */
    function tryParseInt(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, int256 value) {
        if (end > bytes(input).length || begin > end) return (false, 0);
        return _tryParseIntUncheckedBounds(input, begin, end);
    }

    /**
     * @dev Implementation of {tryParseInt-string-uint256-uint256} that does not check bounds. Caller should make sure that
     * `begin <= end <= input.length`. Other inputs would result in undefined behavior.
     */
    function _tryParseIntUncheckedBounds(
        string memory input,
        uint256 begin,
        uint256 end
    ) private pure returns (bool success, int256 value) {
        bytes memory buffer = bytes(input);

        // Check presence of a negative sign.
        bytes1 sign = begin == end ? bytes1(0) : bytes1(_unsafeReadBytesOffset(buffer, begin)); // don't do out-of-bound (possibly unsafe) read if sub-string is empty
        bool positiveSign = sign == bytes1("+");
        bool negativeSign = sign == bytes1("-");
        uint256 offset = (positiveSign || negativeSign).toUint();

        (bool absSuccess, uint256 absValue) = tryParseUint(input, begin + offset, end);

        if (absSuccess && absValue < ABS_MIN_INT256) {
            return (true, negativeSign ? -int256(absValue) : int256(absValue));
        } else if (absSuccess && negativeSign && absValue == ABS_MIN_INT256) {
            return (true, type(int256).min);
        } else return (false, 0);
    }

    /**
     * @dev Parse a hexadecimal string (with or without "0x" prefix), and returns the value as a `uint256`.
     *
     * Requirements:
     * - The string must be formatted as `(0x)?[0-9a-fA-F]*`
     * - The result must fit in an `uint256` type.
     */
    function parseHexUint(string memory input) internal pure returns (uint256) {
        return parseHexUint(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseHexUint-string} that parses a substring of `input` located between position `begin` (included) and
     * `end` (excluded).
     *
     * Requirements:
     * - The substring must be formatted as `(0x)?[0-9a-fA-F]*`
     * - The result must fit in an `uint256` type.
     */
    function parseHexUint(string memory input, uint256 begin, uint256 end) internal pure returns (uint256) {
        (bool success, uint256 value) = tryParseHexUint(input, begin, end);
        if (!success) revert StringsInvalidChar();
        return value;
    }

    /**
     * @dev Variant of {parseHexUint-string} that returns false if the parsing fails because of an invalid character.
     *
     * NOTE: This function will revert if the result does not fit in a `uint256`.
     */
    function tryParseHexUint(string memory input) internal pure returns (bool success, uint256 value) {
        return _tryParseHexUintUncheckedBounds(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseHexUint-string-uint256-uint256} that returns false if the parsing fails because of an
     * invalid character.
     *
     * NOTE: This function will revert if the result does not fit in a `uint256`.
     */
    function tryParseHexUint(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, uint256 value) {
        if (end > bytes(input).length || begin > end) return (false, 0);
        return _tryParseHexUintUncheckedBounds(input, begin, end);
    }

    /**
     * @dev Implementation of {tryParseHexUint-string-uint256-uint256} that does not check bounds. Caller should make sure that
     * `begin <= end <= input.length`. Other inputs would result in undefined behavior.
     */
    function _tryParseHexUintUncheckedBounds(
        string memory input,
        uint256 begin,
        uint256 end
    ) private pure returns (bool success, uint256 value) {
        bytes memory buffer = bytes(input);

        // skip 0x prefix if present
        bool hasPrefix = (end > begin + 1) && bytes2(_unsafeReadBytesOffset(buffer, begin)) == bytes2("0x"); // don't do out-of-bound (possibly unsafe) read if sub-string is empty
        uint256 offset = hasPrefix.toUint() * 2;

        uint256 result = 0;
        for (uint256 i = begin + offset; i < end; ++i) {
            uint8 chr = _tryParseChr(bytes1(_unsafeReadBytesOffset(buffer, i)));
            if (chr > 15) return (false, 0);
            result *= 16;
            unchecked {
                // Multiplying by 16 is equivalent to a shift of 4 bits (with additional overflow check).
                // This guarantees that adding a value < 16 will not cause an overflow, hence the unchecked.
                result += chr;
            }
        }
        return (true, result);
    }

    /**
     * @dev Parse a hexadecimal string (with or without "0x" prefix), and returns the value as an `address`.
     *
     * Requirements:
     * - The string must be formatted as `(0x)?[0-9a-fA-F]{40}`
     */
    function parseAddress(string memory input) internal pure returns (address) {
        return parseAddress(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseAddress-string} that parses a substring of `input` located between position `begin` (included) and
     * `end` (excluded).
     *
     * Requirements:
     * - The substring must be formatted as `(0x)?[0-9a-fA-F]{40}`
     */
    function parseAddress(string memory input, uint256 begin, uint256 end) internal pure returns (address) {
        (bool success, address value) = tryParseAddress(input, begin, end);
        if (!success) revert StringsInvalidAddressFormat();
        return value;
    }

    /**
     * @dev Variant of {parseAddress-string} that returns false if the parsing fails because the input is not a properly
     * formatted address. See {parseAddress-string} requirements.
     */
    function tryParseAddress(string memory input) internal pure returns (bool success, address value) {
        return tryParseAddress(input, 0, bytes(input).length);
    }

    /**
     * @dev Variant of {parseAddress-string-uint256-uint256} that returns false if the parsing fails because input is not a properly
     * formatted address. See {parseAddress-string-uint256-uint256} requirements.
     */
    function tryParseAddress(
        string memory input,
        uint256 begin,
        uint256 end
    ) internal pure returns (bool success, address value) {
        if (end > bytes(input).length || begin > end) return (false, address(0));

        bool hasPrefix = (end > begin + 1) && bytes2(_unsafeReadBytesOffset(bytes(input), begin)) == bytes2("0x"); // don't do out-of-bound (possibly unsafe) read if sub-string is empty
        uint256 expectedLength = 40 + hasPrefix.toUint() * 2;

        // check that input is the correct length
        if (end - begin == expectedLength) {
            // length guarantees that this does not overflow, and value is at most type(uint160).max
            (bool s, uint256 v) = _tryParseHexUintUncheckedBounds(input, begin, end);
            return (s, address(uint160(v)));
        } else {
            return (false, address(0));
        }
    }

    function _tryParseChr(bytes1 chr) private pure returns (uint8) {
        uint8 value = uint8(chr);

        // Try to parse `chr`:
        // - Case 1: [0-9]
        // - Case 2: [a-f]
        // - Case 3: [A-F]
        // - otherwise not supported
        unchecked {
            if (value > 47 && value < 58) value -= 48;
            else if (value > 96 && value < 103) value -= 87;
            else if (value > 64 && value < 71) value -= 55;
            else return type(uint8).max;
        }

        return value;
    }

    /**
     * @dev Escape special characters in JSON strings. This can be useful to prevent JSON injection in NFT metadata.
     *
     * WARNING: This function should only be used in double quoted JSON strings. Single quotes are not escaped.
     *
     * NOTE: This function escapes all unicode characters, and not just the ones in ranges defined in section 2.5 of
     * RFC-4627 (U+0000 to U+001F, U+0022 and U+005C). ECMAScript's `JSON.parse` does recover escaped unicode
     * characters that are not in this range, but other tooling may provide different results.
     */
    function escapeJSON(string memory input) internal pure returns (string memory) {
        bytes memory buffer = bytes(input);
        bytes memory output = new bytes(2 * buffer.length); // worst case scenario
        uint256 outputLength = 0;

        for (uint256 i; i < buffer.length; ++i) {
            bytes1 char = bytes1(_unsafeReadBytesOffset(buffer, i));
            if (((SPECIAL_CHARS_LOOKUP & (1 << uint8(char))) != 0)) {
                output[outputLength++] = "\\";
                if (char == 0x08) output[outputLength++] = "b";
                else if (char == 0x09) output[outputLength++] = "t";
                else if (char == 0x0a) output[outputLength++] = "n";
                else if (char == 0x0c) output[outputLength++] = "f";
                else if (char == 0x0d) output[outputLength++] = "r";
                else if (char == 0x5c) output[outputLength++] = "\\";
                else if (char == 0x22) {
                    // solhint-disable-next-line quotes
                    output[outputLength++] = '"';
                }
            } else {
                output[outputLength++] = char;
            }
        }
        // write the actual length and deallocate unused memory
        assembly ("memory-safe") {
            mstore(output, outputLength)
            mstore(0x40, add(output, shl(5, shr(5, add(outputLength, 63)))))
        }

        return string(output);
    }

    /**
     * @dev Reads a bytes32 from a bytes array without bounds checking.
     *
     * NOTE: making this function internal would mean it could be used with memory unsafe offset, and marking the
     * assembly block as such would prevent some optimizations.
     */
    function _unsafeReadBytesOffset(bytes memory buffer, uint256 offset) private pure returns (bytes32 value) {
        // This is not memory safe in the general case, but all calls to this private function are within bounds.
        assembly ("memory-safe") {
            value := mload(add(buffer, add(0x20, offset)))
        }
    }
}

// node_modules/@fhenixprotocol/cofhe-contracts/FHE.sol

// solhint-disable one-contract-per-file

type ebool is uint256;
type euint8 is uint256;
type euint16 is uint256;
type euint32 is uint256;
type euint64 is uint256;
type euint128 is uint256;
type euint256 is uint256;
type eaddress is uint256;

// ================================
// \/ \/ \/ \/ \/ \/ \/ \/ \/ \/ \/
// TODO : CHANGE ME AFTER DEPLOYING
// /\ /\ /\ /\ /\ /\ /\ /\ /\ /\ /\
// ================================
//solhint-disable const-name-snakecase
address constant TASK_MANAGER_ADDRESS = 0xeA30c4B8b44078Bbf8a6ef5b9f1eC1626C7848D9;

library Common {
    error InvalidHexCharacter(bytes1 char);
    error SecurityZoneOutOfBounds(int32 value);

    // Default value for temp hash calculation in unary operations
    string private constant DEFAULT_VALUE = "0";

    function convertInt32ToUint256(int32 value) internal pure returns (uint256) {
        if (value < 0) {
            revert SecurityZoneOutOfBounds(value);
        }
        return uint256(uint32(value));
    }

    function isInitialized(uint256 hash) internal pure returns (bool) {
        return hash != 0;
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(ebool v) internal pure returns (bool) {
        return isInitialized(ebool.unwrap(v));
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(euint8 v) internal pure returns (bool) {
        return isInitialized(euint8.unwrap(v));
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(euint16 v) internal pure returns (bool) {
        return isInitialized(euint16.unwrap(v));
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(euint32 v) internal pure returns (bool) {
        return isInitialized(euint32.unwrap(v));
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(euint64 v) internal pure returns (bool) {
        return isInitialized(euint64.unwrap(v));
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(euint128 v) internal pure returns (bool) {
        return isInitialized(euint128.unwrap(v));
    }

    // Return true if the encrypted integer is initialized and false otherwise.
    function isInitialized(euint256 v) internal pure returns (bool) {
        return isInitialized(euint256.unwrap(v));
    }

    function isInitialized(eaddress v) internal pure returns (bool) {
        return isInitialized(eaddress.unwrap(v));
    }

    function createUint256Inputs(uint256 input1) internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = input1;
        return inputs;
    }

    function createUint256Inputs(uint256 input1, uint256 input2) internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = input1;
        inputs[1] = input2;
        return inputs;
    }

    function createUint256Inputs(uint256 input1, uint256 input2, uint256 input3) internal pure returns (uint256[] memory) {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = input1;
        inputs[1] = input2;
        inputs[2] = input3;
        return inputs;
    }
}

library Impl {
    function trivialEncrypt(uint256 value, uint8 toType, int32 securityZone) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(toType, FunctionId.trivialEncrypt, new uint256[](0), Common.createUint256Inputs(value, toType, Common.convertInt32ToUint256(securityZone)));
    }

    function cast(uint256 key, uint8 toType) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(toType, FunctionId.cast, Common.createUint256Inputs(key), Common.createUint256Inputs(toType));
    }

    function select(uint8 returnType, ebool control, uint256 ifTrue, uint256 ifFalse) internal returns (uint256 result) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(returnType,
            FunctionId.select,
            Common.createUint256Inputs(ebool.unwrap(control), ifTrue, ifFalse),
            new uint256[](0));
    }

    function mathOp(uint8 returnType, uint256 lhs, uint256 rhs, FunctionId functionId) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(returnType, functionId, Common.createUint256Inputs(lhs, rhs), new uint256[](0));
    }

    function decrypt(uint256 input) internal returns (uint256) {
        ITaskManager(TASK_MANAGER_ADDRESS).createDecryptTask(input, msg.sender);
        return input;
    }

    function getDecryptResult(uint256 input) internal view returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).getDecryptResult(input);
    }

    function getDecryptResultSafe(uint256 input) internal view returns (uint256 result, bool decrypted) {
        return ITaskManager(TASK_MANAGER_ADDRESS).getDecryptResultSafe(input);
    }

    function not(uint8 returnType, uint256 input) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(returnType, FunctionId.not, Common.createUint256Inputs(input), new uint256[](0));
    }

    function square(uint8 returnType, uint256 input) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(returnType, FunctionId.square, Common.createUint256Inputs(input), new uint256[](0));
    }

    function verifyInput(EncryptedInput memory input) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).verifyInput(input, msg.sender);
    }

    /// @notice Generates a random value of a given type with the given seed, for the provided securityZone
    /// @dev Calls the desired function
    /// @param uintType the type of the random value to generate
    /// @param seed the seed to use to create a random value from
    /// @param securityZone the security zone to use for the random value
    function random(uint8 uintType, uint64 seed, int32 securityZone) internal returns (uint256) {
        return ITaskManager(TASK_MANAGER_ADDRESS).createTask(uintType, FunctionId.random, new uint256[](0), Common.createUint256Inputs(seed, Common.convertInt32ToUint256(securityZone)));
    }

    /// @notice Generates a random value of a given type with the given seed
    /// @dev Calls the desired function
    /// @param uintType the type of the random value to generate
    /// @param seed the seed to use to create a random value from
    function random(uint8 uintType, uint32 seed) internal returns (uint256) {
        return random(uintType, seed, 0);
    }

    /// @notice Generates a random value of a given type
    /// @dev Calls the desired function
    /// @param uintType the type of the random value to generate
    function random(uint8 uintType) internal returns (uint256) {
        return random(uintType, 0, 0);
    }

}

library FHE {

    error InvalidEncryptedInput(uint8 got, uint8 expected);
    /// @notice Perform the addition operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted addition
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the addition result
    function add(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.add));
    }

    /// @notice Perform the addition operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted addition
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the addition result
    function add(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.add));
    }

    /// @notice Perform the addition operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted addition
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the addition result
    function add(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.add));
    }

    /// @notice Perform the addition operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted addition
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the addition result
    function add(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.add));
    }

    /// @notice Perform the addition operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted addition
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the addition result
    function add(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.add));
    }

    /// @notice Perform the addition operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted addition
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the addition result
    function add(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.add));
    }

    /// @notice Perform the less than or equal to operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type ebool containing the comparison result
    function lte(euint8 lhs, euint8 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.lte));
    }

    /// @notice Perform the less than or equal to operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type ebool containing the comparison result
    function lte(euint16 lhs, euint16 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.lte));
    }

    /// @notice Perform the less than or equal to operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type ebool containing the comparison result
    function lte(euint32 lhs, euint32 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.lte));
    }

    /// @notice Perform the less than or equal to operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type ebool containing the comparison result
    function lte(euint64 lhs, euint64 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.lte));
    }

    /// @notice Perform the less than or equal to operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type ebool containing the comparison result
    function lte(euint128 lhs, euint128 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.lte));
    }

    /// @notice Perform the less than or equal to operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type ebool containing the comparison result
    function lte(euint256 lhs, euint256 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.lte));
    }

    /// @notice Perform the subtraction operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted subtraction
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the subtraction result
    function sub(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.sub));
    }

    /// @notice Perform the subtraction operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted subtraction
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the subtraction result
    function sub(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.sub));
    }

    /// @notice Perform the subtraction operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted subtraction
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the subtraction result
    function sub(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.sub));
    }

    /// @notice Perform the subtraction operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted subtraction
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the subtraction result
    function sub(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.sub));
    }

    /// @notice Perform the subtraction operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted subtraction
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the subtraction result
    function sub(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.sub));
    }

    /// @notice Perform the subtraction operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted subtraction
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the subtraction result
    function sub(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.sub));
    }

    /// @notice Perform the multiplication operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted multiplication
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the multiplication result
    function mul(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.mul));
    }

    /// @notice Perform the multiplication operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted multiplication
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the multiplication result
    function mul(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.mul));
    }

    /// @notice Perform the multiplication operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted multiplication
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the multiplication result
    function mul(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.mul));
    }

    /// @notice Perform the multiplication operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted multiplication
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the multiplication result
    function mul(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.mul));
    }

    /// @notice Perform the multiplication operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted multiplication
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the multiplication result
    function mul(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.mul));
    }

    /// @notice Perform the multiplication operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted multiplication
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the multiplication result
    function mul(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.mul));
    }

    /// @notice Perform the less than operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type ebool containing the comparison result
    function lt(euint8 lhs, euint8 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.lt));
    }

    /// @notice Perform the less than operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type ebool containing the comparison result
    function lt(euint16 lhs, euint16 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.lt));
    }

    /// @notice Perform the less than operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type ebool containing the comparison result
    function lt(euint32 lhs, euint32 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.lt));
    }

    /// @notice Perform the less than operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type ebool containing the comparison result
    function lt(euint64 lhs, euint64 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.lt));
    }

    /// @notice Perform the less than operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type ebool containing the comparison result
    function lt(euint128 lhs, euint128 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.lt));
    }

    /// @notice Perform the less than operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type ebool containing the comparison result
    function lt(euint256 lhs, euint256 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.lt));
    }

    /// @notice Perform the division operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted division
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the division result
    function div(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.div));
    }

    /// @notice Perform the division operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted division
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the division result
    function div(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.div));
    }

    /// @notice Perform the division operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted division
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the division result
    function div(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.div));
    }

    /// @notice Perform the division operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted division
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the division result
    function div(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.div));
    }

    /// @notice Perform the division operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted division
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the division result
    function div(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.div));
    }

    /// @notice Perform the division operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted division
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the division result
    function div(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.div));
    }

    /// @notice Perform the greater than operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type ebool containing the comparison result
    function gt(euint8 lhs, euint8 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.gt));
    }

    /// @notice Perform the greater than operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type ebool containing the comparison result
    function gt(euint16 lhs, euint16 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.gt));
    }

    /// @notice Perform the greater than operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type ebool containing the comparison result
    function gt(euint32 lhs, euint32 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.gt));
    }

    /// @notice Perform the greater than operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type ebool containing the comparison result
    function gt(euint64 lhs, euint64 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.gt));
    }

    /// @notice Perform the greater than operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type ebool containing the comparison result
    function gt(euint128 lhs, euint128 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.gt));
    }

    /// @notice Perform the greater than operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type ebool containing the comparison result
    function gt(euint256 lhs, euint256 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.gt));
    }

    /// @notice Perform the greater than or equal to operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type ebool containing the comparison result
    function gte(euint8 lhs, euint8 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.gte));
    }

    /// @notice Perform the greater than or equal to operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type ebool containing the comparison result
    function gte(euint16 lhs, euint16 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.gte));
    }

    /// @notice Perform the greater than or equal to operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type ebool containing the comparison result
    function gte(euint32 lhs, euint32 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.gte));
    }

    /// @notice Perform the greater than or equal to operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type ebool containing the comparison result
    function gte(euint64 lhs, euint64 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.gte));
    }

    /// @notice Perform the greater than or equal to operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type ebool containing the comparison result
    function gte(euint128 lhs, euint128 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.gte));
    }

    /// @notice Perform the greater than or equal to operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted comparison
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type ebool containing the comparison result
    function gte(euint256 lhs, euint256 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.gte));
    }

    /// @notice Perform the remainder operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted remainder calculation
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the remainder result
    function rem(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.rem));
    }

    /// @notice Perform the remainder operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted remainder calculation
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the remainder result
    function rem(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.rem));
    }

    /// @notice Perform the remainder operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted remainder calculation
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the remainder result
    function rem(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.rem));
    }

    /// @notice Perform the remainder operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted remainder calculation
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the remainder result
    function rem(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.rem));
    }

    /// @notice Perform the remainder operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted remainder calculation
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the remainder result
    function rem(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.rem));
    }

    /// @notice Perform the remainder operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted remainder calculation
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the remainder result
    function rem(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.rem));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type ebool
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return result of type ebool containing the AND result
    function and(ebool lhs, ebool rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEbool(true);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEbool(true);
        }

        return ebool.wrap(Impl.mathOp(Utils.EBOOL_TFHE, ebool.unwrap(lhs), ebool.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the AND result
    function and(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the AND result
    function and(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the AND result
    function and(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the AND result
    function and(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the AND result
    function and(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise AND operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise AND
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the AND result
    function and(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.and));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type ebool
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return result of type ebool containing the OR result
    function or(ebool lhs, ebool rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEbool(true);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEbool(true);
        }

        return ebool.wrap(Impl.mathOp(Utils.EBOOL_TFHE, ebool.unwrap(lhs), ebool.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the OR result
    function or(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the OR result
    function or(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the OR result
    function or(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the OR result
    function or(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the OR result
    function or(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise OR operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise OR
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the OR result
    function or(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.or));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type ebool
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return result of type ebool containing the XOR result
    function xor(ebool lhs, ebool rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEbool(true);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEbool(true);
        }

        return ebool.wrap(Impl.mathOp(Utils.EBOOL_TFHE, ebool.unwrap(lhs), ebool.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the XOR result
    function xor(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the XOR result
    function xor(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the XOR result
    function xor(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the XOR result
    function xor(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the XOR result
    function xor(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the bitwise XOR operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted bitwise XOR
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the XOR result
    function xor(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.xor));
    }

    /// @notice Perform the equality operation on two parameters of type ebool
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return result of type ebool containing the equality result
    function eq(ebool lhs, ebool rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEbool(true);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEbool(true);
        }

        return ebool.wrap(Impl.mathOp(Utils.EBOOL_TFHE, ebool.unwrap(lhs), ebool.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type ebool containing the equality result
    function eq(euint8 lhs, euint8 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type ebool containing the equality result
    function eq(euint16 lhs, euint16 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type ebool containing the equality result
    function eq(euint32 lhs, euint32 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type ebool containing the equality result
    function eq(euint64 lhs, euint64 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type ebool containing the equality result
    function eq(euint128 lhs, euint128 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type ebool containing the equality result
    function eq(euint256 lhs, euint256 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the equality operation on two parameters of type eaddress
    /// @dev Verifies that inputs are initialized, performs encrypted equality check
    /// @param lhs input of type eaddress
    /// @param rhs second input of type eaddress
    /// @return result of type ebool containing the equality result
    function eq(eaddress lhs, eaddress rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEaddress(address(0));
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEaddress(address(0));
        }

        return ebool.wrap(Impl.mathOp(Utils.EADDRESS_TFHE, eaddress.unwrap(lhs), eaddress.unwrap(rhs), FunctionId.eq));
    }

    /// @notice Perform the inequality operation on two parameters of type ebool
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return result of type ebool containing the inequality result
    function ne(ebool lhs, ebool rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEbool(true);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEbool(true);
        }

        return ebool.wrap(Impl.mathOp(Utils.EBOOL_TFHE, ebool.unwrap(lhs), ebool.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type ebool containing the inequality result
    function ne(euint8 lhs, euint8 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type ebool containing the inequality result
    function ne(euint16 lhs, euint16 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type ebool containing the inequality result
    function ne(euint32 lhs, euint32 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type ebool containing the inequality result
    function ne(euint64 lhs, euint64 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type ebool containing the inequality result
    function ne(euint128 lhs, euint128 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type ebool containing the inequality result
    function ne(euint256 lhs, euint256 rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return ebool.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the inequality operation on two parameters of type eaddress
    /// @dev Verifies that inputs are initialized, performs encrypted inequality check
    /// @param lhs input of type eaddress
    /// @param rhs second input of type eaddress
    /// @return result of type ebool containing the inequality result
    function ne(eaddress lhs, eaddress rhs) internal returns (ebool) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEaddress(address(0));
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEaddress(address(0));
        }

        return ebool.wrap(Impl.mathOp(Utils.EADDRESS_TFHE, eaddress.unwrap(lhs), eaddress.unwrap(rhs), FunctionId.ne));
    }

    /// @notice Perform the minimum operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted minimum comparison
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the minimum value
    function min(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.min));
    }

    /// @notice Perform the minimum operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted minimum comparison
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the minimum value
    function min(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.min));
    }

    /// @notice Perform the minimum operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted minimum comparison
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the minimum value
    function min(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.min));
    }

    /// @notice Perform the minimum operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted minimum comparison
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the minimum value
    function min(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.min));
    }

    /// @notice Perform the minimum operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted minimum comparison
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the minimum value
    function min(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.min));
    }

    /// @notice Perform the minimum operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted minimum comparison
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the minimum value
    function min(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.min));
    }

    /// @notice Perform the maximum operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted maximum calculation
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the maximum result
    function max(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.max));
    }

    /// @notice Perform the maximum operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted maximum calculation
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the maximum result
    function max(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.max));
    }

    /// @notice Perform the maximum operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted maximum calculation
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the maximum result
    function max(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.max));
    }

    /// @notice Perform the maximum operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted maximum comparison
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the maximum value
    function max(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.max));
    }

    /// @notice Perform the maximum operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted maximum comparison
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the maximum value
    function max(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.max));
    }

    /// @notice Perform the maximum operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted maximum comparison
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the maximum value
    function max(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.max));
    }

    /// @notice Perform the shift left operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted left shift
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the left shift result
    function shl(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.shl));
    }

    /// @notice Perform the shift left operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted left shift
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the left shift result
    function shl(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.shl));
    }

    /// @notice Perform the shift left operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted left shift
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the left shift result
    function shl(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.shl));
    }

    /// @notice Perform the shift left operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted left shift
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the left shift result
    function shl(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.shl));
    }

    /// @notice Perform the shift left operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted left shift
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the left shift result
    function shl(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.shl));
    }

    /// @notice Perform the shift left operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted left shift
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the left shift result
    function shl(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.shl));
    }

    /// @notice Perform the shift right operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted right shift
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the right shift result
    function shr(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.shr));
    }

    /// @notice Perform the shift right operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted right shift
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the right shift result
    function shr(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.shr));
    }

    /// @notice Perform the shift right operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted right shift
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the right shift result
    function shr(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.shr));
    }

    /// @notice Perform the shift right operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted right shift
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the right shift result
    function shr(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.shr));
    }

    /// @notice Perform the shift right operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted right shift
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the right shift result
    function shr(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.shr));
    }

    /// @notice Perform the shift right operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted right shift
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the right shift result
    function shr(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.shr));
    }

    /// @notice Perform the rol operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted left rotation
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the left rotation result
    function rol(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.rol));
    }

    /// @notice Perform the rotate left operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted left rotation
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the left rotation result
    function rol(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.rol));
    }

    /// @notice Perform the rotate left operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted left rotation
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the left rotation result
    function rol(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.rol));
    }

    /// @notice Perform the rotate left operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted left rotation
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the left rotation result
    function rol(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.rol));
    }

    /// @notice Perform the rotate left operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted left rotation
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the left rotation result
    function rol(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.rol));
    }

    /// @notice Perform the rotate left operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted left rotation
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the left rotation result
    function rol(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.rol));
    }

    /// @notice Perform the rotate right operation on two parameters of type euint8
    /// @dev Verifies that inputs are initialized, performs encrypted right rotation
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return result of type euint8 containing the right rotation result
    function ror(euint8 lhs, euint8 rhs) internal returns (euint8) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint8(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint8(0);
        }

        return euint8.wrap(Impl.mathOp(Utils.EUINT8_TFHE, euint8.unwrap(lhs), euint8.unwrap(rhs), FunctionId.ror));
    }

    /// @notice Perform the rotate right operation on two parameters of type euint16
    /// @dev Verifies that inputs are initialized, performs encrypted right rotation
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return result of type euint16 containing the right rotation result
    function ror(euint16 lhs, euint16 rhs) internal returns (euint16) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint16(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint16(0);
        }

        return euint16.wrap(Impl.mathOp(Utils.EUINT16_TFHE, euint16.unwrap(lhs), euint16.unwrap(rhs), FunctionId.ror));
    }

    /// @notice Perform the rotate right operation on two parameters of type euint32
    /// @dev Verifies that inputs are initialized, performs encrypted right rotation
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return result of type euint32 containing the right rotation result
    function ror(euint32 lhs, euint32 rhs) internal returns (euint32) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint32(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint32(0);
        }

        return euint32.wrap(Impl.mathOp(Utils.EUINT32_TFHE, euint32.unwrap(lhs), euint32.unwrap(rhs), FunctionId.ror));
    }

    /// @notice Perform the rotate right operation on two parameters of type euint64
    /// @dev Verifies that inputs are initialized, performs encrypted right rotation
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return result of type euint64 containing the right rotation result
    function ror(euint64 lhs, euint64 rhs) internal returns (euint64) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint64(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint64(0);
        }

        return euint64.wrap(Impl.mathOp(Utils.EUINT64_TFHE, euint64.unwrap(lhs), euint64.unwrap(rhs), FunctionId.ror));
    }

    /// @notice Perform the rotate right operation on two parameters of type euint128
    /// @dev Verifies that inputs are initialized, performs encrypted right rotation
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return result of type euint128 containing the right rotation result
    function ror(euint128 lhs, euint128 rhs) internal returns (euint128) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint128(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint128(0);
        }

        return euint128.wrap(Impl.mathOp(Utils.EUINT128_TFHE, euint128.unwrap(lhs), euint128.unwrap(rhs), FunctionId.ror));
    }

    /// @notice Perform the rotate right operation on two parameters of type euint256
    /// @dev Verifies that inputs are initialized, performs encrypted right rotation
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return result of type euint256 containing the right rotation result
    function ror(euint256 lhs, euint256 rhs) internal returns (euint256) {
        if (!Common.isInitialized(lhs)) {
            lhs = asEuint256(0);
        }
        if (!Common.isInitialized(rhs)) {
            rhs = asEuint256(0);
        }

        return euint256.wrap(Impl.mathOp(Utils.EUINT256_TFHE, euint256.unwrap(lhs), euint256.unwrap(rhs), FunctionId.ror));
    }

    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(ebool input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }

        ebool.wrap(Impl.decrypt(ebool.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(euint8 input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint8(0);
        }

        euint8.wrap(Impl.decrypt(euint8.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(euint16 input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint16(0);
        }

        euint16.wrap(Impl.decrypt(euint16.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(euint32 input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint32(0);
        }

        euint32.wrap(Impl.decrypt(euint32.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(euint64 input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint64(0);
        }

        euint64.wrap(Impl.decrypt(euint64.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(euint128 input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint128(0);
        }

        euint128.wrap(Impl.decrypt(euint128.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(euint256 input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint256(0);
        }

        euint256.wrap(Impl.decrypt(euint256.unwrap(input1)));
    }
    /// @notice Performs the async decrypt operation on a ciphertext
    /// @dev The decrypted output should be asynchronously handled by the IAsyncFHEReceiver implementation
    /// @param input1 the input ciphertext
    function decrypt(eaddress input1) internal {
        if (!Common.isInitialized(input1)) {
            input1 = asEaddress(address(0));
        }

        Impl.decrypt(eaddress.unwrap(input1));
    }

    /// @notice Gets the decrypted value from a previously decrypted ebool ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The ebool ciphertext to get the decrypted value from
    /// @return The decrypted boolean value
    function getDecryptResult(ebool input1) internal view returns (bool) {
        uint256 result = Impl.getDecryptResult(ebool.unwrap(input1));
        return result != 0;
    }

    /// @notice Gets the decrypted value from a previously decrypted euint8 ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The euint8 ciphertext to get the decrypted value from
    /// @return The decrypted uint8 value
    function getDecryptResult(euint8 input1) internal view returns (uint8) {
        return uint8(Impl.getDecryptResult(euint8.unwrap(input1)));
    }

    /// @notice Gets the decrypted value from a previously decrypted euint16 ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The euint16 ciphertext to get the decrypted value from
    /// @return The decrypted uint16 value
    function getDecryptResult(euint16 input1) internal view returns (uint16) {
        return uint16(Impl.getDecryptResult(euint16.unwrap(input1)));
    }

    /// @notice Gets the decrypted value from a previously decrypted euint32 ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The euint32 ciphertext to get the decrypted value from
    /// @return The decrypted uint32 value
    function getDecryptResult(euint32 input1) internal view returns (uint32) {
        return uint32(Impl.getDecryptResult(euint32.unwrap(input1)));
    }

    /// @notice Gets the decrypted value from a previously decrypted euint64 ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The euint64 ciphertext to get the decrypted value from
    /// @return The decrypted uint64 value
    function getDecryptResult(euint64 input1) internal view returns (uint64) {
        return uint64(Impl.getDecryptResult(euint64.unwrap(input1)));
    }

    /// @notice Gets the decrypted value from a previously decrypted euint128 ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The euint128 ciphertext to get the decrypted value from
    /// @return The decrypted uint128 value
    function getDecryptResult(euint128 input1) internal view returns (uint128) {
        return uint128(Impl.getDecryptResult(euint128.unwrap(input1)));
    }

    /// @notice Gets the decrypted value from a previously decrypted euint256 ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The euint256 ciphertext to get the decrypted value from
    /// @return The decrypted uint256 value
    function getDecryptResult(euint256 input1) internal view returns (uint256) {
        return uint256(Impl.getDecryptResult(euint256.unwrap(input1)));
    }

    /// @notice Gets the decrypted value from a previously decrypted eaddress ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The eaddress ciphertext to get the decrypted value from
    /// @return The decrypted address value
    function getDecryptResult(eaddress input1) internal view returns (address) {
        return address(uint160(Impl.getDecryptResult(eaddress.unwrap(input1))));
    }

    /// @notice Gets the decrypted value from a previously decrypted raw ciphertext
    /// @dev This function will revert if the ciphertext is not yet decrypted. Use getDecryptResultSafe for a non-reverting version.
    /// @param input1 The raw ciphertext to get the decrypted value from
    /// @return The decrypted uint256 value
    function getDecryptResult(uint256 input1) internal view returns (uint256) {
        return Impl.getDecryptResult(input1);
    }

    /// @notice Safely gets the decrypted value from an ebool ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The ebool ciphertext to get the decrypted value from
    /// @return result The decrypted boolean value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(ebool input1) internal view returns (bool result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(ebool.unwrap(input1));
        return (_result != 0, _decrypted);
    }

    /// @notice Safely gets the decrypted value from a euint8 ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The euint8 ciphertext to get the decrypted value from
    /// @return result The decrypted uint8 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(euint8 input1) internal view returns (uint8 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(euint8.unwrap(input1));
        return (uint8(_result), _decrypted);
    }

    /// @notice Safely gets the decrypted value from a euint16 ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The euint16 ciphertext to get the decrypted value from
    /// @return result The decrypted uint16 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(euint16 input1) internal view returns (uint16 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(euint16.unwrap(input1));
        return (uint16(_result), _decrypted);
    }

    /// @notice Safely gets the decrypted value from a euint32 ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The euint32 ciphertext to get the decrypted value from
    /// @return result The decrypted uint32 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(euint32 input1) internal view returns (uint32 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(euint32.unwrap(input1));
        return (uint32(_result), _decrypted);
    }

    /// @notice Safely gets the decrypted value from a euint64 ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The euint64 ciphertext to get the decrypted value from
    /// @return result The decrypted uint64 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(euint64 input1) internal view returns (uint64 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(euint64.unwrap(input1));
        return (uint64(_result), _decrypted);
    }

    /// @notice Safely gets the decrypted value from a euint128 ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The euint128 ciphertext to get the decrypted value from
    /// @return result The decrypted uint128 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(euint128 input1) internal view returns (uint128 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(euint128.unwrap(input1));
        return (uint128(_result), _decrypted);
    }

    /// @notice Safely gets the decrypted value from a euint256 ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The euint256 ciphertext to get the decrypted value from
    /// @return result The decrypted uint256 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(euint256 input1) internal view returns (uint256 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(euint256.unwrap(input1));
        return (uint256(_result), _decrypted);
    }

    /// @notice Safely gets the decrypted value from an eaddress ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The eaddress ciphertext to get the decrypted value from
    /// @return result The decrypted address value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(eaddress input1) internal view returns (address result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(eaddress.unwrap(input1));
        return (address(uint160(_result)), _decrypted);
    }

    /// @notice Safely gets the decrypted value from a raw ciphertext
    /// @dev Returns the decrypted value and a flag indicating whether the decryption has finished
    /// @param input1 The raw ciphertext to get the decrypted value from
    /// @return result The decrypted uint256 value
    /// @return decrypted Flag indicating if the value was successfully decrypted
    function getDecryptResultSafe(uint256 input1) internal view returns (uint256 result, bool decrypted) {
        (uint256 _result, bool _decrypted) = Impl.getDecryptResultSafe(input1);
        return (_result, _decrypted);
    }

    /// @notice Performs a multiplexer operation between two ebool values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type ebool
    /// @param input3 Second choice of type ebool
    /// @return result of type ebool containing the selected value
    function select(ebool input1, ebool input2, ebool input3) internal returns (ebool) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEbool(false);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEbool(false);
        }

        return ebool.wrap(Impl.select(Utils.EBOOL_TFHE, input1, ebool.unwrap(input2), ebool.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two euint8 values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type euint8
    /// @param input3 Second choice of type euint8
    /// @return result of type euint8 containing the selected value
    function select(ebool input1, euint8 input2, euint8 input3) internal returns (euint8) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEuint8(0);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEuint8(0);
        }

        return euint8.wrap(Impl.select(Utils.EUINT8_TFHE, input1, euint8.unwrap(input2), euint8.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two euint16 values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type euint16
    /// @param input3 Second choice of type euint16
    /// @return result of type euint16 containing the selected value
    function select(ebool input1, euint16 input2, euint16 input3) internal returns (euint16) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEuint16(0);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEuint16(0);
        }

        return euint16.wrap(Impl.select(Utils.EUINT16_TFHE, input1, euint16.unwrap(input2), euint16.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two euint32 values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type euint32
    /// @param input3 Second choice of type euint32
    /// @return result of type euint32 containing the selected value
    function select(ebool input1, euint32 input2, euint32 input3) internal returns (euint32) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEuint32(0);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEuint32(0);
        }

        return euint32.wrap(Impl.select(Utils.EUINT32_TFHE, input1, euint32.unwrap(input2), euint32.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two euint64 values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type euint64
    /// @param input3 Second choice of type euint64
    /// @return result of type euint64 containing the selected value
    function select(ebool input1, euint64 input2, euint64 input3) internal returns (euint64) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEuint64(0);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEuint64(0);
        }

        return euint64.wrap(Impl.select(Utils.EUINT64_TFHE, input1, euint64.unwrap(input2), euint64.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two euint128 values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type euint128
    /// @param input3 Second choice of type euint128
    /// @return result of type euint128 containing the selected value
    function select(ebool input1, euint128 input2, euint128 input3) internal returns (euint128) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEuint128(0);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEuint128(0);
        }

        return euint128.wrap(Impl.select(Utils.EUINT128_TFHE, input1, euint128.unwrap(input2), euint128.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two euint256 values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type euint256
    /// @param input3 Second choice of type euint256
    /// @return result of type euint256 containing the selected value
    function select(ebool input1, euint256 input2, euint256 input3) internal returns (euint256) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEuint256(0);
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEuint256(0);
        }

        return euint256.wrap(Impl.select(Utils.EUINT256_TFHE, input1, euint256.unwrap(input2), euint256.unwrap(input3)));
    }

    /// @notice Performs a multiplexer operation between two eaddress values based on a selector
    /// @dev If input1 is true, returns input2, otherwise returns input3. All inputs are initialized to defaults if not set.
    /// @param input1 The selector of type ebool
    /// @param input2 First choice of type eaddress
    /// @param input3 Second choice of type eaddress
    /// @return result of type eaddress containing the selected value
    function select(ebool input1, eaddress input2, eaddress input3) internal returns (eaddress) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }
        if (!Common.isInitialized(input2)) {
            input2 = asEaddress(address(0));
        }
        if (!Common.isInitialized(input3)) {
            input3 = asEaddress(address(0));
        }

        return eaddress.wrap(Impl.select(Utils.EADDRESS_TFHE, input1, eaddress.unwrap(input2), eaddress.unwrap(input3)));
    }

    /// @notice Performs the not operation on a ciphertext
    /// @dev Verifies that the input value matches a valid ciphertext.
    /// @param input1 the input ciphertext
    function not(ebool input1) internal returns (ebool) {
        if (!Common.isInitialized(input1)) {
            input1 = asEbool(false);
        }

        return ebool.wrap(Impl.not(Utils.EBOOL_TFHE, ebool.unwrap(input1)));
    }

    /// @notice Performs the not operation on a ciphertext
    /// @dev Verifies that the input value matches a valid ciphertext.
    /// @param input1 the input ciphertext
    function not(euint8 input1) internal returns (euint8) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint8(0);
        }

        return euint8.wrap(Impl.not(Utils.EUINT8_TFHE, euint8.unwrap(input1)));
    }
    /// @notice Performs the not operation on a ciphertext
    /// @dev Verifies that the input value matches a valid ciphertext.
    /// @param input1 the input ciphertext
    function not(euint16 input1) internal returns (euint16) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint16(0);
        }

        return euint16.wrap(Impl.not(Utils.EUINT16_TFHE, euint16.unwrap(input1)));
    }
    /// @notice Performs the not operation on a ciphertext
    /// @dev Verifies that the input value matches a valid ciphertext.
    /// @param input1 the input ciphertext
    function not(euint32 input1) internal returns (euint32) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint32(0);
        }

        return euint32.wrap(Impl.not(Utils.EUINT32_TFHE, euint32.unwrap(input1)));
    }

    /// @notice Performs the bitwise NOT operation on an encrypted 64-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      The operation inverts all bits of the input value.
    /// @param input1 The input ciphertext to negate
    /// @return An euint64 containing the bitwise NOT of the input
    function not(euint64 input1) internal returns (euint64) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint64(0);
        }

        return euint64.wrap(Impl.not(Utils.EUINT64_TFHE, euint64.unwrap(input1)));
    }

    /// @notice Performs the bitwise NOT operation on an encrypted 128-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      The operation inverts all bits of the input value.
    /// @param input1 The input ciphertext to negate
    /// @return An euint128 containing the bitwise NOT of the input
    function not(euint128 input1) internal returns (euint128) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint128(0);
        }

        return euint128.wrap(Impl.not(Utils.EUINT128_TFHE, euint128.unwrap(input1)));
    }

    /// @notice Performs the bitwise NOT operation on an encrypted 256-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      The operation inverts all bits of the input value.
    /// @param input1 The input ciphertext to negate
    /// @return An euint256 containing the bitwise NOT of the input
    function not(euint256 input1) internal returns (euint256) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint256(0);
        }

        return euint256.wrap(Impl.not(Utils.EUINT256_TFHE, euint256.unwrap(input1)));
    }

    /// @notice Performs the square operation on an encrypted 8-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      Note: The result may overflow if input * input exceeds 8 bits.
    /// @param input1 The input ciphertext to square
    /// @return An euint8 containing the square of the input
    function square(euint8 input1) internal returns (euint8) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint8(0);
        }

        return euint8.wrap(Impl.square(Utils.EUINT8_TFHE, euint8.unwrap(input1)));
    }

    /// @notice Performs the square operation on an encrypted 16-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      Note: The result may overflow if input * input exceeds 16 bits.
    /// @param input1 The input ciphertext to square
    /// @return An euint16 containing the square of the input
    function square(euint16 input1) internal returns (euint16) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint16(0);
        }

        return euint16.wrap(Impl.square(Utils.EUINT16_TFHE, euint16.unwrap(input1)));
    }

    /// @notice Performs the square operation on an encrypted 32-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      Note: The result may overflow if input * input exceeds 32 bits.
    /// @param input1 The input ciphertext to square
    /// @return An euint32 containing the square of the input
    function square(euint32 input1) internal returns (euint32) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint32(0);
        }

        return euint32.wrap(Impl.square(Utils.EUINT32_TFHE, euint32.unwrap(input1)));
    }

    /// @notice Performs the square operation on an encrypted 64-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      Note: The result may overflow if input * input exceeds 64 bits.
    /// @param input1 The input ciphertext to square
    /// @return An euint64 containing the square of the input
    function square(euint64 input1) internal returns (euint64) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint64(0);
        }

        return euint64.wrap(Impl.square(Utils.EUINT64_TFHE, euint64.unwrap(input1)));
    }

    /// @notice Performs the square operation on an encrypted 128-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      Note: The result may overflow if input * input exceeds 128 bits.
    /// @param input1 The input ciphertext to square
    /// @return An euint128 containing the square of the input
    function square(euint128 input1) internal returns (euint128) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint128(0);
        }

        return euint128.wrap(Impl.square(Utils.EUINT128_TFHE, euint128.unwrap(input1)));
    }

    /// @notice Performs the square operation on an encrypted 256-bit unsigned integer
    /// @dev Verifies that the input is initialized, defaulting to 0 if not.
    ///      Note: The result may overflow if input * input exceeds 256 bits.
    /// @param input1 The input ciphertext to square
    /// @return An euint256 containing the square of the input
    function square(euint256 input1) internal returns (euint256) {
        if (!Common.isInitialized(input1)) {
            input1 = asEuint256(0);
        }

        return euint256.wrap(Impl.square(Utils.EUINT256_TFHE, euint256.unwrap(input1)));
    }
    /// @notice Generates a random value of a euint8 type for provided securityZone
    /// @dev Generates a cryptographically secure random 8-bit unsigned integer in encrypted form.
    ///      The generated value is fully encrypted and cannot be predicted by any party.
    /// @param securityZone The security zone identifier to use for random value generation.
    /// @return A randomly generated encrypted 8-bit unsigned integer (euint8)
    function randomEuint8(int32 securityZone) internal returns (euint8) {
        return euint8.wrap(Impl.random(Utils.EUINT8_TFHE, 0, securityZone));
    }
    /// @notice Generates a random value of a euint8 type
    /// @dev Generates a cryptographically secure random 8-bit unsigned integer in encrypted form
    ///      using the default security zone (0). The generated value is fully encrypted and
    ///      cannot be predicted by any party.
    /// @return A randomly generated encrypted 8-bit unsigned integer (euint8)
    function randomEuint8() internal returns (euint8) {
        return randomEuint8(0);
    }
    /// @notice Generates a random value of a euint16 type for provided securityZone
    /// @dev Generates a cryptographically secure random 16-bit unsigned integer in encrypted form.
    ///      The generated value is fully encrypted and cannot be predicted by any party.
    /// @param securityZone The security zone identifier to use for random value generation.
    /// @return A randomly generated encrypted 16-bit unsigned integer (euint16)
    function randomEuint16(int32 securityZone) internal returns (euint16) {
        return euint16.wrap(Impl.random(Utils.EUINT16_TFHE, 0, securityZone));
    }
    /// @notice Generates a random value of a euint16 type
    /// @dev Generates a cryptographically secure random 16-bit unsigned integer in encrypted form
    ///      using the default security zone (0). The generated value is fully encrypted and
    ///      cannot be predicted by any party.
    /// @return A randomly generated encrypted 16-bit unsigned integer (euint16)
    function randomEuint16() internal returns (euint16) {
        return randomEuint16(0);
    }
    /// @notice Generates a random value of a euint32 type for provided securityZone
    /// @dev Generates a cryptographically secure random 32-bit unsigned integer in encrypted form.
    ///      The generated value is fully encrypted and cannot be predicted by any party.
    /// @param securityZone The security zone identifier to use for random value generation.
    /// @return A randomly generated encrypted 32-bit unsigned integer (euint32)
    function randomEuint32(int32 securityZone) internal returns (euint32) {
        return euint32.wrap(Impl.random(Utils.EUINT32_TFHE, 0, securityZone));
    }
    /// @notice Generates a random value of a euint32 type
    /// @dev Generates a cryptographically secure random 32-bit unsigned integer in encrypted form
    ///      using the default security zone (0). The generated value is fully encrypted and
    ///      cannot be predicted by any party.
    /// @return A randomly generated encrypted 32-bit unsigned integer (euint32)
    function randomEuint32() internal returns (euint32) {
        return randomEuint32(0);
    }
    /// @notice Generates a random value of a euint64 type for provided securityZone
    /// @dev Generates a cryptographically secure random 64-bit unsigned integer in encrypted form.
    ///      The generated value is fully encrypted and cannot be predicted by any party.
    /// @param securityZone The security zone identifier to use for random value generation.
    /// @return A randomly generated encrypted 64-bit unsigned integer (euint64)
    function randomEuint64(int32 securityZone) internal returns (euint64) {
        return euint64.wrap(Impl.random(Utils.EUINT64_TFHE, 0, securityZone));
    }
    /// @notice Generates a random value of a euint64 type
    /// @dev Generates a cryptographically secure random 64-bit unsigned integer in encrypted form
    ///      using the default security zone (0). The generated value is fully encrypted and
    ///      cannot be predicted by any party.
    /// @return A randomly generated encrypted 64-bit unsigned integer (euint64)
    function randomEuint64() internal returns (euint64) {
        return randomEuint64(0);
    }
    /// @notice Generates a random value of a euint128 type for provided securityZone
    /// @dev Generates a cryptographically secure random 128-bit unsigned integer in encrypted form.
    ///      The generated value is fully encrypted and cannot be predicted by any party.
    /// @param securityZone The security zone identifier to use for random value generation.
    /// @return A randomly generated encrypted 128-bit unsigned integer (euint128)
    function randomEuint128(int32 securityZone) internal returns (euint128) {
        return euint128.wrap(Impl.random(Utils.EUINT128_TFHE, 0, securityZone));
    }
    /// @notice Generates a random value of a euint128 type
    /// @dev Generates a cryptographically secure random 128-bit unsigned integer in encrypted form
    ///      using the default security zone (0). The generated value is fully encrypted and
    ///      cannot be predicted by any party.
    /// @return A randomly generated encrypted 128-bit unsigned integer (euint128)
    function randomEuint128() internal returns (euint128) {
        return randomEuint128(0);
    }
    /// @notice Generates a random value of a euint256 type for provided securityZone
    /// @dev Generates a cryptographically secure random 256-bit unsigned integer in encrypted form.
    ///      The generated value is fully encrypted and cannot be predicted by any party.
    /// @param securityZone The security zone identifier to use for random value generation.
    /// @return A randomly generated encrypted 256-bit unsigned integer (euint256)
    function randomEuint256(int32 securityZone) internal returns (euint256) {
        return euint256.wrap(Impl.random(Utils.EUINT256_TFHE, 0, securityZone));
    }
    /// @notice Generates a random value of a euint256 type
    /// @dev Generates a cryptographically secure random 256-bit unsigned integer in encrypted form
    ///      using the default security zone (0). The generated value is fully encrypted and
    ///      cannot be predicted by any party.
    /// @return A randomly generated encrypted 256-bit unsigned integer (euint256)
    function randomEuint256() internal returns (euint256) {
        return randomEuint256(0);
    }

    /// @notice Verifies and converts an inEbool input to an ebool encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An ebool containing the verified encrypted value
    function asEbool(InEbool memory value) internal returns (ebool) {
        uint8 expectedUtype = Utils.EBOOL_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }

        return ebool.wrap(Impl.verifyInput(Utils.inputFromEbool(value)));
    }

    /// @notice Verifies and converts an InEuint8 input to an euint8 encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An euint8 containing the verified encrypted value
    function asEuint8(InEuint8 memory value) internal returns (euint8) {
        uint8 expectedUtype = Utils.EUINT8_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }

        return euint8.wrap(Impl.verifyInput(Utils.inputFromEuint8(value)));
    }

    /// @notice Verifies and converts an InEuint16 input to an euint16 encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An euint16 containing the verified encrypted value
    function asEuint16(InEuint16 memory value) internal returns (euint16) {
        uint8 expectedUtype = Utils.EUINT16_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }

        return euint16.wrap(Impl.verifyInput(Utils.inputFromEuint16(value)));
    }

    /// @notice Verifies and converts an InEuint32 input to an euint32 encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An euint32 containing the verified encrypted value
    function asEuint32(InEuint32 memory value) internal returns (euint32) {
        uint8 expectedUtype = Utils.EUINT32_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }

        return euint32.wrap(Impl.verifyInput(Utils.inputFromEuint32(value)));
    }

    /// @notice Verifies and converts an InEuint64 input to an euint64 encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An euint64 containing the verified encrypted value
    function asEuint64(InEuint64 memory value) internal returns (euint64) {
        uint8 expectedUtype = Utils.EUINT64_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }

        return euint64.wrap(Impl.verifyInput(Utils.inputFromEuint64(value)));
    }

    /// @notice Verifies and converts an InEuint128 input to an euint128 encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An euint128 containing the verified encrypted value
    function asEuint128(InEuint128 memory value) internal returns (euint128) {
        uint8 expectedUtype = Utils.EUINT128_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }

        return euint128.wrap(Impl.verifyInput(Utils.inputFromEuint128(value)));
    }

    /// @notice Verifies and converts an InEuint256 input to an euint256 encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An euint256 containing the verified encrypted value
    function asEuint256(InEuint256 memory value) internal returns (euint256) {
        uint8 expectedUtype = Utils.EUINT256_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }

        return euint256.wrap(Impl.verifyInput(Utils.inputFromEuint256(value)));
    }

    /// @notice Verifies and converts an InEaddress input to an eaddress encrypted type
    /// @dev Verifies the input signature and security parameters before converting to the encrypted type
    /// @param value The input value containing hash, type, security zone and signature
    /// @return An eaddress containing the verified encrypted value
    function asEaddress(InEaddress memory value) internal returns (eaddress) {
        uint8 expectedUtype = Utils.EADDRESS_TFHE;
        if (value.utype != expectedUtype) {
            revert InvalidEncryptedInput(value.utype, expectedUtype);
        }

        return eaddress.wrap(Impl.verifyInput(Utils.inputFromEaddress(value)));
    }

    // ********** TYPE CASTING ************* //
    /// @notice Converts a ebool to an euint8
    function asEuint8(ebool value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(ebool.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a ebool to an euint16
    function asEuint16(ebool value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(ebool.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a ebool to an euint32
    function asEuint32(ebool value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(ebool.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a ebool to an euint64
    function asEuint64(ebool value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(ebool.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a ebool to an euint128
    function asEuint128(ebool value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(ebool.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a ebool to an euint256
    function asEuint256(ebool value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(ebool.unwrap(value), Utils.EUINT256_TFHE));
    }

    /// @notice Converts a euint8 to an ebool
    function asEbool(euint8 value) internal returns (ebool) {
        return ne(value, asEuint8(0));
    }
    /// @notice Converts a euint8 to an euint16
    function asEuint16(euint8 value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(euint8.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a euint8 to an euint32
    function asEuint32(euint8 value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(euint8.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a euint8 to an euint64
    function asEuint64(euint8 value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(euint8.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a euint8 to an euint128
    function asEuint128(euint8 value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(euint8.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a euint8 to an euint256
    function asEuint256(euint8 value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(euint8.unwrap(value), Utils.EUINT256_TFHE));
    }

    /// @notice Converts a euint16 to an ebool
    function asEbool(euint16 value) internal returns (ebool) {
        return ne(value, asEuint16(0));
    }
    /// @notice Converts a euint16 to an euint8
    function asEuint8(euint16 value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(euint16.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a euint16 to an euint32
    function asEuint32(euint16 value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(euint16.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a euint16 to an euint64
    function asEuint64(euint16 value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(euint16.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a euint16 to an euint128
    function asEuint128(euint16 value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(euint16.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a euint16 to an euint256
    function asEuint256(euint16 value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(euint16.unwrap(value), Utils.EUINT256_TFHE));
    }

    /// @notice Converts a euint32 to an ebool
    function asEbool(euint32 value) internal returns (ebool) {
        return ne(value, asEuint32(0));
    }
    /// @notice Converts a euint32 to an euint8
    function asEuint8(euint32 value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(euint32.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a euint32 to an euint16
    function asEuint16(euint32 value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(euint32.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a euint32 to an euint64
    function asEuint64(euint32 value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(euint32.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a euint32 to an euint128
    function asEuint128(euint32 value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(euint32.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a euint32 to an euint256
    function asEuint256(euint32 value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(euint32.unwrap(value), Utils.EUINT256_TFHE));
    }

    /// @notice Converts a euint64 to an ebool
    function asEbool(euint64 value) internal returns (ebool) {
        return ne(value, asEuint64(0));
    }
    /// @notice Converts a euint64 to an euint8
    function asEuint8(euint64 value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(euint64.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a euint64 to an euint16
    function asEuint16(euint64 value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(euint64.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a euint64 to an euint32
    function asEuint32(euint64 value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(euint64.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a euint64 to an euint128
    function asEuint128(euint64 value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(euint64.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a euint64 to an euint256
    function asEuint256(euint64 value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(euint64.unwrap(value), Utils.EUINT256_TFHE));
    }

    /// @notice Converts a euint128 to an ebool
    function asEbool(euint128 value) internal returns (ebool) {
        return ne(value, asEuint128(0));
    }
    /// @notice Converts a euint128 to an euint8
    function asEuint8(euint128 value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(euint128.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a euint128 to an euint16
    function asEuint16(euint128 value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(euint128.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a euint128 to an euint32
    function asEuint32(euint128 value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(euint128.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a euint128 to an euint64
    function asEuint64(euint128 value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(euint128.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a euint128 to an euint256
    function asEuint256(euint128 value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(euint128.unwrap(value), Utils.EUINT256_TFHE));
    }

    /// @notice Converts a euint256 to an ebool
    function asEbool(euint256 value) internal returns (ebool) {
        return ne(value, asEuint256(0));
    }
    /// @notice Converts a euint256 to an euint8
    function asEuint8(euint256 value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(euint256.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a euint256 to an euint16
    function asEuint16(euint256 value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(euint256.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a euint256 to an euint32
    function asEuint32(euint256 value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(euint256.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a euint256 to an euint64
    function asEuint64(euint256 value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(euint256.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a euint256 to an euint128
    function asEuint128(euint256 value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(euint256.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a euint256 to an eaddress
    function asEaddress(euint256 value) internal returns (eaddress) {
        return eaddress.wrap(Impl.cast(euint256.unwrap(value), Utils.EADDRESS_TFHE));
    }

    /// @notice Converts a eaddress to an ebool
    function asEbool(eaddress value) internal returns (ebool) {
        return ne(value, asEaddress(address(0)));
    }
    /// @notice Converts a eaddress to an euint8
    function asEuint8(eaddress value) internal returns (euint8) {
        return euint8.wrap(Impl.cast(eaddress.unwrap(value), Utils.EUINT8_TFHE));
    }
    /// @notice Converts a eaddress to an euint16
    function asEuint16(eaddress value) internal returns (euint16) {
        return euint16.wrap(Impl.cast(eaddress.unwrap(value), Utils.EUINT16_TFHE));
    }
    /// @notice Converts a eaddress to an euint32
    function asEuint32(eaddress value) internal returns (euint32) {
        return euint32.wrap(Impl.cast(eaddress.unwrap(value), Utils.EUINT32_TFHE));
    }
    /// @notice Converts a eaddress to an euint64
    function asEuint64(eaddress value) internal returns (euint64) {
        return euint64.wrap(Impl.cast(eaddress.unwrap(value), Utils.EUINT64_TFHE));
    }
    /// @notice Converts a eaddress to an euint128
    function asEuint128(eaddress value) internal returns (euint128) {
        return euint128.wrap(Impl.cast(eaddress.unwrap(value), Utils.EUINT128_TFHE));
    }
    /// @notice Converts a eaddress to an euint256
    function asEuint256(eaddress value) internal returns (euint256) {
        return euint256.wrap(Impl.cast(eaddress.unwrap(value), Utils.EUINT256_TFHE));
    }
    /// @notice Converts a plaintext boolean value to a ciphertext ebool
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    /// @return A ciphertext representation of the input
    function asEbool(bool value) internal returns (ebool) {
        return asEbool(value, 0);
    }
    /// @notice Converts a plaintext boolean value to a ciphertext ebool, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    /// @return A ciphertext representation of the input
    function asEbool(bool value, int32 securityZone) internal returns (ebool) {
        uint256 sVal = 0;
        if (value) {
            sVal = 1;
        }
        uint256 ct = Impl.trivialEncrypt(sVal, Utils.EBOOL_TFHE, securityZone);
        return ebool.wrap(ct);
    }
    /// @notice Converts a uint256 to an euint8
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint8(uint256 value) internal returns (euint8) {
        return asEuint8(value, 0);
    }
    /// @notice Converts a uint256 to an euint8, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint8(uint256 value, int32 securityZone) internal returns (euint8) {
        uint256 ct = Impl.trivialEncrypt(value, Utils.EUINT8_TFHE, securityZone);
        return euint8.wrap(ct);
    }
    /// @notice Converts a uint256 to an euint16
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint16(uint256 value) internal returns (euint16) {
        return asEuint16(value, 0);
    }
    /// @notice Converts a uint256 to an euint16, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint16(uint256 value, int32 securityZone) internal returns (euint16) {
        uint256 ct = Impl.trivialEncrypt(value, Utils.EUINT16_TFHE, securityZone);
        return euint16.wrap(ct);
    }
    /// @notice Converts a uint256 to an euint32
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint32(uint256 value) internal returns (euint32) {
        return asEuint32(value, 0);
    }
    /// @notice Converts a uint256 to an euint32, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint32(uint256 value, int32 securityZone) internal returns (euint32) {
        uint256 ct = Impl.trivialEncrypt(value, Utils.EUINT32_TFHE, securityZone);
        return euint32.wrap(ct);
    }
    /// @notice Converts a uint256 to an euint64
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint64(uint256 value) internal returns (euint64) {
        return asEuint64(value, 0);
    }
    /// @notice Converts a uint256 to an euint64, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint64(uint256 value, int32 securityZone) internal returns (euint64) {
        uint256 ct = Impl.trivialEncrypt(value, Utils.EUINT64_TFHE, securityZone);
        return euint64.wrap(ct);
    }
    /// @notice Converts a uint256 to an euint128
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint128(uint256 value) internal returns (euint128) {
        return asEuint128(value, 0);
    }
    /// @notice Converts a uint256 to an euint128, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint128(uint256 value, int32 securityZone) internal returns (euint128) {
        uint256 ct = Impl.trivialEncrypt(value, Utils.EUINT128_TFHE, securityZone);
        return euint128.wrap(ct);
    }
    /// @notice Converts a uint256 to an euint256
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint256(uint256 value) internal returns (euint256) {
        return asEuint256(value, 0);
    }
    /// @notice Converts a uint256 to an euint256, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    function asEuint256(uint256 value, int32 securityZone) internal returns (euint256) {
        uint256 ct = Impl.trivialEncrypt(value, Utils.EUINT256_TFHE, securityZone);
        return euint256.wrap(ct);
    }
    /// @notice Converts a address to an eaddress
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    /// Allows for a better user experience when working with eaddresses
    function asEaddress(address value) internal returns (eaddress) {
        return asEaddress(value, 0);
    }
    /// @notice Converts a address to an eaddress, specifying security zone
    /// @dev Privacy: The input value is public, therefore the resulting ciphertext should be considered public until involved in an fhe operation
    /// Allows for a better user experience when working with eaddresses
    function asEaddress(address value, int32 securityZone) internal returns (eaddress) {
        uint256 ct = Impl.trivialEncrypt(uint256(uint160(value)), Utils.EADDRESS_TFHE, securityZone);
        return eaddress.wrap(ct);
    }

    /// @notice Grants permission to an account to operate on the encrypted boolean value
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted boolean value to grant access to
    /// @param account The address being granted permission
    function allow(ebool ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(ebool.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted 8-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted uint8 value to grant access to
    /// @param account The address being granted permission
    function allow(euint8 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint8.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted 16-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted uint16 value to grant access to
    /// @param account The address being granted permission
    function allow(euint16 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint16.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted 32-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted uint32 value to grant access to
    /// @param account The address being granted permission
    function allow(euint32 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint32.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted 64-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted uint64 value to grant access to
    /// @param account The address being granted permission
    function allow(euint64 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint64.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted 128-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted uint128 value to grant access to
    /// @param account The address being granted permission
    function allow(euint128 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint128.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted 256-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted uint256 value to grant access to
    /// @param account The address being granted permission
    function allow(euint256 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint256.unwrap(ctHash), account);
    }

    /// @notice Grants permission to an account to operate on the encrypted address
    /// @dev Allows the specified account to access the ciphertext
    /// @param ctHash The encrypted address value to grant access to
    /// @param account The address being granted permission
    function allow(eaddress ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(eaddress.unwrap(ctHash), account);
    }

    /// @notice Grants global permission to operate on the encrypted boolean value
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted boolean value to grant global access to
    function allowGlobal(ebool ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(ebool.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted 8-bit unsigned integer
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted uint8 value to grant global access to
    function allowGlobal(euint8 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(euint8.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted 16-bit unsigned integer
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted uint16 value to grant global access to
    function allowGlobal(euint16 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(euint16.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted 32-bit unsigned integer
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted uint32 value to grant global access to
    function allowGlobal(euint32 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(euint32.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted 64-bit unsigned integer
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted uint64 value to grant global access to
    function allowGlobal(euint64 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(euint64.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted 128-bit unsigned integer
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted uint128 value to grant global access to
    function allowGlobal(euint128 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(euint128.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted 256-bit unsigned integer
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted uint256 value to grant global access to
    function allowGlobal(euint256 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(euint256.unwrap(ctHash));
    }

    /// @notice Grants global permission to operate on the encrypted address
    /// @dev Allows all accounts to access the ciphertext
    /// @param ctHash The encrypted address value to grant global access to
    function allowGlobal(eaddress ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowGlobal(eaddress.unwrap(ctHash));
    }

    /// @notice Checks if an account has permission to operate on the encrypted boolean value
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted boolean value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(ebool ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(ebool.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted 8-bit unsigned integer
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted uint8 value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(euint8 ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(euint8.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted 16-bit unsigned integer
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted uint16 value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(euint16 ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(euint16.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted 32-bit unsigned integer
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted uint32 value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(euint32 ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(euint32.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted 64-bit unsigned integer
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted uint64 value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(euint64 ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(euint64.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted 128-bit unsigned integer
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted uint128 value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(euint128 ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(euint128.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted 256-bit unsigned integer
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted uint256 value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(euint256 ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(euint256.unwrap(ctHash), account);
    }

    /// @notice Checks if an account has permission to operate on the encrypted address
    /// @dev Returns whether the specified account can access the ciphertext
    /// @param ctHash The encrypted address value to check access for
    /// @param account The address to check permissions for
    /// @return True if the account has permission, false otherwise
    function isAllowed(eaddress ctHash, address account) internal returns (bool) {
        return ITaskManager(TASK_MANAGER_ADDRESS).isAllowed(eaddress.unwrap(ctHash), account);
    }

    /// @notice Grants permission to the current contract to operate on the encrypted boolean value
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted boolean value to grant access to
    function allowThis(ebool ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(ebool.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted 8-bit unsigned integer
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted uint8 value to grant access to
    function allowThis(euint8 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint8.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted 16-bit unsigned integer
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted uint16 value to grant access to
    function allowThis(euint16 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint16.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted 32-bit unsigned integer
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted uint32 value to grant access to
    function allowThis(euint32 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint32.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted 64-bit unsigned integer
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted uint64 value to grant access to
    function allowThis(euint64 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint64.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted 128-bit unsigned integer
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted uint128 value to grant access to
    function allowThis(euint128 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint128.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted 256-bit unsigned integer
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted uint256 value to grant access to
    function allowThis(euint256 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint256.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the current contract to operate on the encrypted address
    /// @dev Allows this contract to access the ciphertext
    /// @param ctHash The encrypted address value to grant access to
    function allowThis(eaddress ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(eaddress.unwrap(ctHash), address(this));
    }

    /// @notice Grants permission to the message sender to operate on the encrypted boolean value
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted boolean value to grant access to
    function allowSender(ebool ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(ebool.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted 8-bit unsigned integer
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted uint8 value to grant access to
    function allowSender(euint8 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint8.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted 16-bit unsigned integer
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted uint16 value to grant access to
    function allowSender(euint16 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint16.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted 32-bit unsigned integer
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted uint32 value to grant access to
    function allowSender(euint32 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint32.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted 64-bit unsigned integer
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted uint64 value to grant access to
    function allowSender(euint64 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint64.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted 128-bit unsigned integer
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted uint128 value to grant access to
    function allowSender(euint128 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint128.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted 256-bit unsigned integer
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted uint256 value to grant access to
    function allowSender(euint256 ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(euint256.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants permission to the message sender to operate on the encrypted address
    /// @dev Allows the transaction sender to access the ciphertext
    /// @param ctHash The encrypted address value to grant access to
    function allowSender(eaddress ctHash) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allow(eaddress.unwrap(ctHash), msg.sender);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted boolean value
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted boolean value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(ebool ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(ebool.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted 8-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted uint8 value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(euint8 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(euint8.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted 16-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted uint16 value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(euint16 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(euint16.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted 32-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted uint32 value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(euint32 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(euint32.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted 64-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted uint64 value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(euint64 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(euint64.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted 128-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted uint128 value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(euint128 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(euint128.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted 256-bit unsigned integer
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted uint256 value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(euint256 ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(euint256.unwrap(ctHash), account);
    }

    /// @notice Grants temporary permission to an account to operate on the encrypted address
    /// @dev Allows the specified account to access the ciphertext for the current transaction only
    /// @param ctHash The encrypted address value to grant temporary access to
    /// @param account The address being granted temporary permission
    function allowTransient(eaddress ctHash, address account) internal {
        ITaskManager(TASK_MANAGER_ADDRESS).allowTransient(eaddress.unwrap(ctHash), account);
    }

}
// ********** BINDING DEFS ************* //

using BindingsEbool for ebool global;
library BindingsEbool {

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return the result of the eq
    function eq(ebool lhs, ebool rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return the result of the ne
    function ne(ebool lhs, ebool rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }

    /// @notice Performs the not operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type ebool
    /// @return the result of the not
    function not(ebool lhs) internal returns (ebool) {
        return FHE.not(lhs);
    }

    /// @notice Performs the and operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return the result of the and
    function and(ebool lhs, ebool rhs) internal returns (ebool) {
        return FHE.and(lhs, rhs);
    }

    /// @notice Performs the or operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return the result of the or
    function or(ebool lhs, ebool rhs) internal returns (ebool) {
        return FHE.or(lhs, rhs);
    }

    /// @notice Performs the xor operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type ebool
    /// @param rhs second input of type ebool
    /// @return the result of the xor
    function xor(ebool lhs, ebool rhs) internal returns (ebool) {
        return FHE.xor(lhs, rhs);
    }
    function toU8(ebool value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU16(ebool value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU32(ebool value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU64(ebool value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU128(ebool value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toU256(ebool value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(ebool value) internal {
        FHE.decrypt(value);
    }
    function allow(ebool ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(ebool ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(ebool ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(ebool ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(ebool ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(ebool ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEuint8 for euint8 global;
library BindingsEuint8 {

    /// @notice Performs the add operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the add
    function add(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.add(lhs, rhs);
    }

    /// @notice Performs the mul operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the mul
    function mul(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.mul(lhs, rhs);
    }

    /// @notice Performs the div operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the div
    function div(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.div(lhs, rhs);
    }

    /// @notice Performs the sub operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the sub
    function sub(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.sub(lhs, rhs);
    }

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the eq
    function eq(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the ne
    function ne(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }

    /// @notice Performs the not operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @return the result of the not
    function not(euint8 lhs) internal returns (euint8) {
        return FHE.not(lhs);
    }

    /// @notice Performs the and operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the and
    function and(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.and(lhs, rhs);
    }

    /// @notice Performs the or operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the or
    function or(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.or(lhs, rhs);
    }

    /// @notice Performs the xor operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the xor
    function xor(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.xor(lhs, rhs);
    }

    /// @notice Performs the gt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the gt
    function gt(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return FHE.gt(lhs, rhs);
    }

    /// @notice Performs the gte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the gte
    function gte(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return FHE.gte(lhs, rhs);
    }

    /// @notice Performs the lt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the lt
    function lt(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return FHE.lt(lhs, rhs);
    }

    /// @notice Performs the lte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the lte
    function lte(euint8 lhs, euint8 rhs) internal returns (ebool) {
        return FHE.lte(lhs, rhs);
    }

    /// @notice Performs the rem operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the rem
    function rem(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.rem(lhs, rhs);
    }

    /// @notice Performs the max operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the max
    function max(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.max(lhs, rhs);
    }

    /// @notice Performs the min operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the min
    function min(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.min(lhs, rhs);
    }

    /// @notice Performs the shl operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the shl
    function shl(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.shl(lhs, rhs);
    }

    /// @notice Performs the shr operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the shr
    function shr(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.shr(lhs, rhs);
    }

    /// @notice Performs the rol operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the rol
    function rol(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.rol(lhs, rhs);
    }

    /// @notice Performs the ror operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @param rhs second input of type euint8
    /// @return the result of the ror
    function ror(euint8 lhs, euint8 rhs) internal returns (euint8) {
        return FHE.ror(lhs, rhs);
    }

    /// @notice Performs the square operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint8
    /// @return the result of the square
    function square(euint8 lhs) internal returns (euint8) {
        return FHE.square(lhs);
    }
    function toBool(euint8 value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU16(euint8 value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU32(euint8 value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU64(euint8 value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU128(euint8 value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toU256(euint8 value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(euint8 value) internal {
        FHE.decrypt(value);
    }
    function allow(euint8 ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(euint8 ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(euint8 ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(euint8 ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(euint8 ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(euint8 ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEuint16 for euint16 global;
library BindingsEuint16 {

    /// @notice Performs the add operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the add
    function add(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.add(lhs, rhs);
    }

    /// @notice Performs the mul operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the mul
    function mul(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.mul(lhs, rhs);
    }

    /// @notice Performs the div operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the div
    function div(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.div(lhs, rhs);
    }

    /// @notice Performs the sub operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the sub
    function sub(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.sub(lhs, rhs);
    }

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the eq
    function eq(euint16 lhs, euint16 rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the ne
    function ne(euint16 lhs, euint16 rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }

    /// @notice Performs the not operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @return the result of the not
    function not(euint16 lhs) internal returns (euint16) {
        return FHE.not(lhs);
    }

    /// @notice Performs the and operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the and
    function and(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.and(lhs, rhs);
    }

    /// @notice Performs the or operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the or
    function or(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.or(lhs, rhs);
    }

    /// @notice Performs the xor operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the xor
    function xor(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.xor(lhs, rhs);
    }

    /// @notice Performs the gt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the gt
    function gt(euint16 lhs, euint16 rhs) internal returns (ebool) {
        return FHE.gt(lhs, rhs);
    }

    /// @notice Performs the gte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the gte
    function gte(euint16 lhs, euint16 rhs) internal returns (ebool) {
        return FHE.gte(lhs, rhs);
    }

    /// @notice Performs the lt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the lt
    function lt(euint16 lhs, euint16 rhs) internal returns (ebool) {
        return FHE.lt(lhs, rhs);
    }

    /// @notice Performs the lte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the lte
    function lte(euint16 lhs, euint16 rhs) internal returns (ebool) {
        return FHE.lte(lhs, rhs);
    }

    /// @notice Performs the rem operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the rem
    function rem(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.rem(lhs, rhs);
    }

    /// @notice Performs the max operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the max
    function max(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.max(lhs, rhs);
    }

    /// @notice Performs the min operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the min
    function min(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.min(lhs, rhs);
    }

    /// @notice Performs the shl operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the shl
    function shl(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.shl(lhs, rhs);
    }

    /// @notice Performs the shr operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the shr
    function shr(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.shr(lhs, rhs);
    }

    /// @notice Performs the rol operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the rol
    function rol(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.rol(lhs, rhs);
    }

    /// @notice Performs the ror operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @param rhs second input of type euint16
    /// @return the result of the ror
    function ror(euint16 lhs, euint16 rhs) internal returns (euint16) {
        return FHE.ror(lhs, rhs);
    }

    /// @notice Performs the square operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint16
    /// @return the result of the square
    function square(euint16 lhs) internal returns (euint16) {
        return FHE.square(lhs);
    }
    function toBool(euint16 value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU8(euint16 value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU32(euint16 value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU64(euint16 value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU128(euint16 value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toU256(euint16 value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(euint16 value) internal {
        FHE.decrypt(value);
    }
    function allow(euint16 ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(euint16 ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(euint16 ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(euint16 ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(euint16 ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(euint16 ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEuint32 for euint32 global;
library BindingsEuint32 {

    /// @notice Performs the add operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the add
    function add(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.add(lhs, rhs);
    }

    /// @notice Performs the mul operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the mul
    function mul(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.mul(lhs, rhs);
    }

    /// @notice Performs the div operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the div
    function div(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.div(lhs, rhs);
    }

    /// @notice Performs the sub operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the sub
    function sub(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.sub(lhs, rhs);
    }

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the eq
    function eq(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the ne
    function ne(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }

    /// @notice Performs the not operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @return the result of the not
    function not(euint32 lhs) internal returns (euint32) {
        return FHE.not(lhs);
    }

    /// @notice Performs the and operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the and
    function and(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.and(lhs, rhs);
    }

    /// @notice Performs the or operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the or
    function or(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.or(lhs, rhs);
    }

    /// @notice Performs the xor operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the xor
    function xor(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.xor(lhs, rhs);
    }

    /// @notice Performs the gt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the gt
    function gt(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return FHE.gt(lhs, rhs);
    }

    /// @notice Performs the gte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the gte
    function gte(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return FHE.gte(lhs, rhs);
    }

    /// @notice Performs the lt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the lt
    function lt(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return FHE.lt(lhs, rhs);
    }

    /// @notice Performs the lte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the lte
    function lte(euint32 lhs, euint32 rhs) internal returns (ebool) {
        return FHE.lte(lhs, rhs);
    }

    /// @notice Performs the rem operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the rem
    function rem(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.rem(lhs, rhs);
    }

    /// @notice Performs the max operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the max
    function max(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.max(lhs, rhs);
    }

    /// @notice Performs the min operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the min
    function min(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.min(lhs, rhs);
    }

    /// @notice Performs the shl operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the shl
    function shl(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.shl(lhs, rhs);
    }

    /// @notice Performs the shr operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the shr
    function shr(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.shr(lhs, rhs);
    }

    /// @notice Performs the rol operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the rol
    function rol(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.rol(lhs, rhs);
    }

    /// @notice Performs the ror operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @param rhs second input of type euint32
    /// @return the result of the ror
    function ror(euint32 lhs, euint32 rhs) internal returns (euint32) {
        return FHE.ror(lhs, rhs);
    }

    /// @notice Performs the square operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint32
    /// @return the result of the square
    function square(euint32 lhs) internal returns (euint32) {
        return FHE.square(lhs);
    }
    function toBool(euint32 value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU8(euint32 value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU16(euint32 value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU64(euint32 value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU128(euint32 value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toU256(euint32 value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(euint32 value) internal {
        FHE.decrypt(value);
    }
    function allow(euint32 ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(euint32 ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(euint32 ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(euint32 ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(euint32 ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(euint32 ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEuint64 for euint64 global;
library BindingsEuint64 {

    /// @notice Performs the add operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the add
    function add(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.add(lhs, rhs);
    }

    /// @notice Performs the mul operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the mul
    function mul(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.mul(lhs, rhs);
    }

    /// @notice Performs the sub operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the sub
    function sub(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.sub(lhs, rhs);
    }

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the eq
    function eq(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the ne
    function ne(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }

    /// @notice Performs the not operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @return the result of the not
    function not(euint64 lhs) internal returns (euint64) {
        return FHE.not(lhs);
    }

    /// @notice Performs the and operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the and
    function and(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.and(lhs, rhs);
    }

    /// @notice Performs the or operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the or
    function or(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.or(lhs, rhs);
    }

    /// @notice Performs the xor operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the xor
    function xor(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.xor(lhs, rhs);
    }

    /// @notice Performs the gt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the gt
    function gt(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return FHE.gt(lhs, rhs);
    }

    /// @notice Performs the gte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the gte
    function gte(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return FHE.gte(lhs, rhs);
    }

    /// @notice Performs the lt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the lt
    function lt(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return FHE.lt(lhs, rhs);
    }

    /// @notice Performs the lte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the lte
    function lte(euint64 lhs, euint64 rhs) internal returns (ebool) {
        return FHE.lte(lhs, rhs);
    }

    /// @notice Performs the max operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the max
    function max(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.max(lhs, rhs);
    }

    /// @notice Performs the min operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the min
    function min(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.min(lhs, rhs);
    }

    /// @notice Performs the shl operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the shl
    function shl(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.shl(lhs, rhs);
    }

    /// @notice Performs the shr operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the shr
    function shr(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.shr(lhs, rhs);
    }

    /// @notice Performs the rol operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the rol
    function rol(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.rol(lhs, rhs);
    }

    /// @notice Performs the ror operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @param rhs second input of type euint64
    /// @return the result of the ror
    function ror(euint64 lhs, euint64 rhs) internal returns (euint64) {
        return FHE.ror(lhs, rhs);
    }

    /// @notice Performs the square operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint64
    /// @return the result of the square
    function square(euint64 lhs) internal returns (euint64) {
        return FHE.square(lhs);
    }
    function toBool(euint64 value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU8(euint64 value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU16(euint64 value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU32(euint64 value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU128(euint64 value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toU256(euint64 value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(euint64 value) internal {
        FHE.decrypt(value);
    }
    function allow(euint64 ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(euint64 ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(euint64 ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(euint64 ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(euint64 ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(euint64 ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEuint128 for euint128 global;
library BindingsEuint128 {

    /// @notice Performs the add operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the add
    function add(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.add(lhs, rhs);
    }

    /// @notice Performs the sub operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the sub
    function sub(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.sub(lhs, rhs);
    }

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the eq
    function eq(euint128 lhs, euint128 rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the ne
    function ne(euint128 lhs, euint128 rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }

    /// @notice Performs the not operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @return the result of the not
    function not(euint128 lhs) internal returns (euint128) {
        return FHE.not(lhs);
    }

    /// @notice Performs the and operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the and
    function and(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.and(lhs, rhs);
    }

    /// @notice Performs the or operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the or
    function or(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.or(lhs, rhs);
    }

    /// @notice Performs the xor operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the xor
    function xor(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.xor(lhs, rhs);
    }

    /// @notice Performs the gt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the gt
    function gt(euint128 lhs, euint128 rhs) internal returns (ebool) {
        return FHE.gt(lhs, rhs);
    }

    /// @notice Performs the gte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the gte
    function gte(euint128 lhs, euint128 rhs) internal returns (ebool) {
        return FHE.gte(lhs, rhs);
    }

    /// @notice Performs the lt operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the lt
    function lt(euint128 lhs, euint128 rhs) internal returns (ebool) {
        return FHE.lt(lhs, rhs);
    }

    /// @notice Performs the lte operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the lte
    function lte(euint128 lhs, euint128 rhs) internal returns (ebool) {
        return FHE.lte(lhs, rhs);
    }

    /// @notice Performs the max operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the max
    function max(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.max(lhs, rhs);
    }

    /// @notice Performs the min operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the min
    function min(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.min(lhs, rhs);
    }

    /// @notice Performs the shl operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the shl
    function shl(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.shl(lhs, rhs);
    }

    /// @notice Performs the shr operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the shr
    function shr(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.shr(lhs, rhs);
    }

    /// @notice Performs the rol operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the rol
    function rol(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.rol(lhs, rhs);
    }

    /// @notice Performs the ror operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint128
    /// @param rhs second input of type euint128
    /// @return the result of the ror
    function ror(euint128 lhs, euint128 rhs) internal returns (euint128) {
        return FHE.ror(lhs, rhs);
    }
    function toBool(euint128 value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU8(euint128 value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU16(euint128 value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU32(euint128 value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU64(euint128 value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU256(euint128 value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(euint128 value) internal {
        FHE.decrypt(value);
    }
    function allow(euint128 ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(euint128 ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(euint128 ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(euint128 ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(euint128 ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(euint128 ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEuint256 for euint256 global;
library BindingsEuint256 {

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return the result of the eq
    function eq(euint256 lhs, euint256 rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type euint256
    /// @param rhs second input of type euint256
    /// @return the result of the ne
    function ne(euint256 lhs, euint256 rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }
    function toBool(euint256 value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU8(euint256 value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU16(euint256 value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU32(euint256 value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU64(euint256 value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU128(euint256 value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toEaddress(euint256 value) internal returns (eaddress) {
        return FHE.asEaddress(value);
    }
    function decrypt(euint256 value) internal {
        FHE.decrypt(value);
    }
    function allow(euint256 ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(euint256 ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(euint256 ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(euint256 ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(euint256 ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(euint256 ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

using BindingsEaddress for eaddress global;
library BindingsEaddress {

    /// @notice Performs the eq operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type eaddress
    /// @param rhs second input of type eaddress
    /// @return the result of the eq
    function eq(eaddress lhs, eaddress rhs) internal returns (ebool) {
        return FHE.eq(lhs, rhs);
    }

    /// @notice Performs the ne operation
    /// @dev Pure in this function is marked as a hack/workaround - note that this function is NOT pure as fetches of ciphertexts require state access
    /// @param lhs input of type eaddress
    /// @param rhs second input of type eaddress
    /// @return the result of the ne
    function ne(eaddress lhs, eaddress rhs) internal returns (ebool) {
        return FHE.ne(lhs, rhs);
    }
    function toBool(eaddress value) internal  returns (ebool) {
        return FHE.asEbool(value);
    }
    function toU8(eaddress value) internal returns (euint8) {
        return FHE.asEuint8(value);
    }
    function toU16(eaddress value) internal returns (euint16) {
        return FHE.asEuint16(value);
    }
    function toU32(eaddress value) internal returns (euint32) {
        return FHE.asEuint32(value);
    }
    function toU64(eaddress value) internal returns (euint64) {
        return FHE.asEuint64(value);
    }
    function toU128(eaddress value) internal returns (euint128) {
        return FHE.asEuint128(value);
    }
    function toU256(eaddress value) internal returns (euint256) {
        return FHE.asEuint256(value);
    }
    function decrypt(eaddress value) internal {
        FHE.decrypt(value);
    }
    function allow(eaddress ctHash, address account) internal {
        FHE.allow(ctHash, account);
    }
    function isAllowed(eaddress ctHash, address account) internal returns (bool) {
        return FHE.isAllowed(ctHash, account);
    }
    function allowThis(eaddress ctHash) internal {
        FHE.allowThis(ctHash);
    }
    function allowGlobal(eaddress ctHash) internal {
        FHE.allowGlobal(ctHash);
    }
    function allowSender(eaddress ctHash) internal {
        FHE.allowSender(ctHash);
    }
    function allowTransient(eaddress ctHash, address account) internal {
        FHE.allowTransient(ctHash, account);
    }
}

// src/interface/IFHERC20.sol

// Fhenix Protocol (last updated v0.1.0) (token/FHERC20/IFHERC20.sol)
// Inspired by OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts) (token/ERC20/IERC20.sol)

interface IFHERC20 is IERC20 {
    // -------- Public Mint / Burn Functions --------
    function mint(address user, uint256 amount) external;
    function burn(address user, uint256 amount) external;

    // -------- Encrypted Mint Functions --------
    function mintEncrypted(address user, InEuint128 memory amount) external;
    function mintEncrypted(address user, euint128 amount) external;

    // -------- Encrypted Burn Functions --------
    function burnEncrypted(address user, InEuint128 memory amount) external;
    function burnEncrypted(address user, euint128 amount) external;

    // -------- Encrypted Transfer Functions --------
    function transferFromEncrypted(address from, address to, InEuint128 memory amount) external returns (euint128);
    function transferFromEncrypted(address from, address to, euint128 amount) external returns (euint128);

    // -------- Decrypt Balance Functions --------
    function decryptBalance(address user) external;
    function getDecryptBalanceResult(address user) external view returns (uint128);
    function getDecryptBalanceResultSafe(address user) external view returns (uint128, bool);

    // -------- Encrypted Wrapping Functions --------
    function wrap(address user, uint128 amount) external;

    // -------- Encrypted Unwrapping Functions --------
    function requestUnwrap(address user, InEuint128 memory amount) external returns (euint128);
    function requestUnwrap(address user, euint128 amount) external returns (euint128);
    function getUnwrapResult(address user, euint128 burnAmount) external returns (uint128);
    function getUnwrapResultSafe(address user, euint128 burnAmount) external returns (uint128, bool);

    // -------- View for encrypted balances --------
    function encBalances(address user) external view returns (euint128);
}

// node_modules/@uniswap/v4-core/src/interfaces/IHooks.sol

/// @notice V4 decides whether to invoke specific hooks by inspecting the least significant bits
/// of the address that the hooks contract is deployed to.
/// For example, a hooks contract deployed to address: 0x0000000000000000000000000000000000002400
/// has the lowest bits '10 0100 0000 0000' which would cause the 'before initialize' and 'after add liquidity' hooks to be used.
/// See the Hooks library for the full spec.
/// @dev Should only be callable by the v4 PoolManager.
interface IHooks {
    /// @notice The hook called before the state of a pool is initialized
    /// @param sender The initial msg.sender for the initialize call
    /// @param key The key for the pool being initialized
    /// @param sqrtPriceX96 The sqrt(price) of the pool as a Q64.96
    /// @return bytes4 The function selector for the hook
    function beforeInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96) external returns (bytes4);

    /// @notice The hook called after the state of a pool is initialized
    /// @param sender The initial msg.sender for the initialize call
    /// @param key The key for the pool being initialized
    /// @param sqrtPriceX96 The sqrt(price) of the pool as a Q64.96
    /// @param tick The current tick after the state of a pool is initialized
    /// @return bytes4 The function selector for the hook
    function afterInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96, int24 tick)
        external
        returns (bytes4);

    /// @notice The hook called before liquidity is added
    /// @param sender The initial msg.sender for the add liquidity call
    /// @param key The key for the pool
    /// @param params The parameters for adding liquidity
    /// @param hookData Arbitrary data handed into the PoolManager by the liquidity provider to be passed on to the hook
    /// @return bytes4 The function selector for the hook
    function beforeAddLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        bytes calldata hookData
    ) external returns (bytes4);

    /// @notice The hook called after liquidity is added
    /// @param sender The initial msg.sender for the add liquidity call
    /// @param key The key for the pool
    /// @param params The parameters for adding liquidity
    /// @param delta The caller's balance delta after adding liquidity; the sum of principal delta, fees accrued, and hook delta
    /// @param feesAccrued The fees accrued since the last time fees were collected from this position
    /// @param hookData Arbitrary data handed into the PoolManager by the liquidity provider to be passed on to the hook
    /// @return bytes4 The function selector for the hook
    /// @return BalanceDelta The hook's delta in token0 and token1. Positive: the hook is owed/took currency, negative: the hook owes/sent currency
    function afterAddLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        BalanceDelta delta,
        BalanceDelta feesAccrued,
        bytes calldata hookData
    ) external returns (bytes4, BalanceDelta);

    /// @notice The hook called before liquidity is removed
    /// @param sender The initial msg.sender for the remove liquidity call
    /// @param key The key for the pool
    /// @param params The parameters for removing liquidity
    /// @param hookData Arbitrary data handed into the PoolManager by the liquidity provider to be be passed on to the hook
    /// @return bytes4 The function selector for the hook
    function beforeRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        bytes calldata hookData
    ) external returns (bytes4);

    /// @notice The hook called after liquidity is removed
    /// @param sender The initial msg.sender for the remove liquidity call
    /// @param key The key for the pool
    /// @param params The parameters for removing liquidity
    /// @param delta The caller's balance delta after removing liquidity; the sum of principal delta, fees accrued, and hook delta
    /// @param feesAccrued The fees accrued since the last time fees were collected from this position
    /// @param hookData Arbitrary data handed into the PoolManager by the liquidity provider to be be passed on to the hook
    /// @return bytes4 The function selector for the hook
    /// @return BalanceDelta The hook's delta in token0 and token1. Positive: the hook is owed/took currency, negative: the hook owes/sent currency
    function afterRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        BalanceDelta delta,
        BalanceDelta feesAccrued,
        bytes calldata hookData
    ) external returns (bytes4, BalanceDelta);

    /// @notice The hook called before a swap
    /// @param sender The initial msg.sender for the swap call
    /// @param key The key for the pool
    /// @param params The parameters for the swap
    /// @param hookData Arbitrary data handed into the PoolManager by the swapper to be be passed on to the hook
    /// @return bytes4 The function selector for the hook
    /// @return BeforeSwapDelta The hook's delta in specified and unspecified currencies. Positive: the hook is owed/took currency, negative: the hook owes/sent currency
    /// @return uint24 Optionally override the lp fee, only used if three conditions are met: 1. the Pool has a dynamic fee, 2. the value's 2nd highest bit is set (23rd bit, 0x400000), and 3. the value is less than or equal to the maximum fee (1 million)
    function beforeSwap(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata hookData)
        external
        returns (bytes4, BeforeSwapDelta, uint24);

    /// @notice The hook called after a swap
    /// @param sender The initial msg.sender for the swap call
    /// @param key The key for the pool
    /// @param params The parameters for the swap
    /// @param delta The amount owed to the caller (positive) or owed to the pool (negative)
    /// @param hookData Arbitrary data handed into the PoolManager by the swapper to be be passed on to the hook
    /// @return bytes4 The function selector for the hook
    /// @return int128 The hook's delta in unspecified currency. Positive: the hook is owed/took currency, negative: the hook owes/sent currency
    function afterSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata params,
        BalanceDelta delta,
        bytes calldata hookData
    ) external returns (bytes4, int128);

    /// @notice The hook called before donate
    /// @param sender The initial msg.sender for the donate call
    /// @param key The key for the pool
    /// @param amount0 The amount of token0 being donated
    /// @param amount1 The amount of token1 being donated
    /// @param hookData Arbitrary data handed into the PoolManager by the donor to be be passed on to the hook
    /// @return bytes4 The function selector for the hook
    function beforeDonate(
        address sender,
        PoolKey calldata key,
        uint256 amount0,
        uint256 amount1,
        bytes calldata hookData
    ) external returns (bytes4);

    /// @notice The hook called after donate
    /// @param sender The initial msg.sender for the donate call
    /// @param key The key for the pool
    /// @param amount0 The amount of token0 being donated
    /// @param amount1 The amount of token1 being donated
    /// @param hookData Arbitrary data handed into the PoolManager by the donor to be be passed on to the hook
    /// @return bytes4 The function selector for the hook
    function afterDonate(
        address sender,
        PoolKey calldata key,
        uint256 amount0,
        uint256 amount1,
        bytes calldata hookData
    ) external returns (bytes4);
}

// node_modules/@uniswap/v4-core/src/types/PoolId.sol

type PoolId is bytes32;

/// @notice Library for computing the ID of a pool
library PoolIdLibrary {
    /// @notice Returns value equal to keccak256(abi.encode(poolKey))
    function toId(PoolKey memory poolKey) internal pure returns (PoolId poolId) {
        assembly ("memory-safe") {
            // 0xa0 represents the total size of the poolKey struct (5 slots of 32 bytes)
            poolId := keccak256(poolKey, 0xa0)
        }
    }
}

// node_modules/@uniswap/v4-core/src/types/PoolKey.sol

using PoolIdLibrary for PoolKey global;

/// @notice Returns the key for identifying a pool
struct PoolKey {
    /// @notice The lower currency of the pool, sorted numerically
    Currency currency0;
    /// @notice The higher currency of the pool, sorted numerically
    Currency currency1;
    /// @notice The pool LP fee, capped at 1_000_000. If the highest bit is 1, the pool has a dynamic fee and must be exactly equal to 0x800000
    uint24 fee;
    /// @notice Ticks that involve positions must be a multiple of tick spacing
    int24 tickSpacing;
    /// @notice The hooks of the pool
    IHooks hooks;
}

// node_modules/@uniswap/v4-core/src/types/PoolOperation.sol

/// @notice Parameter struct for `ModifyLiquidity` pool operations
struct ModifyLiquidityParams {
    // the lower and upper tick of the position
    int24 tickLower;
    int24 tickUpper;
    // how to modify the liquidity
    int256 liquidityDelta;
    // a value to set if you want unique liquidity positions at the same range
    bytes32 salt;
}

/// @notice Parameter struct for `Swap` pool operations
struct SwapParams {
    /// Whether to swap token0 for token1 or vice versa
    bool zeroForOne;
    /// The desired input amount if negative (exactIn), or the desired output amount if positive (exactOut)
    int256 amountSpecified;
    /// The sqrt price at which, if reached, the swap will stop executing
    uint160 sqrtPriceLimitX96;
}

// node_modules/@uniswap/v4-core/src/interfaces/IProtocolFees.sol

/// @notice Interface for all protocol-fee related functions in the pool manager
interface IProtocolFees {
    /// @notice Thrown when protocol fee is set too high
    error ProtocolFeeTooLarge(uint24 fee);

    /// @notice Thrown when collectProtocolFees or setProtocolFee is not called by the controller.
    error InvalidCaller();

    /// @notice Thrown when collectProtocolFees is attempted on a token that is synced.
    error ProtocolFeeCurrencySynced();

    /// @notice Emitted when the protocol fee controller address is updated in setProtocolFeeController.
    event ProtocolFeeControllerUpdated(address indexed protocolFeeController);

    /// @notice Emitted when the protocol fee is updated for a pool.
    event ProtocolFeeUpdated(PoolId indexed id, uint24 protocolFee);

    /// @notice Given a currency address, returns the protocol fees accrued in that currency
    /// @param currency The currency to check
    /// @return amount The amount of protocol fees accrued in the currency
    function protocolFeesAccrued(Currency currency) external view returns (uint256 amount);

    /// @notice Sets the protocol fee for the given pool
    /// @param key The key of the pool to set a protocol fee for
    /// @param newProtocolFee The fee to set
    function setProtocolFee(PoolKey memory key, uint24 newProtocolFee) external;

    /// @notice Sets the protocol fee controller
    /// @param controller The new protocol fee controller
    function setProtocolFeeController(address controller) external;

    /// @notice Collects the protocol fees for a given recipient and currency, returning the amount collected
    /// @dev This will revert if the contract is unlocked
    /// @param recipient The address to receive the protocol fees
    /// @param currency The currency to withdraw
    /// @param amount The amount of currency to withdraw
    /// @return amountCollected The amount of currency successfully withdrawn
    function collectProtocolFees(address recipient, Currency currency, uint256 amount)
        external
        returns (uint256 amountCollected);

    /// @notice Returns the current protocol fee controller address
    /// @return address The current protocol fee controller address
    function protocolFeeController() external view returns (address);
}

// src/HybridFHERC20.sol
// forge coverage: ignore-file

/**
 * @dev Minimal implementation of an FHERC20 token
 * Implementation of the bare minimum methods to make
 * the hook work with a hybrid FHE / ERC20 token
 */
contract HybridFHERC20 is ERC20, IFHERC20 {

    //errors
    error HybridFHERC20__InvalidSender();
    error HybridFHERC20__InvalidReceiver();

    //allow for more natural syntax for euint types
    using FHE for uint256;

    //encrypted balances
    mapping(address => euint128) public encBalances;
    euint128 public totalEncryptedSupply = FHE.asEuint128(0);

    //zero constant
    euint128 private immutable ZERO = FHE.asEuint128(0);

    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        FHE.allowThis(ZERO);
    }

    // ----------- Public Mint Functions --------------------
    function mint(address user, uint256 amount) public {
        _mint(user, amount);
    }

    // ----------- Public Burn Functions --------------------
    function burn(address user, uint256 amount) public {
        _burn(user, amount);
    }

    // ----------- Encrypted Mint Functions -----------------
    function mintEncrypted(address user, InEuint128 memory amount) public {
        _mintEnc(user, FHE.asEuint128(amount));
    }

    function mintEncrypted(address user, euint128 amount) public {
        _mintEnc(user, amount);
    }

    function _mintEnc(address user, euint128 amount) internal {
        encBalances[user] = encBalances[user].add(amount);
        totalEncryptedSupply = totalEncryptedSupply.add(amount);

        FHE.allowThis(encBalances[user]);
        FHE.allow(encBalances[user], user);
        FHE.allowGlobal(totalEncryptedSupply);
    }

    // ----------- Encrypted Burn Functions -----------------
    function burnEncrypted(address user, InEuint128 memory amount) public {
        _burnEnc(user, FHE.asEuint128(amount));
    }

    function burnEncrypted(address user, euint128 amount) public {
        _burnEnc(user, amount);
    }

    function _burnEnc(address user, euint128 amount) internal {
        euint128 burnAmount = _calculateBurnAmount(user, amount);
        encBalances[user] = encBalances[user].sub(burnAmount);
        totalEncryptedSupply = totalEncryptedSupply.sub(burnAmount);

        FHE.allowThis(encBalances[user]);
        FHE.allow(encBalances[user], user);
        FHE.allowGlobal(totalEncryptedSupply);
    }

    function _calculateBurnAmount(address user, euint128 amount) internal returns(euint128){
        return FHE.select(amount.lte(encBalances[user]), amount, ZERO);
    }

    // ----------- Encrypted Transfer Functions ---------------
    function transferEncrypted(address to, InEuint128 memory amount) external returns(euint128) {
        return _transferImpl(msg.sender, to, FHE.asEuint128(amount));
    }

    function transferEncrypted(address to, euint128 amount) external returns(euint128) {
        return _transferImpl(msg.sender, to, amount);
    }

    function transferFromEncrypted(address from, address to, InEuint128 memory amount) external returns(euint128) {
        return _transferImpl(from, to, FHE.asEuint128(amount));
    }

    function transferFromEncrypted(address from, address to, euint128 amount) external returns(euint128) {
        return _transferImpl(from, to, amount);
    }

    function _transferImpl(address from, address to, euint128 amount) internal returns (euint128) {
        //ensure sender / receiver is not 0x00
        if(from == address(0)){
            revert HybridFHERC20__InvalidSender();
        }
        if(to == address(0)){
            revert HybridFHERC20__InvalidReceiver();
        }

        // Make sure the sender has enough tokens.
        euint128 amountToSend = FHE.select(amount.lte(encBalances[from]), amount, ZERO);

        // Add to the balance of `to` and subract from the balance of `from`.
        encBalances[to] = encBalances[to].add(amountToSend);
        encBalances[from] = encBalances[from].sub(amountToSend);

        //allow contract to interact with balances
        FHE.allowThis(encBalances[to]);
        FHE.allowThis(encBalances[from]);

        //allow users to interact with their balances
        FHE.allow(encBalances[to], to);
        FHE.allow(encBalances[from], from);

        return amountToSend;
    }

    // --------- Decrypt Balance Functions ------------------
    function decryptBalance(address user) public {
        FHE.decrypt(encBalances[user]);
    }

    function getDecryptBalanceResult(address user) public view returns(uint128) {
        return FHE.getDecryptResult(encBalances[user]);
    }

    function getDecryptBalanceResultSafe(address user) public view returns(uint128, bool) {
        return FHE.getDecryptResultSafe(encBalances[user]);
    }

    // --------- Encrypted Wrapping Functions ---------------
    function wrap(address user, uint128 amount) external {
        _wrap(user, amount);
    }

    function _wrap(address user, uint128 amount) internal {
        //burn public balance
        _burn(user, uint256(amount));

        //mint encrypted balance
        _mintEnc(user, FHE.asEuint128(amount));
    }

    // --------- Encrypted Unwrapping Functions ---------------
    function requestUnwrap(address user, InEuint128 memory amount) external returns(euint128) {
        return _requestUnwrap(user, FHE.asEuint128(amount));
    }

    function requestUnwrap(address user, euint128 amount) external returns(euint128) {
        return _requestUnwrap(user, amount);
    }

    function getUnwrapResult(address user, euint128 burnAmount) external returns(uint128 amount) {
        return _getUnwrapResult(user, burnAmount);
    }

    function getUnwrapResultSafe(address user, euint128 burnAmount) external returns(uint128 amount, bool decrypted) {
        return _getUnwrapResultSafe(user, burnAmount);
    }

    function _requestUnwrap(address user, euint128 amount) internal returns(euint128 burnAmount) {
        burnAmount = _calculateBurnAmount(user, amount);
        //request decrpytion of burn amount
        FHE.decrypt(burnAmount);
    }

    function _getUnwrapResult(address user, euint128 burnAmount) internal returns(uint128 amount) {
        amount = FHE.getDecryptResult(burnAmount);

        //burn encrypted balance
        _burnEnc(user, burnAmount);

        //mint public balance
        _mint(user, amount);
    }

    function _getUnwrapResultSafe(address user, euint128 burnAmount) internal returns(uint128 amount, bool decrypted) {
        (amount, decrypted) = FHE.getDecryptResultSafe(burnAmount);

        if(!decrypted){
            return (0, false);
        }

        //burn encrypted balance
        _burnEnc(user, burnAmount);

        //mint public balance
        _mint(user, amount);
    }
}

// node_modules/@uniswap/v4-core/src/interfaces/IPoolManager.sol

/// @notice Interface for the PoolManager
interface IPoolManager is IProtocolFees, IERC6909Claims, IExtsload, IExttload {
    /// @notice Thrown when a currency is not netted out after the contract is unlocked
    error CurrencyNotSettled();

    /// @notice Thrown when trying to interact with a non-initialized pool
    error PoolNotInitialized();

    /// @notice Thrown when unlock is called, but the contract is already unlocked
    error AlreadyUnlocked();

    /// @notice Thrown when a function is called that requires the contract to be unlocked, but it is not
    error ManagerLocked();

    /// @notice Pools are limited to type(int16).max tickSpacing in #initialize, to prevent overflow
    error TickSpacingTooLarge(int24 tickSpacing);

    /// @notice Pools must have a positive non-zero tickSpacing passed to #initialize
    error TickSpacingTooSmall(int24 tickSpacing);

    /// @notice PoolKey must have currencies where address(currency0) < address(currency1)
    error CurrenciesOutOfOrderOrEqual(address currency0, address currency1);

    /// @notice Thrown when a call to updateDynamicLPFee is made by an address that is not the hook,
    /// or on a pool that does not have a dynamic swap fee.
    error UnauthorizedDynamicLPFeeUpdate();

    /// @notice Thrown when trying to swap amount of 0
    error SwapAmountCannotBeZero();

    ///@notice Thrown when native currency is passed to a non native settlement
    error NonzeroNativeValue();

    /// @notice Thrown when `clear` is called with an amount that is not exactly equal to the open currency delta.
    error MustClearExactPositiveDelta();

    /// @notice Emitted when a new pool is initialized
    /// @param id The abi encoded hash of the pool key struct for the new pool
    /// @param currency0 The first currency of the pool by address sort order
    /// @param currency1 The second currency of the pool by address sort order
    /// @param fee The fee collected upon every swap in the pool, denominated in hundredths of a bip
    /// @param tickSpacing The minimum number of ticks between initialized ticks
    /// @param hooks The hooks contract address for the pool, or address(0) if none
    /// @param sqrtPriceX96 The price of the pool on initialization
    /// @param tick The initial tick of the pool corresponding to the initialized price
    event Initialize(
        PoolId indexed id,
        Currency indexed currency0,
        Currency indexed currency1,
        uint24 fee,
        int24 tickSpacing,
        IHooks hooks,
        uint160 sqrtPriceX96,
        int24 tick
    );

    /// @notice Emitted when a liquidity position is modified
    /// @param id The abi encoded hash of the pool key struct for the pool that was modified
    /// @param sender The address that modified the pool
    /// @param tickLower The lower tick of the position
    /// @param tickUpper The upper tick of the position
    /// @param liquidityDelta The amount of liquidity that was added or removed
    /// @param salt The extra data to make positions unique
    event ModifyLiquidity(
        PoolId indexed id, address indexed sender, int24 tickLower, int24 tickUpper, int256 liquidityDelta, bytes32 salt
    );

    /// @notice Emitted for swaps between currency0 and currency1
    /// @param id The abi encoded hash of the pool key struct for the pool that was modified
    /// @param sender The address that initiated the swap call, and that received the callback
    /// @param amount0 The delta of the currency0 balance of the pool
    /// @param amount1 The delta of the currency1 balance of the pool
    /// @param sqrtPriceX96 The sqrt(price) of the pool after the swap, as a Q64.96
    /// @param liquidity The liquidity of the pool after the swap
    /// @param tick The log base 1.0001 of the price of the pool after the swap
    /// @param fee The swap fee in hundredths of a bip
    event Swap(
        PoolId indexed id,
        address indexed sender,
        int128 amount0,
        int128 amount1,
        uint160 sqrtPriceX96,
        uint128 liquidity,
        int24 tick,
        uint24 fee
    );

    /// @notice Emitted for donations
    /// @param id The abi encoded hash of the pool key struct for the pool that was donated to
    /// @param sender The address that initiated the donate call
    /// @param amount0 The amount donated in currency0
    /// @param amount1 The amount donated in currency1
    event Donate(PoolId indexed id, address indexed sender, uint256 amount0, uint256 amount1);

    /// @notice All interactions on the contract that account deltas require unlocking. A caller that calls `unlock` must implement
    /// `IUnlockCallback(msg.sender).unlockCallback(data)`, where they interact with the remaining functions on this contract.
    /// @dev The only functions callable without an unlocking are `initialize` and `updateDynamicLPFee`
    /// @param data Any data to pass to the callback, via `IUnlockCallback(msg.sender).unlockCallback(data)`
    /// @return The data returned by the call to `IUnlockCallback(msg.sender).unlockCallback(data)`
    function unlock(bytes calldata data) external returns (bytes memory);

    /// @notice Initialize the state for a given pool ID
    /// @dev A swap fee totaling MAX_SWAP_FEE (100%) makes exact output swaps impossible since the input is entirely consumed by the fee
    /// @param key The pool key for the pool to initialize
    /// @param sqrtPriceX96 The initial square root price
    /// @return tick The initial tick of the pool
    function initialize(PoolKey memory key, uint160 sqrtPriceX96) external returns (int24 tick);

    /// @notice Modify the liquidity for the given pool
    /// @dev Poke by calling with a zero liquidityDelta
    /// @param key The pool to modify liquidity in
    /// @param params The parameters for modifying the liquidity
    /// @param hookData The data to pass through to the add/removeLiquidity hooks
    /// @return callerDelta The balance delta of the caller of modifyLiquidity. This is the total of both principal, fee deltas, and hook deltas if applicable
    /// @return feesAccrued The balance delta of the fees generated in the liquidity range. Returned for informational purposes
    /// @dev Note that feesAccrued can be artificially inflated by a malicious actor and integrators should be careful using the value
    /// For pools with a single liquidity position, actors can donate to themselves to inflate feeGrowthGlobal (and consequently feesAccrued)
    /// atomically donating and collecting fees in the same unlockCallback may make the inflated value more extreme
    function modifyLiquidity(PoolKey memory key, ModifyLiquidityParams memory params, bytes calldata hookData)
        external
        returns (BalanceDelta callerDelta, BalanceDelta feesAccrued);

    /// @notice Swap against the given pool
    /// @param key The pool to swap in
    /// @param params The parameters for swapping
    /// @param hookData The data to pass through to the swap hooks
    /// @return swapDelta The balance delta of the address swapping
    /// @dev Swapping on low liquidity pools may cause unexpected swap amounts when liquidity available is less than amountSpecified.
    /// Additionally note that if interacting with hooks that have the BEFORE_SWAP_RETURNS_DELTA_FLAG or AFTER_SWAP_RETURNS_DELTA_FLAG
    /// the hook may alter the swap input/output. Integrators should perform checks on the returned swapDelta.
    function swap(PoolKey memory key, SwapParams memory params, bytes calldata hookData)
        external
        returns (BalanceDelta swapDelta);

    /// @notice Donate the given currency amounts to the in-range liquidity providers of a pool
    /// @dev Calls to donate can be frontrun adding just-in-time liquidity, with the aim of receiving a portion donated funds.
    /// Donors should keep this in mind when designing donation mechanisms.
    /// @dev This function donates to in-range LPs at slot0.tick. In certain edge-cases of the swap algorithm, the `sqrtPrice` of
    /// a pool can be at the lower boundary of tick `n`, but the `slot0.tick` of the pool is already `n - 1`. In this case a call to
    /// `donate` would donate to tick `n - 1` (slot0.tick) not tick `n` (getTickAtSqrtPrice(slot0.sqrtPriceX96)).
    /// Read the comments in `Pool.swap()` for more information about this.
    /// @param key The key of the pool to donate to
    /// @param amount0 The amount of currency0 to donate
    /// @param amount1 The amount of currency1 to donate
    /// @param hookData The data to pass through to the donate hooks
    /// @return BalanceDelta The delta of the caller after the donate
    function donate(PoolKey memory key, uint256 amount0, uint256 amount1, bytes calldata hookData)
        external
        returns (BalanceDelta);

    /// @notice Writes the current ERC20 balance of the specified currency to transient storage
    /// This is used to checkpoint balances for the manager and derive deltas for the caller.
    /// @dev This MUST be called before any ERC20 tokens are sent into the contract, but can be skipped
    /// for native tokens because the amount to settle is determined by the sent value.
    /// However, if an ERC20 token has been synced and not settled, and the caller instead wants to settle
    /// native funds, this function can be called with the native currency to then be able to settle the native currency
    function sync(Currency currency) external;

    /// @notice Called by the user to net out some value owed to the user
    /// @dev Will revert if the requested amount is not available, consider using `mint` instead
    /// @dev Can also be used as a mechanism for free flash loans
    /// @param currency The currency to withdraw from the pool manager
    /// @param to The address to withdraw to
    /// @param amount The amount of currency to withdraw
    function take(Currency currency, address to, uint256 amount) external;

    /// @notice Called by the user to pay what is owed
    /// @return paid The amount of currency settled
    function settle() external payable returns (uint256 paid);

    /// @notice Called by the user to pay on behalf of another address
    /// @param recipient The address to credit for the payment
    /// @return paid The amount of currency settled
    function settleFor(address recipient) external payable returns (uint256 paid);

    /// @notice WARNING - Any currency that is cleared, will be non-retrievable, and locked in the contract permanently.
    /// A call to clear will zero out a positive balance WITHOUT a corresponding transfer.
    /// @dev This could be used to clear a balance that is considered dust.
    /// Additionally, the amount must be the exact positive balance. This is to enforce that the caller is aware of the amount being cleared.
    function clear(Currency currency, uint256 amount) external;

    /// @notice Called by the user to move value into ERC6909 balance
    /// @param to The address to mint the tokens to
    /// @param id The currency address to mint to ERC6909s, as a uint256
    /// @param amount The amount of currency to mint
    /// @dev The id is converted to a uint160 to correspond to a currency address
    /// If the upper 12 bytes are not 0, they will be 0-ed out
    function mint(address to, uint256 id, uint256 amount) external;

    /// @notice Called by the user to move value from ERC6909 balance
    /// @param from The address to burn the tokens from
    /// @param id The currency address to burn from ERC6909s, as a uint256
    /// @param amount The amount of currency to burn
    /// @dev The id is converted to a uint160 to correspond to a currency address
    /// If the upper 12 bytes are not 0, they will be 0-ed out
    function burn(address from, uint256 id, uint256 amount) external;

    /// @notice Updates the pools lp fees for the a pool that has enabled dynamic lp fees.
    /// @dev A swap fee totaling MAX_SWAP_FEE (100%) makes exact output swaps impossible since the input is entirely consumed by the fee
    /// @param key The key of the pool to update dynamic LP fees for
    /// @param newDynamicLPFee The new dynamic pool LP fee
    function updateDynamicLPFee(PoolKey memory key, uint24 newDynamicLPFee) external;
}

// node_modules/@uniswap/v4-periphery/src/interfaces/IImmutableState.sol

/// @title IImmutableState
/// @notice Interface for the ImmutableState contract
interface IImmutableState {
    /// @notice The Uniswap v4 PoolManager contract
    function poolManager() external view returns (IPoolManager);
}

// node_modules/@uniswap/v4-periphery/src/base/ImmutableState.sol

/// @title Immutable State
/// @notice A collection of immutable state variables, commonly used across multiple contracts
contract ImmutableState is IImmutableState {
    /// @inheritdoc IImmutableState
    IPoolManager public immutable poolManager;

    /// @notice Thrown when the caller is not PoolManager
    error NotPoolManager();

    /// @notice Only allow calls from the PoolManager contract
    modifier onlyPoolManager() {
        if (msg.sender != address(poolManager)) revert NotPoolManager();
        _;
    }

    constructor(IPoolManager _poolManager) {
        poolManager = _poolManager;
    }
}

// node_modules/@uniswap/v4-core/src/libraries/Hooks.sol

/// @notice V4 decides whether to invoke specific hooks by inspecting the least significant bits
/// of the address that the hooks contract is deployed to.
/// For example, a hooks contract deployed to address: 0x0000000000000000000000000000000000002400
/// has the lowest bits '10 0100 0000 0000' which would cause the 'before initialize' and 'after add liquidity' hooks to be used.
library Hooks {
    using LPFeeLibrary for uint24;
    using Hooks for IHooks;
    using SafeCast_1 for int256;
    using BeforeSwapDeltaLibrary for BeforeSwapDelta;
    using ParseBytes for bytes;
    using CustomRevert for bytes4;

    uint160 internal constant ALL_HOOK_MASK = uint160((1 << 14) - 1);

    uint160 internal constant BEFORE_INITIALIZE_FLAG = 1 << 13;
    uint160 internal constant AFTER_INITIALIZE_FLAG = 1 << 12;

    uint160 internal constant BEFORE_ADD_LIQUIDITY_FLAG = 1 << 11;
    uint160 internal constant AFTER_ADD_LIQUIDITY_FLAG = 1 << 10;

    uint160 internal constant BEFORE_REMOVE_LIQUIDITY_FLAG = 1 << 9;
    uint160 internal constant AFTER_REMOVE_LIQUIDITY_FLAG = 1 << 8;

    uint160 internal constant BEFORE_SWAP_FLAG = 1 << 7;
    uint160 internal constant AFTER_SWAP_FLAG = 1 << 6;

    uint160 internal constant BEFORE_DONATE_FLAG = 1 << 5;
    uint160 internal constant AFTER_DONATE_FLAG = 1 << 4;

    uint160 internal constant BEFORE_SWAP_RETURNS_DELTA_FLAG = 1 << 3;
    uint160 internal constant AFTER_SWAP_RETURNS_DELTA_FLAG = 1 << 2;
    uint160 internal constant AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG = 1 << 1;
    uint160 internal constant AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG = 1 << 0;

    struct Permissions {
        bool beforeInitialize;
        bool afterInitialize;
        bool beforeAddLiquidity;
        bool afterAddLiquidity;
        bool beforeRemoveLiquidity;
        bool afterRemoveLiquidity;
        bool beforeSwap;
        bool afterSwap;
        bool beforeDonate;
        bool afterDonate;
        bool beforeSwapReturnDelta;
        bool afterSwapReturnDelta;
        bool afterAddLiquidityReturnDelta;
        bool afterRemoveLiquidityReturnDelta;
    }

    /// @notice Thrown if the address will not lead to the specified hook calls being called
    /// @param hooks The address of the hooks contract
    error HookAddressNotValid(address hooks);

    /// @notice Hook did not return its selector
    error InvalidHookResponse();

    /// @notice Additional context for ERC-7751 wrapped error when a hook call fails
    error HookCallFailed();

    /// @notice The hook's delta changed the swap from exactIn to exactOut or vice versa
    error HookDeltaExceedsSwapAmount();

    /// @notice Utility function intended to be used in hook constructors to ensure
    /// the deployed hooks address causes the intended hooks to be called
    /// @param permissions The hooks that are intended to be called
    /// @dev permissions param is memory as the function will be called from constructors
    function validateHookPermissions(IHooks self, Permissions memory permissions) internal pure {
        if (
            permissions.beforeInitialize != self.hasPermission(BEFORE_INITIALIZE_FLAG)
                || permissions.afterInitialize != self.hasPermission(AFTER_INITIALIZE_FLAG)
                || permissions.beforeAddLiquidity != self.hasPermission(BEFORE_ADD_LIQUIDITY_FLAG)
                || permissions.afterAddLiquidity != self.hasPermission(AFTER_ADD_LIQUIDITY_FLAG)
                || permissions.beforeRemoveLiquidity != self.hasPermission(BEFORE_REMOVE_LIQUIDITY_FLAG)
                || permissions.afterRemoveLiquidity != self.hasPermission(AFTER_REMOVE_LIQUIDITY_FLAG)
                || permissions.beforeSwap != self.hasPermission(BEFORE_SWAP_FLAG)
                || permissions.afterSwap != self.hasPermission(AFTER_SWAP_FLAG)
                || permissions.beforeDonate != self.hasPermission(BEFORE_DONATE_FLAG)
                || permissions.afterDonate != self.hasPermission(AFTER_DONATE_FLAG)
                || permissions.beforeSwapReturnDelta != self.hasPermission(BEFORE_SWAP_RETURNS_DELTA_FLAG)
                || permissions.afterSwapReturnDelta != self.hasPermission(AFTER_SWAP_RETURNS_DELTA_FLAG)
                || permissions.afterAddLiquidityReturnDelta != self.hasPermission(AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG)
                || permissions.afterRemoveLiquidityReturnDelta
                    != self.hasPermission(AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG)
        ) {
            HookAddressNotValid.selector.revertWith(address(self));
        }
    }

    /// @notice Ensures that the hook address includes at least one hook flag or dynamic fees, or is the 0 address
    /// @param self The hook to verify
    /// @param fee The fee of the pool the hook is used with
    /// @return bool True if the hook address is valid
    function isValidHookAddress(IHooks self, uint24 fee) internal pure returns (bool) {
        // The hook can only have a flag to return a hook delta on an action if it also has the corresponding action flag
        if (!self.hasPermission(BEFORE_SWAP_FLAG) && self.hasPermission(BEFORE_SWAP_RETURNS_DELTA_FLAG)) return false;
        if (!self.hasPermission(AFTER_SWAP_FLAG) && self.hasPermission(AFTER_SWAP_RETURNS_DELTA_FLAG)) return false;
        if (!self.hasPermission(AFTER_ADD_LIQUIDITY_FLAG) && self.hasPermission(AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG))
        {
            return false;
        }
        if (
            !self.hasPermission(AFTER_REMOVE_LIQUIDITY_FLAG)
                && self.hasPermission(AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG)
        ) return false;

        // If there is no hook contract set, then fee cannot be dynamic
        // If a hook contract is set, it must have at least 1 flag set, or have a dynamic fee
        return address(self) == address(0)
            ? !fee.isDynamicFee()
            : (uint160(address(self)) & ALL_HOOK_MASK > 0 || fee.isDynamicFee());
    }

    /// @notice performs a hook call using the given calldata on the given hook that doesn't return a delta
    /// @return result The complete data returned by the hook
    function callHook(IHooks self, bytes memory data) internal returns (bytes memory result) {
        bool success;
        assembly ("memory-safe") {
            success := call(gas(), self, 0, add(data, 0x20), mload(data), 0, 0)
        }
        // Revert with FailedHookCall, containing any error message to bubble up
        if (!success) CustomRevert.bubbleUpAndRevertWith(address(self), bytes4(data), HookCallFailed.selector);

        // The call was successful, fetch the returned data
        assembly ("memory-safe") {
            // allocate result byte array from the free memory pointer
            result := mload(0x40)
            // store new free memory pointer at the end of the array padded to 32 bytes
            mstore(0x40, add(result, and(add(returndatasize(), 0x3f), not(0x1f))))
            // store length in memory
            mstore(result, returndatasize())
            // copy return data to result
            returndatacopy(add(result, 0x20), 0, returndatasize())
        }

        // Length must be at least 32 to contain the selector. Check expected selector and returned selector match.
        if (result.length < 32 || result.parseSelector() != data.parseSelector()) {
            InvalidHookResponse.selector.revertWith();
        }
    }

    /// @notice performs a hook call using the given calldata on the given hook
    /// @return int256 The delta returned by the hook
    function callHookWithReturnDelta(IHooks self, bytes memory data, bool parseReturn) internal returns (int256) {
        bytes memory result = callHook(self, data);

        // If this hook wasn't meant to return something, default to 0 delta
        if (!parseReturn) return 0;

        // A length of 64 bytes is required to return a bytes4, and a 32 byte delta
        if (result.length != 64) InvalidHookResponse.selector.revertWith();
        return result.parseReturnDelta();
    }

    /// @notice modifier to prevent calling a hook if they initiated the action
    modifier noSelfCall(IHooks self) {
        if (msg.sender != address(self)) {
            _;
        }
    }

    /// @notice calls beforeInitialize hook if permissioned and validates return value
    function beforeInitialize(IHooks self, PoolKey memory key, uint160 sqrtPriceX96) internal noSelfCall(self) {
        if (self.hasPermission(BEFORE_INITIALIZE_FLAG)) {
            self.callHook(abi.encodeCall(IHooks.beforeInitialize, (msg.sender, key, sqrtPriceX96)));
        }
    }

    /// @notice calls afterInitialize hook if permissioned and validates return value
    function afterInitialize(IHooks self, PoolKey memory key, uint160 sqrtPriceX96, int24 tick)
        internal
        noSelfCall(self)
    {
        if (self.hasPermission(AFTER_INITIALIZE_FLAG)) {
            self.callHook(abi.encodeCall(IHooks.afterInitialize, (msg.sender, key, sqrtPriceX96, tick)));
        }
    }

    /// @notice calls beforeModifyLiquidity hook if permissioned and validates return value
    function beforeModifyLiquidity(
        IHooks self,
        PoolKey memory key,
        ModifyLiquidityParams memory params,
        bytes calldata hookData
    ) internal noSelfCall(self) {
        if (params.liquidityDelta > 0 && self.hasPermission(BEFORE_ADD_LIQUIDITY_FLAG)) {
            self.callHook(abi.encodeCall(IHooks.beforeAddLiquidity, (msg.sender, key, params, hookData)));
        } else if (params.liquidityDelta <= 0 && self.hasPermission(BEFORE_REMOVE_LIQUIDITY_FLAG)) {
            self.callHook(abi.encodeCall(IHooks.beforeRemoveLiquidity, (msg.sender, key, params, hookData)));
        }
    }

    /// @notice calls afterModifyLiquidity hook if permissioned and validates return value
    function afterModifyLiquidity(
        IHooks self,
        PoolKey memory key,
        ModifyLiquidityParams memory params,
        BalanceDelta delta,
        BalanceDelta feesAccrued,
        bytes calldata hookData
    ) internal returns (BalanceDelta callerDelta, BalanceDelta hookDelta) {
        if (msg.sender == address(self)) return (delta, BalanceDeltaLibrary.ZERO_DELTA);

        callerDelta = delta;
        if (params.liquidityDelta > 0) {
            if (self.hasPermission(AFTER_ADD_LIQUIDITY_FLAG)) {
                hookDelta = BalanceDelta.wrap(
                    self.callHookWithReturnDelta(
                        abi.encodeCall(
                            IHooks.afterAddLiquidity, (msg.sender, key, params, delta, feesAccrued, hookData)
                        ),
                        self.hasPermission(AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG)
                    )
                );
                callerDelta = callerDelta - hookDelta;
            }
        } else {
            if (self.hasPermission(AFTER_REMOVE_LIQUIDITY_FLAG)) {
                hookDelta = BalanceDelta.wrap(
                    self.callHookWithReturnDelta(
                        abi.encodeCall(
                            IHooks.afterRemoveLiquidity, (msg.sender, key, params, delta, feesAccrued, hookData)
                        ),
                        self.hasPermission(AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG)
                    )
                );
                callerDelta = callerDelta - hookDelta;
            }
        }
    }

    /// @notice calls beforeSwap hook if permissioned and validates return value
    function beforeSwap(IHooks self, PoolKey memory key, SwapParams memory params, bytes calldata hookData)
        internal
        returns (int256 amountToSwap, BeforeSwapDelta hookReturn, uint24 lpFeeOverride)
    {
        amountToSwap = params.amountSpecified;
        if (msg.sender == address(self)) return (amountToSwap, BeforeSwapDeltaLibrary.ZERO_DELTA, lpFeeOverride);

        if (self.hasPermission(BEFORE_SWAP_FLAG)) {
            bytes memory result = callHook(self, abi.encodeCall(IHooks.beforeSwap, (msg.sender, key, params, hookData)));

            // A length of 96 bytes is required to return a bytes4, a 32 byte delta, and an LP fee
            if (result.length != 96) InvalidHookResponse.selector.revertWith();

            // dynamic fee pools that want to override the cache fee, return a valid fee with the override flag. If override flag
            // is set but an invalid fee is returned, the transaction will revert. Otherwise the current LP fee will be used
            if (key.fee.isDynamicFee()) lpFeeOverride = result.parseFee();

            // skip this logic for the case where the hook return is 0
            if (self.hasPermission(BEFORE_SWAP_RETURNS_DELTA_FLAG)) {
                hookReturn = BeforeSwapDelta.wrap(result.parseReturnDelta());

                // any return in unspecified is passed to the afterSwap hook for handling
                int128 hookDeltaSpecified = hookReturn.getSpecifiedDelta();

                // Update the swap amount according to the hook's return, and check that the swap type doesn't change (exact input/output)
                if (hookDeltaSpecified != 0) {
                    bool exactInput = amountToSwap < 0;
                    amountToSwap += hookDeltaSpecified;
                    if (exactInput ? amountToSwap > 0 : amountToSwap < 0) {
                        HookDeltaExceedsSwapAmount.selector.revertWith();
                    }
                }
            }
        }
    }

    /// @notice calls afterSwap hook if permissioned and validates return value
    function afterSwap(
        IHooks self,
        PoolKey memory key,
        SwapParams memory params,
        BalanceDelta swapDelta,
        bytes calldata hookData,
        BeforeSwapDelta beforeSwapHookReturn
    ) internal returns (BalanceDelta, BalanceDelta) {
        if (msg.sender == address(self)) return (swapDelta, BalanceDeltaLibrary.ZERO_DELTA);

        int128 hookDeltaSpecified = beforeSwapHookReturn.getSpecifiedDelta();
        int128 hookDeltaUnspecified = beforeSwapHookReturn.getUnspecifiedDelta();

        if (self.hasPermission(AFTER_SWAP_FLAG)) {
            hookDeltaUnspecified += self.callHookWithReturnDelta(
                abi.encodeCall(IHooks.afterSwap, (msg.sender, key, params, swapDelta, hookData)),
                self.hasPermission(AFTER_SWAP_RETURNS_DELTA_FLAG)
            ).toInt128();
        }

        BalanceDelta hookDelta;
        if (hookDeltaUnspecified != 0 || hookDeltaSpecified != 0) {
            hookDelta = (params.amountSpecified < 0 == params.zeroForOne)
                ? toBalanceDelta(hookDeltaSpecified, hookDeltaUnspecified)
                : toBalanceDelta(hookDeltaUnspecified, hookDeltaSpecified);

            // the caller has to pay for (or receive) the hook's delta
            swapDelta = swapDelta - hookDelta;
        }
        return (swapDelta, hookDelta);
    }

    /// @notice calls beforeDonate hook if permissioned and validates return value
    function beforeDonate(IHooks self, PoolKey memory key, uint256 amount0, uint256 amount1, bytes calldata hookData)
        internal
        noSelfCall(self)
    {
        if (self.hasPermission(BEFORE_DONATE_FLAG)) {
            self.callHook(abi.encodeCall(IHooks.beforeDonate, (msg.sender, key, amount0, amount1, hookData)));
        }
    }

    /// @notice calls afterDonate hook if permissioned and validates return value
    function afterDonate(IHooks self, PoolKey memory key, uint256 amount0, uint256 amount1, bytes calldata hookData)
        internal
        noSelfCall(self)
    {
        if (self.hasPermission(AFTER_DONATE_FLAG)) {
            self.callHook(abi.encodeCall(IHooks.afterDonate, (msg.sender, key, amount0, amount1, hookData)));
        }
    }

    function hasPermission(IHooks self, uint160 flag) internal pure returns (bool) {
        return uint160(address(self)) & flag != 0;
    }
}

// node_modules/@uniswap/v4-periphery/src/utils/BaseHook.sol

/// @title Base Hook
/// @notice abstract contract for hook implementations
abstract contract BaseHook is IHooks, ImmutableState {
    error HookNotImplemented();

    constructor(IPoolManager _manager) ImmutableState(_manager) {
        validateHookAddress(this);
    }

    /// @notice Returns a struct of permissions to signal which hook functions are to be implemented
    /// @dev Used at deployment to validate the address correctly represents the expected permissions
    /// @return Permissions struct
    function getHookPermissions() public pure virtual returns (Hooks.Permissions memory);

    /// @notice Validates the deployed hook address agrees with the expected permissions of the hook
    /// @dev this function is virtual so that we can override it during testing,
    /// which allows us to deploy an implementation to any address
    /// and then etch the bytecode into the correct address
    function validateHookAddress(BaseHook _this) internal pure virtual {
        Hooks.validateHookPermissions(_this, getHookPermissions());
    }

    /// @inheritdoc IHooks
    function beforeInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96)
        external
        onlyPoolManager
        returns (bytes4)
    {
        return _beforeInitialize(sender, key, sqrtPriceX96);
    }

    function _beforeInitialize(address, PoolKey calldata, uint160) internal virtual returns (bytes4) {
        revert HookNotImplemented();
    }

    /// @inheritdoc IHooks
    function afterInitialize(address sender, PoolKey calldata key, uint160 sqrtPriceX96, int24 tick)
        external
        onlyPoolManager
        returns (bytes4)
    {
        return _afterInitialize(sender, key, sqrtPriceX96, tick);
    }

    function _afterInitialize(address, PoolKey calldata, uint160, int24) internal virtual returns (bytes4) {
        revert HookNotImplemented();
    }

    /// @inheritdoc IHooks
    function beforeAddLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        bytes calldata hookData
    ) external onlyPoolManager returns (bytes4) {
        return _beforeAddLiquidity(sender, key, params, hookData);
    }

    function _beforeAddLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        internal
        virtual
        returns (bytes4)
    {
        revert HookNotImplemented();
    }

    /// @inheritdoc IHooks
    function beforeRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        bytes calldata hookData
    ) external onlyPoolManager returns (bytes4) {
        return _beforeRemoveLiquidity(sender, key, params, hookData);
    }

    function _beforeRemoveLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        internal
        virtual
        returns (bytes4)
    {
        revert HookNotImplemented();
    }

    /// @inheritdoc IHooks
    function afterAddLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        BalanceDelta delta,
        BalanceDelta feesAccrued,
        bytes calldata hookData
    ) external onlyPoolManager returns (bytes4, BalanceDelta) {
        return _afterAddLiquidity(sender, key, params, delta, feesAccrued, hookData);
    }

    function _afterAddLiquidity(
        address,
        PoolKey calldata,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) internal virtual returns (bytes4, BalanceDelta) {
        revert HookNotImplemented();
    }

    /// @inheritdoc IHooks
    function afterRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        BalanceDelta delta,
        BalanceDelta feesAccrued,
        bytes calldata hookData
    ) external onlyPoolManager returns (bytes4, BalanceDelta) {
        return _afterRemoveLiquidity(sender, key, params, delta, feesAccrued, hookData);
    }

    function _afterRemoveLiquidity(
        address,
        PoolKey calldata,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) internal virtual returns (bytes4, BalanceDelta) {
        revert HookNotImplemented();
    }

    /// @inheritdoc IHooks
    function beforeSwap(address sender, PoolKey calldata key, SwapParams calldata params, bytes calldata hookData)
        external
        onlyPoolManager
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        return _beforeSwap(sender, key, params, hookData);
    }

    function _beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        internal
        virtual
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        revert HookNotImplemented();
    }

    /// @inheritdoc IHooks
    function afterSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata params,
        BalanceDelta delta,
        bytes calldata hookData
    ) external onlyPoolManager returns (bytes4, int128) {
        return _afterSwap(sender, key, params, delta, hookData);
    }

    function _afterSwap(address, PoolKey calldata, SwapParams calldata, BalanceDelta, bytes calldata)
        internal
        virtual
        returns (bytes4, int128)
    {
        revert HookNotImplemented();
    }

    /// @inheritdoc IHooks
    function beforeDonate(
        address sender,
        PoolKey calldata key,
        uint256 amount0,
        uint256 amount1,
        bytes calldata hookData
    ) external onlyPoolManager returns (bytes4) {
        return _beforeDonate(sender, key, amount0, amount1, hookData);
    }

    function _beforeDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        internal
        virtual
        returns (bytes4)
    {
        revert HookNotImplemented();
    }

    /// @inheritdoc IHooks
    function afterDonate(
        address sender,
        PoolKey calldata key,
        uint256 amount0,
        uint256 amount1,
        bytes calldata hookData
    ) external onlyPoolManager returns (bytes4) {
        return _afterDonate(sender, key, amount0, amount1, hookData);
    }

    function _afterDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        internal
        virtual
        returns (bytes4)
    {
        revert HookNotImplemented();
    }
}

// src/PrivacyHook.sol
// forge coverage: ignore-file

// Uniswap v4

// Fhenix FHE

// Local

/**
 * @title PrivacyHook
 * @notice Minimal Uniswap v4 hook + encrypted intent registry for the UHI7 Fhenix track.
 *         Demonstrates encrypted deposits, intent submission, and off-chain matched settlement
 *         without revealing direction/amounts on-chain. Hook callbacks are kept minimal; focus is
 *         on encrypted state handling for the hackathon.
 */
contract PrivacyHook is BaseHook {
    using FHE for uint256;

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------
    error NotRelayer();
    error NotUser();
    error InvalidAmount();

    // -------------------------------------------------------------------------
    // Types
    // -------------------------------------------------------------------------
    struct Intent {
        euint128 amount;   // encrypted amount
        ebool zeroForOne;  // encrypted direction (true = token0 -> token1)
        bool active;       // plaintext liveness flag
    }

    struct Residual {
        euint128 amount;   // encrypted residual amount to route
        ebool zeroForOne;  // encrypted direction
        bool exists;       // plaintext flag
    }

    // -------------------------------------------------------------------------
    // Immutable config
    // -------------------------------------------------------------------------
    address public immutable relayer;
    HybridFHERC20 public immutable token0;
    HybridFHERC20 public immutable token1;

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------
    mapping(address => Intent) public intents;
    mapping(address => Residual) public residuals; // Unmatched intent portions to route via AMM

    function isIntentActive(address user) external view returns (bool) {
        return intents[user].active;
    }

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    event Deposited(address indexed user, uint8 indexed tokenIndex, uint128 amount);
    event WithdrawRequested(address indexed user, uint8 indexed tokenIndex, euint128 encAmount);
    event Withdrawn(address indexed user, uint8 indexed tokenIndex, uint128 amount);
    event IntentSubmitted(address indexed user);
    event IntentCancelled(address indexed user);
    event IntentSettled(address indexed user, address indexed counterparty);
    event ResidualRouted(address indexed user, euint128 amount, bool zeroForOne);
    event SwapObserved(address indexed sender, PoolKey key, SwapParams params);
    event LiquidityObserved(address indexed sender, PoolKey key, ModifyLiquidityParams params, bool add);

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    constructor(
        IPoolManager _poolManager,
        address _relayer,
        HybridFHERC20 _token0,
        HybridFHERC20 _token1
    ) BaseHook(_poolManager) {
        relayer = _relayer;
        token0 = _token0;
        token1 = _token1;
    }

    // -------------------------------------------------------------------------
    // Hook permissions
    // -------------------------------------------------------------------------
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: true,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: true,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // Skip address flag validation for ease of deployment/testing.
    function validateHookAddress(BaseHook) internal pure override {}

    // -------------------------------------------------------------------------
    // User flows: deposit / withdraw
    // -------------------------------------------------------------------------
    function depositToken0(uint128 amount) external {
        _wrap(msg.sender, token0, amount, 0);
    }

    function depositToken1(uint128 amount) external {
        _wrap(msg.sender, token1, amount, 1);
    }

    function requestWithdrawToken0(InEuint128 calldata encAmount) external returns (euint128 burnHandle) {
        burnHandle = _requestUnwrap(msg.sender, token0, encAmount, 0);
    }

    function requestWithdrawToken1(InEuint128 calldata encAmount) external returns (euint128 burnHandle) {
        burnHandle = _requestUnwrap(msg.sender, token1, encAmount, 1);
    }

    function finalizeWithdrawToken0(euint128 burnHandle) external returns (uint128 amount) {
        amount = _finalizeUnwrap(msg.sender, token0, burnHandle, 0);
    }

    function finalizeWithdrawToken1(euint128 burnHandle) external returns (uint128 amount) {
        amount = _finalizeUnwrap(msg.sender, token1, burnHandle, 1);
    }

    // -------------------------------------------------------------------------
    // Intents
    // -------------------------------------------------------------------------
    function submitIntent(InEuint128 calldata amount, InEbool calldata zeroForOne) external {
        Intent storage intent = intents[msg.sender];
        intent.amount = FHE.asEuint128(amount);
        intent.zeroForOne = FHE.asEbool(zeroForOne);
        intent.active = true;

        // Grant relayer + hook permissions to use intent ciphertexts
        FHE.allow(intent.amount, relayer);
        FHE.allow(intent.amount, address(this));
        FHE.allow(intent.zeroForOne, relayer);
        FHE.allow(intent.zeroForOne, address(this));
        emit IntentSubmitted(msg.sender);
    }

    function cancelIntent() external {
        intents[msg.sender].active = false;
        emit IntentCancelled(msg.sender);
    }

    // -------------------------------------------------------------------------
    // Hook callbacks (Uniswap v4 integration)
    // -------------------------------------------------------------------------
    /// @notice beforeSwap hook: Routes residual unmatched intents through AMM.
    /// @dev Checks for residuals matching swap direction and routes them. This enables
    ///      net residual volume from intent matching to flow through the AMM.
    function _beforeSwap(
        address sender,
        PoolKey calldata key,
        SwapParams calldata params,
        bytes calldata /* hookData */
    ) internal override returns (bytes4, BeforeSwapDelta, uint24) {
        // Emit event for observability
        emit SwapObserved(sender, key, params);
        
        // Check if sender has a residual matching this swap direction
        BeforeSwapDelta delta = _routeResidualIfMatches(sender, key, params, toBeforeSwapDelta(0, 0));
        
        uint24 hookDataWord = 0;
        return (IHooks.beforeSwap.selector, delta, hookDataWord);
    }

    /// @notice afterSwap hook: Pass-through for normal AMM operations.
    /// @dev Returns zero unspecified delta. Direct AMM swaps complete normally.
    function _afterSwap(
        address, /* sender */
        PoolKey calldata,
        SwapParams calldata,
        BalanceDelta,
        bytes calldata /* hookData */
    ) internal override returns (bytes4, int128) {
        return (IHooks.afterSwap.selector, int128(0));
    }

    /// @notice beforeAddLiquidity hook: Observes liquidity additions.
    /// @dev Allows normal liquidity provision to proceed unchanged.
    function _beforeAddLiquidity(
        address, /* sender */
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        bytes calldata /* hookData */
    ) internal override returns (bytes4) {
        emit LiquidityObserved(msg.sender, key, params, true);
        return IHooks.beforeAddLiquidity.selector;
    }

    /// @notice afterRemoveLiquidity hook: Observes liquidity removals.
    /// @dev Allows normal liquidity withdrawal to proceed unchanged.
    function _afterRemoveLiquidity(
        address, /* sender */
        PoolKey calldata key,
        ModifyLiquidityParams calldata params,
        BalanceDelta,
        BalanceDelta,
        bytes calldata /* hookData */
    ) internal override returns (bytes4, BalanceDelta) {
        emit LiquidityObserved(msg.sender, key, params, false);
        // Return zero delta: no modification to liquidity removal
        return (IHooks.afterRemoveLiquidity.selector, toBalanceDelta(0, 0));
    }

    // -------------------------------------------------------------------------
    // Settlement (relayer-driven; matched off-chain)
    // -------------------------------------------------------------------------
    /// @notice Settles matched encrypted intents between two users.
    /// @dev The relayer matches intents off-chain using FHE permissions, then calls
    ///      this function to execute encrypted transfers. Matched legs settle internally
    ///      with zero fees/slippage. Any unmatched residual volume would need to be
    ///      routed through the AMM separately by the relayer.
    /// @param maker Address of the maker (first intent)
    /// @param taker Address of the taker (counter-intent, matched off-chain)
    /// @param matchedAmount Encrypted amount that was matched (both intents must have >= this)
    function settleMatched(
        address maker,
        address taker,
        InEuint128 calldata matchedAmount
    ) external {
        if (msg.sender != relayer) revert NotRelayer();
        Intent storage makerIntent = intents[maker];
        Intent storage takerIntent = intents[taker];

        euint128 amt = FHE.asEuint128(matchedAmount);
        euint128 zero = FHE.asEuint128(0);

        // Allow ciphertext use by hook + tokens involved in transfers
        FHE.allow(amt, address(this));
        FHE.allow(amt, address(token0));
        FHE.allow(amt, address(token1));
        FHE.allow(zero, address(this));
        FHE.allow(zero, address(token0));
        FHE.allow(zero, address(token1));
        FHE.allow(makerIntent.zeroForOne, address(token0));
        FHE.allow(makerIntent.zeroForOne, address(token1));
        FHE.allow(takerIntent.zeroForOne, address(token0));
        FHE.allow(takerIntent.zeroForOne, address(token1));
        FHE.allow(makerIntent.zeroForOne, address(this));
        FHE.allow(takerIntent.zeroForOne, address(this));

        // maker: zeroForOne ? send token0 receive token1 : send token1 receive token0
        euint128 makerSend0 = FHE.select(makerIntent.zeroForOne, amt, zero);
        euint128 makerSend1 = FHE.select(makerIntent.zeroForOne, zero, amt);

        // taker is the counter-direction (off-chain matched)
        euint128 takerSend0 = FHE.select(takerIntent.zeroForOne, amt, zero);
        euint128 takerSend1 = FHE.select(takerIntent.zeroForOne, zero, amt);

        // Allow derived ciphertexts for token contracts + hook
        FHE.allow(makerSend0, address(token0));
        FHE.allow(makerSend1, address(token1));
        FHE.allow(takerSend0, address(token0));
        FHE.allow(takerSend1, address(token1));
        FHE.allow(makerSend0, address(this));
        FHE.allow(makerSend1, address(this));
        FHE.allow(takerSend0, address(this));
        FHE.allow(takerSend1, address(this));

        // Transfers remain encrypted; no plaintext amounts emitted.
        // Note: transferFromEncrypted returns the actual amount transferred (may be less if insufficient balance)
        token0.transferFromEncrypted(maker, taker, makerSend0);
        token1.transferFromEncrypted(maker, taker, makerSend1);
        token0.transferFromEncrypted(taker, maker, takerSend0);
        token1.transferFromEncrypted(taker, maker, takerSend1);

        // Compute and store residuals (unmatched portions of intents)
        // residual = intent.amount - matchedAmount (if intent.amount > matchedAmount)
        euint128 makerResidual = _computeResidual(makerIntent.amount, amt);
        euint128 takerResidual = _computeResidual(takerIntent.amount, amt);

        // Store residuals if they exist (non-zero)
        _storeResidualIfExists(maker, makerResidual, makerIntent.zeroForOne);
        _storeResidualIfExists(taker, takerResidual, takerIntent.zeroForOne);

        makerIntent.active = false;
        takerIntent.active = false;

        emit IntentSettled(maker, taker);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------
    function _wrap(address user, HybridFHERC20 token, uint128 amount, uint8 tokenIndex) internal {
        if (msg.sender != user) revert NotUser();
        if (amount == 0) revert InvalidAmount();

        token.wrap(user, amount);
        emit Deposited(user, tokenIndex, amount);
    }

    function _requestUnwrap(
        address user,
        HybridFHERC20 token,
        InEuint128 calldata encAmount,
        uint8 tokenIndex
    ) internal returns (euint128 burnHandle) {
        if (msg.sender != user) revert NotUser();
        burnHandle = token.requestUnwrap(user, encAmount);
        emit WithdrawRequested(user, tokenIndex, burnHandle);
    }

    function _finalizeUnwrap(
        address user,
        HybridFHERC20 token,
        euint128 burnHandle,
        uint8 tokenIndex
    ) internal returns (uint128 amount) {
        if (msg.sender != user) revert NotUser();
        amount = token.getUnwrapResult(user, burnHandle);
        emit Withdrawn(user, tokenIndex, amount);
    }

    /// @notice Computes residual amount: intentAmount - matchedAmount (if intentAmount > matchedAmount)
    function _computeResidual(euint128 intentAmount, euint128 matchedAmount) internal returns (euint128) {
        euint128 zero = FHE.asEuint128(0);
        // If intentAmount > matchedAmount, residual = intentAmount - matchedAmount, else 0
        ebool hasResidual = intentAmount.gt(matchedAmount);
        euint128 diff = intentAmount.sub(matchedAmount);
        return FHE.select(hasResidual, diff, zero);
    }

    /// @notice Stores residual if it exists (non-zero)
    function _storeResidualIfExists(address user, euint128 residualAmount, ebool zeroForOne) internal {
        euint128 zero = FHE.asEuint128(0);
        ebool isNonZero = residualAmount.gt(zero);
        
        // Allow hook to access residual
        FHE.allow(residualAmount, address(this));
        FHE.allow(zeroForOne, address(this));
        
        // Store residual if non-zero
        Residual storage res = residuals[user];
        res.amount = FHE.select(isNonZero, residualAmount, zero);
        res.zeroForOne = zeroForOne;
        res.exists = true; // Set flag; actual routing will check amount > 0 via FHE
    }

    /// @notice Routes residual through AMM if it matches swap direction.
    /// @dev Checks if user has residual matching swap direction. In full implementation,
    ///      would unwrap encrypted residual and route through PoolManager. For now,
    ///      tracks residuals and emits events for observability.
    function _routeResidualIfMatches(
        address user,
        PoolKey calldata,
        SwapParams calldata params,
        BeforeSwapDelta currentDelta
    ) internal returns (BeforeSwapDelta) {
        Residual storage res = residuals[user];
        if (!res.exists) return currentDelta;

        // Check if residual direction matches swap direction using FHE
        // For zeroForOne swap: need zeroForOne residual
        // For oneForZero swap: need oneForZero residual (i.e., !zeroForOne)
        ebool directionMatches = params.zeroForOne 
            ? res.zeroForOne 
            : res.zeroForOne.not();

        euint128 zero = FHE.asEuint128(0);
        euint128 residualToRoute = FHE.select(directionMatches, res.amount, zero);

        // Allow hook to access residual for routing
        FHE.allow(residualToRoute, address(this));
        FHE.allow(directionMatches, address(this));

        // Emit event indicating residual would be routed
        // Note: Full implementation would:
        // 1. Unwrap residualToRoute from encrypted balance
        // 2. Call PoolManager.swap() with unwrapped amount
        // 3. Update swap delta to include residual
        // 4. Clear residual after routing
        emit ResidualRouted(user, residualToRoute, params.zeroForOne);

        // For hackathon: keep residual structure; full routing requires unwrap + PoolManager integration
        // Clear residual flag after attempting to route (actual clearing would happen after successful swap)
        // res.exists = false; // Would clear after successful routing

        return currentDelta; // Return unchanged delta for now; full impl would modify
    }
}
