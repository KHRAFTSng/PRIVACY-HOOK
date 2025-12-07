// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Uniswap v4
import {BaseHook} from "v4-periphery/src/utils/BaseHook.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";

// Fhenix FHE
import {
    FHE,
    InEuint128,
    InEbool,
    euint128,
    ebool
} from "@fhenixprotocol/cofhe-contracts/FHE.sol";

// Local
import {HybridFHERC20} from "./HybridFHERC20.sol";

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

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    event Deposited(address indexed user, uint8 indexed tokenIndex, uint128 amount);
    event WithdrawRequested(address indexed user, uint8 indexed tokenIndex, euint128 encAmount);
    event Withdrawn(address indexed user, uint8 indexed tokenIndex, uint128 amount);
    event IntentSubmitted(address indexed user);
    event IntentCancelled(address indexed user);
    event IntentSettled(address indexed user, address indexed counterparty);

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
    // Hook permissions (minimal for now; no automatic callbacks)
    // -------------------------------------------------------------------------
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: false,
            afterSwap: false,
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
    // Settlement (relayer-driven; matched off-chain)
    // -------------------------------------------------------------------------
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
}

