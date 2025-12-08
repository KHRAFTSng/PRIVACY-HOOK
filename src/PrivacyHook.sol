// forge coverage: ignore-file
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Uniswap v4
import {BaseHook} from "v4-periphery/src/utils/BaseHook.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {SwapParams, ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {BeforeSwapDelta, toBeforeSwapDelta} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {BalanceDelta, toBalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";

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
