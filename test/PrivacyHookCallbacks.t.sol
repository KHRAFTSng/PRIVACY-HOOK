// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {PrivacyHook} from "../src/PrivacyHook.sol";
import {HybridFHERC20} from "../src/HybridFHERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {SwapParams, ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {BalanceDelta, toBalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {CoFheTest} from "@fhenixprotocol/cofhe-foundry-mocks/CoFheTest.sol";
import {FHE, InEuint128, InEbool} from "@fhenixprotocol/cofhe-contracts/FHE.sol";

/**
 * @title PrivacyHookCallbacksTest
 * @notice Tests for Uniswap v4 hook callbacks
 */
contract PrivacyHookCallbacksTest is Test {
    using FHE for uint256;

    PrivacyHook hook;
    HybridFHERC20 token0;
    HybridFHERC20 token1;
    CoFheTest cft;
    IPoolManager poolManager;

    address relayer = address(0x1234);
    address userA = address(0xA);
    address userB = address(0xB);
    address constant TM_ADMIN = address(128);

    function setUp() public {
        cft = new CoFheTest(true);
        token0 = new HybridFHERC20("Token0", "T0");
        token1 = new HybridFHERC20("Token1", "T1");
        poolManager = IPoolManager(address(0x1));
        hook = new PrivacyHook(poolManager, relayer, token0, token1);

        // Disable verifier signer to avoid InvalidSigner during FHE operations in tests
        vm.startPrank(TM_ADMIN);
        cft.taskManager().setVerifierSigner(address(0));
        vm.stopPrank();
    }

    // =========================================================================
    // beforeSwap Hook Tests
    // =========================================================================

    function test_beforeSwap_emits_SwapObserved() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: 100,
            sqrtPriceLimitX96: 0
        });

        vm.expectEmit(true, false, false, false, address(hook));
        emit PrivacyHook.SwapObserved(userA, key, params);

        // Call the hook's beforeSwap function directly
        vm.prank(address(poolManager));
        hook.beforeSwap(userA, key, params, "");
    }

    function test_beforeSwap_zeroForOne_swap() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: 100,
            sqrtPriceLimitX96: 0
        });

        vm.prank(address(poolManager));
        hook.beforeSwap(userA, key, params, "");
    }

    function test_beforeSwap_oneForZero_swap() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        SwapParams memory params = SwapParams({
            zeroForOne: false,
            amountSpecified: 100,
            sqrtPriceLimitX96: 0
        });

        vm.prank(address(poolManager));
        hook.beforeSwap(userA, key, params, "");
    }

    function test_beforeSwap_with_residual() public {
        // Setup: Create a residual for userA
        token0.mint(userA, 500);
        token1.mint(userB, 500);

        vm.prank(userA);
        hook.depositToken0(500);
        vm.prank(userB);
        hook.depositToken1(500);

        InEuint128 memory amtA = cft.createInEuint128(200, 0, userA);
        InEbool memory dirA = cft.createInEbool(true, 0, userA);
        vm.prank(userA);
        hook.submitIntent(amtA, dirA);

        InEuint128 memory amtB = cft.createInEuint128(200, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);
        vm.prank(userB);
        hook.submitIntent(amtB, dirB);

        // Partial settlement creates residual
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(100, 0, relayer));
        vm.stopPrank();

        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        SwapParams memory params = SwapParams({
            zeroForOne: true, // Matches userA's residual direction
            amountSpecified: 100,
            sqrtPriceLimitX96: 0
        });

        vm.prank(address(poolManager));
        hook.beforeSwap(userA, key, params, "");
    }

    function test_beforeSwap_without_residual() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: 100,
            sqrtPriceLimitX96: 0
        });

        // Should not emit ResidualRouted
        vm.prank(address(poolManager));
        hook.beforeSwap(userA, key, params, "");
    }

    // =========================================================================
    // afterSwap Hook Tests
    // =========================================================================

    function test_afterSwap_returns_zero_delta() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: 100,
            sqrtPriceLimitX96: 0
        });

        BalanceDelta delta = toBalanceDelta(100, -50);

        vm.prank(address(poolManager));
        (bytes4 selector, int128 returnDelta) = hook.afterSwap(userA, key, params, delta, "");

        assertEq(selector, hook.afterSwap.selector);
        assertEq(returnDelta, int128(0));
    }

    function test_afterSwap_preserves_original_delta() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        SwapParams memory params = SwapParams({
            zeroForOne: false,
            amountSpecified: 200,
            sqrtPriceLimitX96: 0
        });

        BalanceDelta delta = toBalanceDelta(-150, 200);

        vm.prank(address(poolManager));
        (bytes4 selector, int128 returnDelta) = hook.afterSwap(userA, key, params, delta, "");

        assertEq(selector, hook.afterSwap.selector);
        assertEq(returnDelta, int128(0)); // Hook returns zero, doesn't modify
    }

    // =========================================================================
    // beforeAddLiquidity Hook Tests
    // =========================================================================

    function test_beforeAddLiquidity_emits_LiquidityObserved() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        ModifyLiquidityParams memory params = ModifyLiquidityParams({
            tickLower: -100,
            tickUpper: 100,
            liquidityDelta: 1000,
            salt: bytes32(0)
        });

        vm.expectEmit(true, false, false, false, address(hook));
        emit PrivacyHook.LiquidityObserved(address(poolManager), key, params, true);

        vm.prank(address(poolManager));
        bytes4 selector = hook.beforeAddLiquidity(userA, key, params, "");

        assertEq(selector, hook.beforeAddLiquidity.selector);
    }

    function test_beforeAddLiquidity_allows_normal_operation() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        ModifyLiquidityParams memory params = ModifyLiquidityParams({
            tickLower: -200,
            tickUpper: 200,
            liquidityDelta: 5000,
            salt: bytes32(uint256(123))
        });

        vm.prank(address(poolManager));
        bytes4 selector = hook.beforeAddLiquidity(userA, key, params, "");

        assertEq(selector, hook.beforeAddLiquidity.selector);
    }

    // =========================================================================
    // afterRemoveLiquidity Hook Tests
    // =========================================================================

    function test_afterRemoveLiquidity_emits_LiquidityObserved() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        ModifyLiquidityParams memory params = ModifyLiquidityParams({
            tickLower: -100,
            tickUpper: 100,
            liquidityDelta: -1000,
            salt: bytes32(0)
        });

        BalanceDelta delta = toBalanceDelta(50, 30);

        vm.expectEmit(true, false, false, false, address(hook));
        emit PrivacyHook.LiquidityObserved(address(poolManager), key, params, false);

        vm.prank(address(poolManager));
        (bytes4 selector, BalanceDelta returnDelta) = hook.afterRemoveLiquidity(userA, key, params, delta, delta, "");

        assertEq(selector, hook.afterRemoveLiquidity.selector);
        assertEq(returnDelta.amount0(), 0);
        assertEq(returnDelta.amount1(), 0);
    }

    function test_afterRemoveLiquidity_returns_zero_delta() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        ModifyLiquidityParams memory params = ModifyLiquidityParams({
            tickLower: -200,
            tickUpper: 200,
            liquidityDelta: -5000,
            salt: bytes32(uint256(456))
        });

        BalanceDelta delta = toBalanceDelta(200, 150);

        vm.prank(address(poolManager));
        (bytes4 selector, BalanceDelta returnDelta) = hook.afterRemoveLiquidity(userA, key, params, delta, delta, "");

        assertEq(selector, hook.afterRemoveLiquidity.selector);
        // Hook returns zero delta, doesn't modify liquidity removal
        assertEq(returnDelta.amount0(), 0);
        assertEq(returnDelta.amount1(), 0);
    }

    // =========================================================================
    // Hook Selector Tests
    // =========================================================================

    function test_beforeSwap_returns_correct_selector() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        SwapParams memory params = SwapParams({
            zeroForOne: true,
            amountSpecified: 100,
            sqrtPriceLimitX96: 0
        });

        vm.prank(address(poolManager));
        (bytes4 selector,,) = hook.beforeSwap(userA, key, params, "");

        assertEq(selector, hook.beforeSwap.selector);
    }

    function test_beforeAddLiquidity_returns_correct_selector() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        ModifyLiquidityParams memory params = ModifyLiquidityParams({
            tickLower: -100,
            tickUpper: 100,
            liquidityDelta: 1000,
            salt: bytes32(0)
        });

        vm.prank(address(poolManager));
        bytes4 selector = hook.beforeAddLiquidity(userA, key, params, "");

        assertEq(selector, hook.beforeAddLiquidity.selector);
    }

    function test_afterRemoveLiquidity_returns_correct_selector() public {
        PoolKey memory key = PoolKey({
            currency0: Currency.wrap(address(token0)),
            currency1: Currency.wrap(address(token1)),
            fee: 3000,
            tickSpacing: 60,
            hooks: hook
        });

        ModifyLiquidityParams memory params = ModifyLiquidityParams({
            tickLower: -100,
            tickUpper: 100,
            liquidityDelta: -1000,
            salt: bytes32(0)
        });

        BalanceDelta delta = toBalanceDelta(50, 30);

        vm.prank(address(poolManager));
        (bytes4 selector,) = hook.afterRemoveLiquidity(userA, key, params, delta, delta, "");

        assertEq(selector, hook.afterRemoveLiquidity.selector);
    }
}

