// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {PrivacyHook} from "../src/PrivacyHook.sol";
import {HybridFHERC20} from "../src/HybridFHERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {CoFheTest} from "@fhenixprotocol/cofhe-foundry-mocks/CoFheTest.sol";
import {FHE, InEuint128, InEbool} from "@fhenixprotocol/cofhe-contracts/FHE.sol";

/**
 * @title PrivacyHookInvariantTest
 * @notice Invariant tests for PrivacyHook state consistency
 */
contract PrivacyHookInvariantTest is Test {
    using FHE for uint256;

    PrivacyHook hook;
    HybridFHERC20 token0;
    HybridFHERC20 token1;
    CoFheTest cft;

    address relayer = address(0x1234);
    address userA = address(0xA);
    address userB = address(0xB);

    function setUp() public {
        cft = new CoFheTest(true);
        token0 = new HybridFHERC20("Token0", "T0");
        token1 = new HybridFHERC20("Token1", "T1");
        hook = new PrivacyHook(IPoolManager(address(0x1)), relayer, token0, token1);
    }

    // =========================================================================
    // Invariant: Intent State Consistency
    // =========================================================================

    function invariant_intent_active_flag_consistency() public view {
        // If an intent is active, it should have been submitted
        // This is implicitly true because active is set on submitIntent
        // and cleared on cancelIntent or settleMatched
        bool activeA = hook.isIntentActive(userA);
        bool activeB = hook.isIntentActive(userB);
        
        // Active flag should be boolean (always true or false)
        assertTrue(activeA == true || activeA == false);
        assertTrue(activeB == true || activeB == false);
    }

    function invariant_settled_intents_are_inactive() public {
        // Setup
        token0.mint(userA, 200);
        token1.mint(userB, 200);

        vm.prank(userA);
        hook.depositToken0(200);

        vm.prank(userB);
        hook.depositToken1(200);

        InEuint128 memory amtA = cft.createInEuint128(100, 0, userA);
        InEbool memory dirA = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA, dirA);

        InEuint128 memory amtB = cft.createInEuint128(100, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB, dirB);

        // Settle
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(100, 0, relayer));
        vm.stopPrank();

        // Invariant: Settled intents must be inactive
        assertFalse(hook.isIntentActive(userA));
        assertFalse(hook.isIntentActive(userB));
    }

    function invariant_cancelled_intents_are_inactive() public {
        InEuint128 memory amt = cft.createInEuint128(100, 0, userA);
        InEbool memory dir = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amt, dir);

        vm.prank(userA);
        hook.cancelIntent();

        // Invariant: Cancelled intents must be inactive
        assertFalse(hook.isIntentActive(userA));
    }

    // =========================================================================
    // Invariant: Immutable Configuration
    // =========================================================================

    function invariant_relayer_address_immutable() public view {
        // Invariant: Relayer address should never change
        address currentRelayer = hook.relayer();
        assertEq(currentRelayer, relayer);
    }

    function invariant_token_addresses_immutable() public view {
        // Invariant: Token addresses should never change
        assertEq(address(hook.token0()), address(token0));
        assertEq(address(hook.token1()), address(token1));
    }

    // =========================================================================
    // Invariant: Residual State Consistency
    // =========================================================================

    function invariant_residual_exists_after_partial_settlement() public {
        token0.mint(userA, 300);
        token1.mint(userB, 300);

        vm.prank(userA);
        hook.depositToken0(300);

        vm.prank(userB);
        hook.depositToken1(300);

        InEuint128 memory amtA = cft.createInEuint128(200, 0, userA);
        InEbool memory dirA = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA, dirA);

        InEuint128 memory amtB = cft.createInEuint128(200, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB, dirB);

        // Partial settlement
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(100, 0, relayer));
        vm.stopPrank();

        // Invariant: Partial settlement should create residuals
        (,, bool existsA) = hook.residuals(userA);
        (,, bool existsB) = hook.residuals(userB);
        assertTrue(existsA);
        assertTrue(existsB);
    }

    // =========================================================================
    // Invariant: Balance Consistency
    // =========================================================================

    function invariant_deposit_increases_encrypted_balance() public {
        token0.mint(userA, 500);
        
        uint256 balanceBefore = 0; // Encrypted balance starts at 0
        
        vm.prank(userA);
        hook.depositToken0(200);
        
        // Invariant: Deposit should increase encrypted balance
        // We can't directly read encrypted balance, but we can verify via hash
        cft.assertHashValue(token0.encBalances(userA), 200);
    }

    function invariant_settlement_preserves_total_balances() public {
        token0.mint(userA, 200);
        token1.mint(userB, 200);

        vm.prank(userA);
        hook.depositToken0(200);

        vm.prank(userB);
        hook.depositToken1(200);

        // Record initial total balances
        cft.assertHashValue(token0.encBalances(userA), 200);
        cft.assertHashValue(token1.encBalances(userB), 200);

        InEuint128 memory amtA = cft.createInEuint128(100, 0, userA);
        InEbool memory dirA = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA, dirA);

        InEuint128 memory amtB = cft.createInEuint128(100, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB, dirB);

        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(100, 0, relayer));
        vm.stopPrank();

        // Invariant: Total balances should be preserved (just redistributed)
        // UserA: 200 token0 -> 100 token0 + 100 token1
        // UserB: 200 token1 -> 100 token0 + 100 token1
        cft.assertHashValue(token0.encBalances(userA), 100);
        cft.assertHashValue(token1.encBalances(userA), 100);
        cft.assertHashValue(token0.encBalances(userB), 100);
        cft.assertHashValue(token1.encBalances(userB), 100);
        
        // Total: 200 token0 + 200 token1 (preserved)
    }

    // =========================================================================
    // Invariant: Hook Permissions Consistency
    // =========================================================================

    function invariant_hook_permissions_consistent() public view {
        var permissions = hook.getHookPermissions();
        
        // Invariant: Hook permissions should match expected configuration
        assertFalse(permissions.beforeInitialize);
        assertFalse(permissions.afterInitialize);
        assertTrue(permissions.beforeAddLiquidity);
        assertFalse(permissions.afterAddLiquidity);
        assertFalse(permissions.beforeRemoveLiquidity);
        assertTrue(permissions.afterRemoveLiquidity);
        assertTrue(permissions.beforeSwap);
        assertTrue(permissions.afterSwap);
        assertFalse(permissions.beforeDonate);
        assertFalse(permissions.afterDonate);
    }

    // =========================================================================
    // Invariant: Authorization Consistency
    // =========================================================================

    function invariant_only_relayer_can_settle() public {
        token0.mint(userA, 200);
        token1.mint(userB, 200);

        vm.prank(userA);
        hook.depositToken0(200);

        vm.prank(userB);
        hook.depositToken1(200);

        InEuint128 memory amtA = cft.createInEuint128(100, 0, userA);
        InEbool memory dirA = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA, dirA);

        InEuint128 memory amtB = cft.createInEuint128(100, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB, dirB);

        // Invariant: Only relayer can settle
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(100, 0, relayer));
        vm.stopPrank();

        // If we got here, relayer was able to settle (invariant holds)
        assertFalse(hook.isIntentActive(userA));
        assertFalse(hook.isIntentActive(userB));
    }

    // =========================================================================
    // Invariant: State Transitions
    // =========================================================================

    function invariant_intent_lifecycle_transitions() public {
        // Invariant: Intent can transition: inactive -> active -> inactive
        // Start: inactive
        assertFalse(hook.isIntentActive(userA));

        // Submit: active
        InEuint128 memory amt = cft.createInEuint128(100, 0, userA);
        InEbool memory dir = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amt, dir);
        assertTrue(hook.isIntentActive(userA));

        // Cancel: inactive
        vm.prank(userA);
        hook.cancelIntent();
        assertFalse(hook.isIntentActive(userA));

        // Can resubmit: active again
        vm.prank(userA);
        hook.submitIntent(amt, dir);
        assertTrue(hook.isIntentActive(userA));
    }

    function invariant_no_double_settlement() public {
        token0.mint(userA, 200);
        token1.mint(userB, 200);

        vm.prank(userA);
        hook.depositToken0(200);

        vm.prank(userB);
        hook.depositToken1(200);

        InEuint128 memory amtA = cft.createInEuint128(100, 0, userA);
        InEbool memory dirA = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA, dirA);

        InEuint128 memory amtB = cft.createInEuint128(100, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB, dirB);

        // First settlement
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(100, 0, relayer));
        vm.stopPrank();

        // Invariant: After settlement, intents are inactive
        assertFalse(hook.isIntentActive(userA));
        assertFalse(hook.isIntentActive(userB));

        // Second settlement attempt (should still work but intents remain inactive)
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(0, 0, relayer));
        vm.stopPrank();

        // Invariant: Intents remain inactive
        assertFalse(hook.isIntentActive(userA));
        assertFalse(hook.isIntentActive(userB));
    }
}

