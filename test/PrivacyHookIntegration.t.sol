// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {PrivacyHook} from "../src/PrivacyHook.sol";
import {HybridFHERC20} from "../src/HybridFHERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {CoFheTest} from "@fhenixprotocol/cofhe-foundry-mocks/CoFheTest.sol";
import {FHE, InEuint128, InEbool} from "@fhenixprotocol/cofhe-contracts/FHE.sol";

/**
 * @title PrivacyHookIntegrationTest
 * @notice Integration tests for complete PrivacyHook workflows
 */
contract PrivacyHookIntegrationTest is Test {
    using FHE for uint256;

    PrivacyHook hook;
    HybridFHERC20 token0;
    HybridFHERC20 token1;
    CoFheTest cft;

    address relayer = address(0x1234);
    address userA = address(0xA);
    address userB = address(0xB);
    address userC = address(0xC);

    function setUp() public {
        cft = new CoFheTest(true);
        token0 = new HybridFHERC20("Token0", "T0");
        token1 = new HybridFHERC20("Token1", "T1");
        hook = new PrivacyHook(IPoolManager(address(0x1)), relayer, token0, token1);
    }

    // =========================================================================
    // Complete Flow Tests
    // =========================================================================

    function test_complete_flow_deposit_intent_settle() public {
        // Setup: Users mint tokens
        token0.mint(userA, 1000);
        token1.mint(userB, 1000);

        // Step 1: Users deposit
        vm.prank(userA);
        hook.depositToken0(500);

        vm.prank(userB);
        hook.depositToken1(500);

        // Verify deposits
        cft.assertHashValue(token0.encBalances(userA), 500);
        cft.assertHashValue(token1.encBalances(userB), 500);

        // Step 2: Users submit intents
        InEuint128 memory amtA = cft.createInEuint128(200, 0, userA);
        InEbool memory dirA = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA, dirA);

        InEuint128 memory amtB = cft.createInEuint128(200, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB, dirB);

        // Verify intents are active
        assertTrue(hook.isIntentActive(userA));
        assertTrue(hook.isIntentActive(userB));

        // Step 3: Relayer settles
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(200, 0, relayer));
        vm.stopPrank();

        // Verify intents are inactive
        assertFalse(hook.isIntentActive(userA));
        assertFalse(hook.isIntentActive(userB));

        // Verify balances after settlement
        cft.assertHashValue(token0.encBalances(userA), 300); // 500 - 200
        cft.assertHashValue(token1.encBalances(userA), 200); // 0 + 200
        cft.assertHashValue(token0.encBalances(userB), 200); // 0 + 200
        cft.assertHashValue(token1.encBalances(userB), 300); // 500 - 200
    }

    function test_complete_flow_with_multiple_rounds() public {
        token0.mint(userA, 1000);
        token1.mint(userB, 1000);

        // Round 1
        vm.prank(userA);
        hook.depositToken0(300);

        vm.prank(userB);
        hook.depositToken1(300);

        InEuint128 memory amtA1 = cft.createInEuint128(100, 0, userA);
        InEbool memory dirA1 = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA1, dirA1);

        InEuint128 memory amtB1 = cft.createInEuint128(100, 0, userB);
        InEbool memory dirB1 = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB1, dirB1);

        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(100, 0, relayer));
        vm.stopPrank();

        // Round 2
        InEuint128 memory amtA2 = cft.createInEuint128(150, 0, userA);
        InEbool memory dirA2 = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA2, dirA2);

        InEuint128 memory amtB2 = cft.createInEuint128(150, 0, userB);
        InEbool memory dirB2 = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB2, dirB2);

        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(150, 0, relayer));
        vm.stopPrank();

        // Verify final balances
        cft.assertHashValue(token0.encBalances(userA), 50); // 300 - 100 - 150
        cft.assertHashValue(token1.encBalances(userA), 250); // 0 + 100 + 150
        cft.assertHashValue(token0.encBalances(userB), 250); // 0 + 100 + 150
        cft.assertHashValue(token1.encBalances(userB), 50); // 300 - 100 - 150
    }

    function test_complete_flow_with_cancellation() public {
        token0.mint(userA, 1000);
        token1.mint(userB, 1000);

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

        // UserA cancels intent
        vm.prank(userA);
        hook.cancelIntent();

        assertFalse(hook.isIntentActive(userA));
        assertTrue(hook.isIntentActive(userB));

        // Relayer can still settle (though it won't match properly)
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(200, 0, relayer));
        vm.stopPrank();

        assertFalse(hook.isIntentActive(userA));
        assertFalse(hook.isIntentActive(userB));
    }

    function test_complete_flow_with_partial_settlement() public {
        token0.mint(userA, 1000);
        token1.mint(userB, 1000);

        vm.prank(userA);
        hook.depositToken0(500);

        vm.prank(userB);
        hook.depositToken1(500);

        InEuint128 memory amtA = cft.createInEuint128(400, 0, userA);
        InEbool memory dirA = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA, dirA);

        InEuint128 memory amtB = cft.createInEuint128(400, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB, dirB);

        // Partial settlement
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(250, 0, relayer));
        vm.stopPrank();

        // Verify balances
        cft.assertHashValue(token0.encBalances(userA), 250); // 500 - 250
        cft.assertHashValue(token1.encBalances(userA), 250); // 0 + 250
        cft.assertHashValue(token0.encBalances(userB), 250); // 0 + 250
        cft.assertHashValue(token1.encBalances(userB), 250); // 500 - 250

        // Verify residuals exist
        (,, bool existsA) = hook.residuals(userA);
        (,, bool existsB) = hook.residuals(userB);
        assertTrue(existsA);
        assertTrue(existsB);
    }

    // =========================================================================
    // Multi-User Integration Tests
    // =========================================================================

    function test_multi_user_parallel_intents() public {
        token0.mint(userA, 1000);
        token1.mint(userB, 1000);
        token0.mint(userC, 1000);
        token1.mint(userC, 1000);

        // UserA and UserB deposit
        vm.prank(userA);
        hook.depositToken0(300);

        vm.prank(userB);
        hook.depositToken1(300);

        // UserC deposits both
        vm.prank(userC);
        hook.depositToken0(200);
        vm.prank(userC);
        hook.depositToken1(200);

        // Submit intents
        InEuint128 memory amtA = cft.createInEuint128(100, 0, userA);
        InEbool memory dirA = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA, dirA);

        InEuint128 memory amtB = cft.createInEuint128(100, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB, dirB);

        // Settle A and B
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(100, 0, relayer));
        vm.stopPrank();

        // UserC should be unaffected
        cft.assertHashValue(token0.encBalances(userC), 200);
        cft.assertHashValue(token1.encBalances(userC), 200);
    }

    function test_multi_user_sequential_settlements() public {
        token0.mint(userA, 1000);
        token1.mint(userB, 1000);
        token0.mint(userC, 1000);
        token1.mint(userC, 1000);

        // All users deposit
        vm.prank(userA);
        hook.depositToken0(300);

        vm.prank(userB);
        hook.depositToken1(300);

        vm.prank(userC);
        hook.depositToken0(200);
        vm.prank(userC);
        hook.depositToken1(200);

        // UserA and UserB submit and settle
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

        // UserC and UserA submit and settle
        InEuint128 memory amtC = cft.createInEuint128(50, 0, userC);
        InEbool memory dirC = cft.createInEbool(true, 0, userC);

        vm.prank(userC);
        hook.submitIntent(amtC, dirC);

        InEuint128 memory amtA2 = cft.createInEuint128(50, 0, userA);
        InEbool memory dirA2 = cft.createInEbool(false, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA2, dirA2);

        vm.startPrank(relayer);
        hook.settleMatched(userC, userA, cft.createInEuint128(50, 0, relayer));
        vm.stopPrank();

        // Verify final balances
        // UserA: started with 300 token0, 0 token1
        // First settlement: traded 100 token0 for 100 token1 → 200 token0, 100 token1
        // Second settlement: traded 50 token1 for 50 token0 → 250 token0, 50 token1
        cft.assertHashValue(token0.encBalances(userA), 250); // 300 - 100 + 50
        cft.assertHashValue(token1.encBalances(userA), 50); // 0 + 100 - 50
        cft.assertHashValue(token0.encBalances(userC), 150); // 200 - 50
        cft.assertHashValue(token1.encBalances(userC), 250); // 200 + 50
    }

    // =========================================================================
    // Edge Case Integration Tests
    // =========================================================================

    function test_integration_zero_amount_settlement() public {
        token0.mint(userA, 1000);
        token1.mint(userB, 1000);

        vm.prank(userA);
        hook.depositToken0(500);

        vm.prank(userB);
        hook.depositToken1(500);

        InEuint128 memory amtA = cft.createInEuint128(100, 0, userA);
        InEbool memory dirA = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA, dirA);

        InEuint128 memory amtB = cft.createInEuint128(100, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB, dirB);

        // Settle with zero amount
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(0, 0, relayer));
        vm.stopPrank();

        // Intents should be inactive
        assertFalse(hook.isIntentActive(userA));
        assertFalse(hook.isIntentActive(userB));

        // Balances should be unchanged
        cft.assertHashValue(token0.encBalances(userA), 500);
        cft.assertHashValue(token1.encBalances(userB), 500);
    }

    function test_integration_overwrite_intent_then_settle() public {
        token0.mint(userA, 1000);
        token1.mint(userB, 1000);

        vm.prank(userA);
        hook.depositToken0(500);

        vm.prank(userB);
        hook.depositToken1(500);

        // Submit first intent
        InEuint128 memory amtA1 = cft.createInEuint128(100, 0, userA);
        InEbool memory dirA1 = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA1, dirA1);

        // Overwrite with new intent
        InEuint128 memory amtA2 = cft.createInEuint128(200, 0, userA);
        InEbool memory dirA2 = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA2, dirA2);

        InEuint128 memory amtB = cft.createInEuint128(200, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB, dirB);

        // Settle with new intent amount
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(200, 0, relayer));
        vm.stopPrank();

        // Verify balances reflect new intent
        cft.assertHashValue(token0.encBalances(userA), 300); // 500 - 200
        cft.assertHashValue(token1.encBalances(userA), 200); // 0 + 200
    }
}

