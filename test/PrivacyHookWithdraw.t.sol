// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {PrivacyHook} from "../src/PrivacyHook.sol";
import {HybridFHERC20} from "../src/HybridFHERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {CoFheTest} from "@fhenixprotocol/cofhe-foundry-mocks/CoFheTest.sol";
import {FHE, InEuint128, InEbool, euint128} from "@fhenixprotocol/cofhe-contracts/FHE.sol";

/**
 * @title PrivacyHookWithdrawTest
 * @notice Comprehensive tests for withdraw functionality
 */
contract PrivacyHookWithdrawTest is Test {
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
    // requestWithdrawToken0 Tests
    // =========================================================================

    function test_requestWithdrawToken0_success() public {
        token0.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken0(500);

        InEuint128 memory encAmount = cft.createInEuint128(100, 0, userA);
        
        vm.expectEmit(true, false, false, false);
        emit PrivacyHook.WithdrawRequested(userA, 0, euint128(0)); // burnHandle is encrypted

        vm.prank(userA);
        euint128 burnHandle = hook.requestWithdrawToken0(encAmount);

        // Verify burn handle was returned (encrypted value)
        assertTrue(uint256(burnHandle) != 0);
    }

    function test_requestWithdrawToken0_multiple_requests() public {
        token0.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken0(500);

        InEuint128 memory encAmount1 = cft.createInEuint128(100, 0, userA);
        vm.prank(userA);
        euint128 burnHandle1 = hook.requestWithdrawToken0(encAmount1);

        InEuint128 memory encAmount2 = cft.createInEuint128(50, 0, userA);
        vm.prank(userA);
        euint128 burnHandle2 = hook.requestWithdrawToken0(encAmount2);

        // Both handles should be different
        assertTrue(uint256(burnHandle1) != uint256(burnHandle2));
    }

    function test_requestWithdrawToken0_wrong_sender_reverts() public {
        token0.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken0(500);

        InEuint128 memory encAmount = cft.createInEuint128(100, 0, userA);
        
        vm.expectRevert(PrivacyHook.NotUser.selector);
        hook.requestWithdrawToken0(encAmount); // Called by test contract, not userA
    }

    function test_requestWithdrawToken0_emits_event() public {
        token0.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken0(500);

        InEuint128 memory encAmount = cft.createInEuint128(100, 0, userA);
        
        vm.expectEmit(true, false, false, false);
        emit PrivacyHook.WithdrawRequested(userA, 0, euint128(0));

        vm.prank(userA);
        hook.requestWithdrawToken0(encAmount);
    }

    // =========================================================================
    // requestWithdrawToken1 Tests
    // =========================================================================

    function test_requestWithdrawToken1_success() public {
        token1.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken1(500);

        InEuint128 memory encAmount = cft.createInEuint128(100, 0, userA);
        
        vm.expectEmit(true, false, false, false);
        emit PrivacyHook.WithdrawRequested(userA, 1, euint128(0));

        vm.prank(userA);
        euint128 burnHandle = hook.requestWithdrawToken1(encAmount);

        assertTrue(uint256(burnHandle) != 0);
    }

    function test_requestWithdrawToken1_multiple_requests() public {
        token1.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken1(500);

        InEuint128 memory encAmount1 = cft.createInEuint128(100, 0, userA);
        vm.prank(userA);
        euint128 burnHandle1 = hook.requestWithdrawToken1(encAmount1);

        InEuint128 memory encAmount2 = cft.createInEuint128(50, 0, userA);
        vm.prank(userA);
        euint128 burnHandle2 = hook.requestWithdrawToken1(encAmount2);

        assertTrue(uint256(burnHandle1) != uint256(burnHandle2));
    }

    function test_requestWithdrawToken1_wrong_sender_reverts() public {
        token1.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken1(500);

        InEuint128 memory encAmount = cft.createInEuint128(100, 0, userA);
        
        vm.expectRevert(PrivacyHook.NotUser.selector);
        hook.requestWithdrawToken1(encAmount);
    }

    function test_requestWithdrawToken1_emits_event() public {
        token1.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken1(500);

        InEuint128 memory encAmount = cft.createInEuint128(100, 0, userA);
        
        vm.expectEmit(true, false, false, false);
        emit PrivacyHook.WithdrawRequested(userA, 1, euint128(0));

        vm.prank(userA);
        hook.requestWithdrawToken1(encAmount);
    }

    // =========================================================================
    // finalizeWithdrawToken0 Tests
    // =========================================================================

    function test_finalizeWithdrawToken0_success() public {
        token0.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken0(500);

        InEuint128 memory encAmount = cft.createInEuint128(100, 0, userA);
        vm.prank(userA);
        euint128 burnHandle = hook.requestWithdrawToken0(encAmount);

        // Wait for decryption
        vm.warp(block.timestamp + 11);

        vm.expectEmit(true, false, false, false);
        emit PrivacyHook.Withdrawn(userA, 0, 100);

        vm.prank(userA);
        uint128 amount = hook.finalizeWithdrawToken0(burnHandle);

        assertEq(amount, 100);
    }

    function test_finalizeWithdrawToken0_wrong_sender_reverts() public {
        token0.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken0(500);

        InEuint128 memory encAmount = cft.createInEuint128(100, 0, userA);
        vm.prank(userA);
        euint128 burnHandle = hook.requestWithdrawToken0(encAmount);

        vm.expectRevert(PrivacyHook.NotUser.selector);
        hook.finalizeWithdrawToken0(burnHandle); // Called by test contract
    }

    function test_finalizeWithdrawToken0_emits_event() public {
        token0.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken0(500);

        InEuint128 memory encAmount = cft.createInEuint128(100, 0, userA);
        vm.prank(userA);
        euint128 burnHandle = hook.requestWithdrawToken0(encAmount);

        // Wait for decryption
        vm.warp(block.timestamp + 11);

        vm.expectEmit(true, false, false, false);
        emit PrivacyHook.Withdrawn(userA, 0, 100);

        vm.prank(userA);
        hook.finalizeWithdrawToken0(burnHandle);
    }

    function test_finalizeWithdrawToken0_multiple_withdraws() public {
        token0.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken0(500);

        InEuint128 memory encAmount1 = cft.createInEuint128(100, 0, userA);
        vm.prank(userA);
        euint128 burnHandle1 = hook.requestWithdrawToken0(encAmount1);
        vm.warp(block.timestamp + 11);
        vm.prank(userA);
        uint128 amount1 = hook.finalizeWithdrawToken0(burnHandle1);
        assertEq(amount1, 100);

        InEuint128 memory encAmount2 = cft.createInEuint128(50, 0, userA);
        vm.prank(userA);
        euint128 burnHandle2 = hook.requestWithdrawToken0(encAmount2);
        vm.warp(block.timestamp + 11);
        vm.prank(userA);
        uint128 amount2 = hook.finalizeWithdrawToken0(burnHandle2);
        assertEq(amount2, 50);
    }

    // =========================================================================
    // finalizeWithdrawToken1 Tests
    // =========================================================================

    function test_finalizeWithdrawToken1_success() public {
        token1.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken1(500);

        InEuint128 memory encAmount = cft.createInEuint128(100, 0, userA);
        vm.prank(userA);
        euint128 burnHandle = hook.requestWithdrawToken1(encAmount);

        // Wait for decryption
        vm.warp(block.timestamp + 11);

        vm.expectEmit(true, false, false, false);
        emit PrivacyHook.Withdrawn(userA, 1, 100);

        vm.prank(userA);
        uint128 amount = hook.finalizeWithdrawToken1(burnHandle);

        assertEq(amount, 100);
    }

    function test_finalizeWithdrawToken1_wrong_sender_reverts() public {
        token1.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken1(500);

        InEuint128 memory encAmount = cft.createInEuint128(100, 0, userA);
        vm.prank(userA);
        euint128 burnHandle = hook.requestWithdrawToken1(encAmount);

        vm.expectRevert(PrivacyHook.NotUser.selector);
        hook.finalizeWithdrawToken1(burnHandle);
    }

    function test_finalizeWithdrawToken1_emits_event() public {
        token1.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken1(500);

        InEuint128 memory encAmount = cft.createInEuint128(100, 0, userA);
        vm.prank(userA);
        euint128 burnHandle = hook.requestWithdrawToken1(encAmount);

        // Wait for decryption
        vm.warp(block.timestamp + 11);

        vm.expectEmit(true, false, false, false);
        emit PrivacyHook.Withdrawn(userA, 1, 100);

        vm.prank(userA);
        hook.finalizeWithdrawToken1(burnHandle);
    }

    function test_finalizeWithdrawToken1_multiple_withdraws() public {
        token1.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken1(500);

        InEuint128 memory encAmount1 = cft.createInEuint128(100, 0, userA);
        vm.prank(userA);
        euint128 burnHandle1 = hook.requestWithdrawToken1(encAmount1);
        vm.warp(block.timestamp + 11);
        vm.prank(userA);
        uint128 amount1 = hook.finalizeWithdrawToken1(burnHandle1);
        assertEq(amount1, 100);

        InEuint128 memory encAmount2 = cft.createInEuint128(50, 0, userA);
        vm.prank(userA);
        euint128 burnHandle2 = hook.requestWithdrawToken1(encAmount2);
        vm.warp(block.timestamp + 11);
        vm.prank(userA);
        uint128 amount2 = hook.finalizeWithdrawToken1(burnHandle2);
        assertEq(amount2, 50);
    }

    // =========================================================================
    // Complete Withdraw Flow Tests
    // =========================================================================

    function test_complete_withdraw_flow_token0() public {
        token0.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken0(500);

        // Request withdraw
        InEuint128 memory encAmount = cft.createInEuint128(200, 0, userA);
        vm.prank(userA);
        euint128 burnHandle = hook.requestWithdrawToken0(encAmount);

        // Wait for decryption
        vm.warp(block.timestamp + 11);

        // Finalize withdraw
        vm.prank(userA);
        uint128 amount = hook.finalizeWithdrawToken0(burnHandle);

        assertEq(amount, 200);
        // Encrypted balance should be reduced
        cft.assertHashValue(token0.encBalances(userA), 300);
    }

    function test_complete_withdraw_flow_token1() public {
        token1.mint(userA, 500);
        vm.prank(userA);
        hook.depositToken1(500);

        InEuint128 memory encAmount = cft.createInEuint128(200, 0, userA);
        vm.prank(userA);
        euint128 burnHandle = hook.requestWithdrawToken1(encAmount);

        // Wait for decryption
        vm.warp(block.timestamp + 11);

        vm.prank(userA);
        uint128 amount = hook.finalizeWithdrawToken1(burnHandle);

        assertEq(amount, 200);
        cft.assertHashValue(token1.encBalances(userA), 300);
    }

    function test_withdraw_both_tokens() public {
        token0.mint(userA, 500);
        token1.mint(userA, 500);

        vm.prank(userA);
        hook.depositToken0(500);
        vm.prank(userA);
        hook.depositToken1(500);

        // Withdraw token0
        InEuint128 memory encAmount0 = cft.createInEuint128(100, 0, userA);
        vm.prank(userA);
        euint128 burnHandle0 = hook.requestWithdrawToken0(encAmount0);
        vm.warp(block.timestamp + 11);
        vm.prank(userA);
        uint128 amount0 = hook.finalizeWithdrawToken0(burnHandle0);
        assertEq(amount0, 100);

        // Withdraw token1
        InEuint128 memory encAmount1 = cft.createInEuint128(150, 0, userA);
        vm.prank(userA);
        euint128 burnHandle1 = hook.requestWithdrawToken1(encAmount1);
        vm.warp(block.timestamp + 11);
        vm.prank(userA);
        uint128 amount1 = hook.finalizeWithdrawToken1(burnHandle1);
        assertEq(amount1, 150);

        cft.assertHashValue(token0.encBalances(userA), 400);
        cft.assertHashValue(token1.encBalances(userA), 350);
    }

    // =========================================================================
    // Edge Cases
    // =========================================================================

    function test_request_withdraw_after_settlement() public {
        token0.mint(userA, 500);
        token1.mint(userB, 500);

        vm.prank(userA);
        hook.depositToken0(500);
        vm.prank(userB);
        hook.depositToken1(500);

        // Submit and settle intents
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

        // UserA now has token1, can withdraw it
        InEuint128 memory encAmount = cft.createInEuint128(50, 0, userA);
        vm.prank(userA);
        euint128 burnHandle = hook.requestWithdrawToken1(encAmount);
        vm.warp(block.timestamp + 11);
        vm.prank(userA);
        uint128 amount = hook.finalizeWithdrawToken1(burnHandle);
        assertEq(amount, 50);
    }

    function test_multiple_users_withdraw() public {
        token0.mint(userA, 500);
        token0.mint(userB, 500);

        vm.prank(userA);
        hook.depositToken0(500);
        vm.prank(userB);
        hook.depositToken0(500);

        // UserA withdraws
        InEuint128 memory encAmountA = cft.createInEuint128(100, 0, userA);
        vm.prank(userA);
        euint128 burnHandleA = hook.requestWithdrawToken0(encAmountA);
        vm.warp(block.timestamp + 11);
        vm.prank(userA);
        uint128 amountA = hook.finalizeWithdrawToken0(burnHandleA);
        assertEq(amountA, 100);

        // UserB withdraws
        InEuint128 memory encAmountB = cft.createInEuint128(200, 0, userB);
        vm.prank(userB);
        euint128 burnHandleB = hook.requestWithdrawToken0(encAmountB);
        vm.warp(block.timestamp + 11);
        vm.prank(userB);
        uint128 amountB = hook.finalizeWithdrawToken0(burnHandleB);
        assertEq(amountB, 200);

        cft.assertHashValue(token0.encBalances(userA), 400);
        cft.assertHashValue(token0.encBalances(userB), 300);
    }
}

