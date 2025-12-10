// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {PrivacyHook} from "../src/PrivacyHook.sol";
import {HybridFHERC20} from "../src/HybridFHERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {CoFheTest} from "@fhenixprotocol/cofhe-foundry-mocks/CoFheTest.sol";
import {FHE, InEuint128, InEbool} from "@fhenixprotocol/cofhe-contracts/FHE.sol";

/**
 * @title PrivacyHookUnitTest
 * @notice Unit tests for PrivacyHook focusing on individual function behavior
 */
contract PrivacyHookUnitTest is Test {
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
    // Deposit Tests
    // =========================================================================

    function test_depositToken0_success() public {
        token0.mint(userA, 100);
        vm.prank(userA);
        hook.depositToken0(100);

        cft.assertHashValue(token0.encBalances(userA), 100);
    }

    function test_depositToken1_success() public {
        token1.mint(userA, 200);
        vm.prank(userA);
        hook.depositToken1(200);

        cft.assertHashValue(token1.encBalances(userA), 200);
    }

    function test_depositToken0_zero_reverts() public {
        vm.expectRevert(PrivacyHook.InvalidAmount.selector);
        vm.prank(userA);
        hook.depositToken0(0);
    }

    function test_depositToken1_zero_reverts() public {
        vm.expectRevert(PrivacyHook.InvalidAmount.selector);
        vm.prank(userA);
        hook.depositToken1(0);
    }

    function test_depositToken0_insufficient_balance_reverts() public {
        token0.mint(userA, 50);
        vm.expectRevert();
        vm.prank(userA);
        hook.depositToken0(100); // Trying to deposit more than balance
    }

    function test_depositToken1_insufficient_balance_reverts() public {
        token1.mint(userA, 50);
        vm.expectRevert();
        vm.prank(userA);
        hook.depositToken1(100); // Trying to deposit more than balance
    }

    function test_depositToken0_multiple_deposits() public {
        token0.mint(userA, 300);
        
        vm.prank(userA);
        hook.depositToken0(100);
        
        vm.prank(userA);
        hook.depositToken0(200);

        cft.assertHashValue(token0.encBalances(userA), 300);
    }

    function test_depositToken1_multiple_deposits() public {
        token1.mint(userA, 500);
        
        vm.prank(userA);
        hook.depositToken1(100);
        
        vm.prank(userA);
        hook.depositToken1(400);

        cft.assertHashValue(token1.encBalances(userA), 500);
    }

    function test_depositToken0_emits_event() public {
        token0.mint(userA, 100);
        
        vm.expectEmit(true, false, false, false);
        emit PrivacyHook.Deposited(userA, 0, 100);
        
        vm.prank(userA);
        hook.depositToken0(100);
    }

    function test_depositToken1_emits_event() public {
        token1.mint(userA, 200);
        
        vm.expectEmit(true, false, false, false);
        emit PrivacyHook.Deposited(userA, 1, 200);
        
        vm.prank(userA);
        hook.depositToken1(200);
    }

    // =========================================================================
    // Intent Submission Tests
    // =========================================================================

    function test_submitIntent_success() public {
        InEuint128 memory amt = cft.createInEuint128(100, 0, userA);
        InEbool memory dir = cft.createInEbool(true, 0, userA);

        vm.expectEmit(true, false, false, false);
        emit PrivacyHook.IntentSubmitted(userA);

        vm.prank(userA);
        hook.submitIntent(amt, dir);

        assertTrue(hook.isIntentActive(userA));
    }

    function test_submitIntent_zeroForOne() public {
        InEuint128 memory amt = cft.createInEuint128(50, 0, userA);
        InEbool memory dir = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amt, dir);

        assertTrue(hook.isIntentActive(userA));
    }

    function test_submitIntent_oneForZero() public {
        InEuint128 memory amt = cft.createInEuint128(50, 0, userA);
        InEbool memory dir = cft.createInEbool(false, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amt, dir);

        assertTrue(hook.isIntentActive(userA));
    }

    function test_submitIntent_overwrites_previous() public {
        InEuint128 memory amt1 = cft.createInEuint128(100, 0, userA);
        InEbool memory dir1 = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amt1, dir1);

        InEuint128 memory amt2 = cft.createInEuint128(200, 0, userA);
        InEbool memory dir2 = cft.createInEbool(false, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amt2, dir2);

        assertTrue(hook.isIntentActive(userA));
    }

    function test_submitIntent_multiple_users() public {
        InEuint128 memory amtA = cft.createInEuint128(100, 0, userA);
        InEbool memory dirA = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amtA, dirA);

        InEuint128 memory amtB = cft.createInEuint128(150, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);

        vm.prank(userB);
        hook.submitIntent(amtB, dirB);

        assertTrue(hook.isIntentActive(userA));
        assertTrue(hook.isIntentActive(userB));
    }

    // =========================================================================
    // Intent Cancellation Tests
    // =========================================================================

    function test_cancelIntent_success() public {
        InEuint128 memory amt = cft.createInEuint128(100, 0, userA);
        InEbool memory dir = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amt, dir);

        vm.expectEmit(true, false, false, false);
        emit PrivacyHook.IntentCancelled(userA);

        vm.prank(userA);
        hook.cancelIntent();

        assertFalse(hook.isIntentActive(userA));
    }

    function test_cancelIntent_without_submit() public {
        vm.prank(userA);
        hook.cancelIntent();

        assertFalse(hook.isIntentActive(userA));
    }

    function test_cancelIntent_twice() public {
        InEuint128 memory amt = cft.createInEuint128(100, 0, userA);
        InEbool memory dir = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amt, dir);

        vm.prank(userA);
        hook.cancelIntent();

        vm.prank(userA);
        hook.cancelIntent();

        assertFalse(hook.isIntentActive(userA));
    }

    function test_cancelIntent_after_resubmit() public {
        InEuint128 memory amt1 = cft.createInEuint128(100, 0, userA);
        InEbool memory dir1 = cft.createInEbool(true, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amt1, dir1);

        vm.prank(userA);
        hook.cancelIntent();

        InEuint128 memory amt2 = cft.createInEuint128(200, 0, userA);
        InEbool memory dir2 = cft.createInEbool(false, 0, userA);

        vm.prank(userA);
        hook.submitIntent(amt2, dir2);

        assertTrue(hook.isIntentActive(userA));

        vm.prank(userA);
        hook.cancelIntent();

        assertFalse(hook.isIntentActive(userA));
    }

    // =========================================================================
    // Immutable Config Tests
    // =========================================================================

    function test_relayer_address() public {
        assertEq(hook.relayer(), relayer);
    }

    function test_token0_address() public {
        assertEq(address(hook.token0()), address(token0));
    }

    function test_token1_address() public {
        assertEq(address(hook.token1()), address(token1));
    }

    // =========================================================================
    // Hook Permissions Tests
    // =========================================================================

    function test_getHookPermissions() public {
        Hooks.Permissions memory permissions = hook.getHookPermissions();
        
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
}

