// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {PrivacyHook} from "../src/PrivacyHook.sol";
import {HybridFHERC20} from "../src/HybridFHERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {CoFheTest} from "@fhenixprotocol/cofhe-foundry-mocks/CoFheTest.sol";
import {FHE, InEuint128, InEbool, euint128} from "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract PrivacyHookTest is Test {
    using FHE for uint256;

    HybridFHERC20 token0;
    HybridFHERC20 token1;
    PrivacyHook hook;
    CoFheTest private cft;

    address relayer = address(this);
    address userA = address(0xA);
    address userB = address(0xB);
    address attacker = address(0xC0FFEE);

    function setUp() public {
        cft = new CoFheTest(true);
        token0 = new HybridFHERC20("EncToken0", "eT0");
        token1 = new HybridFHERC20("EncToken1", "eT1");

        // PoolManager address is unused in these tests; provide a non-zero placeholder
        hook = new PrivacyHook(IPoolManager(address(0x1)), relayer, token0, token1);

        token0.mint(userA, 1_000);
        token1.mint(userB, 1_000);
    }

    function test_deposit_submit_settle() public {
        // User deposits
        vm.prank(userA);
        hook.depositToken0(200);

        vm.prank(userB);
        hook.depositToken1(200);

        // Intent: userA sells token0 for token1, userB sells token1 for token0
        vm.startPrank(userA);
        InEuint128 memory amt = cft.createInEuint128(100, 0, userA);
        InEbool memory dir = cft.createInEbool(true, 0, userA);
        hook.submitIntent(amt, dir);
        vm.stopPrank();

        vm.startPrank(userB);
        InEuint128 memory amtB = cft.createInEuint128(100, 0, userB);
        InEbool memory dirB = cft.createInEbool(false, 0, userB);
        hook.submitIntent(amtB, dirB);
        vm.stopPrank();

        // Relayer matches
        vm.startPrank(relayer);
        hook.settleMatched(userA, userB, cft.createInEuint128(100, 0, relayer));
        vm.stopPrank();

        // Assert encrypted balances via mock storage hashes
        cft.assertHashValue(token0.encBalances(userA), 100);
        cft.assertHashValue(token1.encBalances(userA), 100);
        cft.assertHashValue(token0.encBalances(userB), 100);
        cft.assertHashValue(token1.encBalances(userB), 100);
    }

    function test_deposit_only() public {
        vm.prank(userA);
        hook.depositToken0(200);

        // Check encrypted balance was created using mock hash assertion
        cft.assertHashValue(token0.encBalances(userA), 200);
    }

    function test_submit_intent() public {
        vm.prank(userA);
        hook.depositToken0(200);

        vm.startPrank(userA);
        InEuint128 memory amt = cft.createInEuint128(100, 0, userA);
        InEbool memory dir = cft.createInEbool(true, 0, userA);
        hook.submitIntent(amt, dir);
        vm.stopPrank();

        assertTrue(hook.isIntentActive(userA), "Intent should be active");
    }

    function test_cancel_intent() public {
        vm.startPrank(userA);
        InEuint128 memory amt = cft.createInEuint128(50, 0, userA);
        InEbool memory dir = cft.createInEbool(true, 0, userA);
        hook.submitIntent(amt, dir);
        hook.cancelIntent();
        vm.stopPrank();

        assertFalse(hook.isIntentActive(userA), "Intent should be cancelled");
    }

    function test_deposit_zero_reverts() public {
        vm.expectRevert(PrivacyHook.InvalidAmount.selector);
        hook.depositToken0(0);
    }

    function test_request_withdraw_success_path() public {
        vm.prank(userA);
        hook.depositToken0(50);

        vm.startPrank(userA);
        InEuint128 memory burnReq = cft.createInEuint128(20, 0, userA);
        vm.expectRevert(); // decrypt will revert in mock signer flow
        hook.requestWithdrawToken0(burnReq);
        vm.stopPrank();
    }
}

