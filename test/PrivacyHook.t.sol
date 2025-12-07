// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {PrivacyHook} from "../src/PrivacyHook.sol";
import {HybridFHERC20} from "../src/HybridFHERC20.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {CoFheTest} from "@fhenixprotocol/cofhe-foundry-mocks/CoFheTest.sol";
import {FHE, InEuint128, InEbool} from "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract PrivacyHookTest is Test {
    using FHE for uint256;

    HybridFHERC20 token0;
    HybridFHERC20 token1;
    PrivacyHook hook;
    CoFheTest private cft;

    address relayer = address(this);
    address userA = address(0xA);
    address userB = address(0xB);

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
}

