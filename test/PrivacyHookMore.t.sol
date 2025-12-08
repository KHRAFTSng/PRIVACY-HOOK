// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {CoFheTest} from "@fhenixprotocol/cofhe-foundry-mocks/CoFheTest.sol";
import {PrivacyHook} from "../src/PrivacyHook.sol";
import {HybridFHERC20} from "../src/HybridFHERC20.sol";
import {InEuint128, InEbool} from "@fhenixprotocol/cofhe-contracts/FHE.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";

contract PrivacyHookMoreTest is Test {
    PrivacyHook internal hook;
    HybridFHERC20 internal token0;
    HybridFHERC20 internal token1;
    CoFheTest internal cft;

    address internal relayer = address(this);
    address internal userA = address(0xA1);
    address internal userB = address(0xB1);

    function setUp() public {
        cft = new CoFheTest(true);
        token0 = new HybridFHERC20("EncToken0", "eT0");
        token1 = new HybridFHERC20("EncToken1", "eT1");
        hook = new PrivacyHook(IPoolManager(address(0x1)), relayer, token0, token1);
    }

    function _mintAndDeposit(address user, uint128 amount0, uint128 amount1) internal {
        token0.mint(user, amount0);
        token1.mint(user, amount1);

        vm.prank(user);
        hook.depositToken0(amount0);

        vm.prank(user);
        hook.depositToken1(amount1);
    }

    function test_multi_user_deposits() public {
        _mintAndDeposit(userA, 100, 50);
        _mintAndDeposit(userB, 80, 120);

        cft.assertHashValue(token0.encBalances(userA), 100);
        cft.assertHashValue(token1.encBalances(userA), 50);
        cft.assertHashValue(token0.encBalances(userB), 80);
        cft.assertHashValue(token1.encBalances(userB), 120);
    }

    function test_overwrite_intent_keeps_active_flag() public {
        vm.startPrank(userA);
        InEuint128 memory amt1 = cft.createInEuint128(40, 0, userA);
        InEbool memory dir1 = cft.createInEbool(true, 0, userA);
        hook.submitIntent(amt1, dir1);

        InEuint128 memory amt2 = cft.createInEuint128(25, 0, userA);
        InEbool memory dir2 = cft.createInEbool(false, 0, userA);
        hook.submitIntent(amt2, dir2);
        vm.stopPrank();

        assertTrue(hook.isIntentActive(userA), "intent should stay active after overwrite");
    }

    function test_cancel_intent_twice_is_safe() public {
        vm.prank(userA);
        hook.cancelIntent();

        vm.prank(userA);
        hook.cancelIntent();

        assertFalse(hook.isIntentActive(userA), "intent should remain inactive");
    }
}

