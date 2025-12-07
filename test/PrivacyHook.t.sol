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

        // Wait a bit for FHE operations to complete (mock needs time)
        vm.roll(block.number + 1);
        
        // Decrypt balances to assert transfers occurred
        token0.decryptBalance(userA);
        token1.decryptBalance(userA);
        token0.decryptBalance(userB);
        token1.decryptBalance(userB);

        // Wait for decryption to complete
        vm.roll(block.number + 1);
        
        uint128 a0 = token0.getDecryptBalanceResult(userA);
        uint128 a1 = token1.getDecryptBalanceResult(userA);
        uint128 b0 = token0.getDecryptBalanceResult(userB);
        uint128 b1 = token1.getDecryptBalanceResult(userB);

        assertEq(a0, 100, "userA token0 after trade");
        assertEq(a1, 100, "userA token1 after trade");
        assertEq(b0, 100, "userB token0 after trade");
        assertEq(b1, 100, "userB token1 after trade");
    }
}

