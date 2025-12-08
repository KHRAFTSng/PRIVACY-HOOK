// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {CoFheTest} from "@fhenixprotocol/cofhe-foundry-mocks/CoFheTest.sol";
import "../src/HybridFHERC20.sol";

contract HybridFHERC20FuzzTest is Test {
    HybridFHERC20 internal token;
    CoFheTest internal cft;
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    function setUp() public {
        cft = new CoFheTest(true);
        token = new HybridFHERC20("EncToken", "eT");
    }

    function testFuzz_mint_and_transfer(uint256 mintAmt, uint256 sendAmt) public {
        mintAmt = bound(mintAmt, 1, 1e24);
        sendAmt = bound(sendAmt, 0, mintAmt);

        token.mint(alice, mintAmt);

        vm.prank(alice);
        token.transfer(bob, sendAmt);

        uint256 aliceBal = token.balanceOf(alice);
        uint256 bobBal = token.balanceOf(bob);
        assertEq(aliceBal + bobBal, mintAmt, "total supply conservation");
        assertEq(bobBal, sendAmt, "bob receives sendAmt");
    }

    function testFuzz_burn_within_balance(uint256 mintAmt, uint256 burnAmt) public {
        mintAmt = bound(mintAmt, 1, 1e24);
        burnAmt = bound(burnAmt, 0, mintAmt);

        token.mint(alice, mintAmt);
        token.burn(alice, burnAmt);

        uint256 expected = mintAmt - burnAmt;
        assertEq(token.balanceOf(alice), expected, "balance after burn");
        assertEq(token.totalSupply(), expected, "supply after burn");
    }

    function testFuzz_transfer_reverts_zero_receiver(address to) public {
        vm.assume(to != address(0));
        token.mint(alice, 10 ether);

        vm.prank(alice);
        vm.expectRevert(); // OZ ERC20 reverts on zero address
        token.transfer(address(0), 1 ether);
    }
}

