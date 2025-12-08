// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {CoFheTest} from "@fhenixprotocol/cofhe-foundry-mocks/CoFheTest.sol";
import "../src/HybridFHERC20.sol";

contract HybridFHERC20Handler {
    HybridFHERC20 public token;
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);

    constructor(HybridFHERC20 _token) {
        token = _token;
    }

    function mintA(uint256 amt) public {
        amt = _bound(amt, 1, 1e24);
        token.mint(alice, amt);
    }

    function mintB(uint256 amt) public {
        amt = _bound(amt, 1, 1e24);
        token.mint(bob, amt);
    }

    function burnA(uint256 amt) public {
        uint256 bal = token.balanceOf(alice);
        if (bal == 0) return;
        amt = _bound(amt, 1, bal);
        token.burn(alice, amt);
    }

    function burnB(uint256 amt) public {
        uint256 bal = token.balanceOf(bob);
        if (bal == 0) return;
        amt = _bound(amt, 1, bal);
        token.burn(bob, amt);
    }

    function _bound(uint256 x, uint256 min, uint256 max) internal pure returns (uint256) {
        if (x < min) return min;
        if (x > max) return max;
        return x;
    }
}

contract HybridFHERC20InvariantTest is Test {
    HybridFHERC20 internal token;
    HybridFHERC20Handler internal handler;
    CoFheTest internal cft;

    function setUp() public {
        cft = new CoFheTest(true);
        token = new HybridFHERC20("EncToken", "eT");
        handler = new HybridFHERC20Handler(token);
        targetContract(address(handler));
    }

    function invariant_totalSupply_matches_balances() public {
        uint256 supply = token.totalSupply();
        uint256 sum = token.balanceOf(handler.alice()) + token.balanceOf(handler.bob());
        assertEq(supply, sum, "totalSupply should equal tracked balances");
    }
}

