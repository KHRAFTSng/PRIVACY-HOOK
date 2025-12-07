// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Script.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {console2} from "forge-std/console2.sol";
import {HybridFHERC20} from "../src/HybridFHERC20.sol";
import {PrivacyHook} from "../src/PrivacyHook.sol";

contract DeployPrivacyHook is Script {
    function run() external {
        address deployer = vm.envAddress("DEPLOYER");
        address poolManager = vm.envAddress("POOL_MANAGER");
        address relayer = vm.envAddress("RELAYER");

        vm.startBroadcast(deployer);

        HybridFHERC20 token0 = new HybridFHERC20("EncToken0", "eT0");
        HybridFHERC20 token1 = new HybridFHERC20("EncToken1", "eT1");

        PrivacyHook hook = new PrivacyHook(IPoolManager(poolManager), relayer, token0, token1);

        vm.stopBroadcast();

        console2.log("token0", address(token0));
        console2.log("token1", address(token1));
        console2.log("hook", address(hook));
    }
}

