import { ethers } from "hardhat";
import * as dotenv from "dotenv";

dotenv.config();

/**
 * Deploy HybridFHERC20 tokens and PrivacyHook to a Fhenix-compatible network.
 *
 * Env vars required:
 *  - FHENIX_RPC_URL: RPC endpoint for Fhenix/localfhenix
 *  - FHENIX_PRIVATE_KEY: deployer key (with funds on that network)
 *  - FHENIX_RELAYER: relayer address permitted to call settleMatched
 *  - FHENIX_POOL_MANAGER: PoolManager address (use a placeholder if not interacting with v4 swaps)
 */
async function main() {
  const relayer = process.env.FHENIX_RELAYER;
  const poolManager = process.env.FHENIX_POOL_MANAGER;

  if (!relayer || !poolManager) {
    throw new Error("FHENIX_RELAYER and FHENIX_POOL_MANAGER must be set");
  }

  console.log("Deploying with account:", (await ethers.getSigners())[0].address);
  console.log("Relayer:", relayer);
  console.log("PoolManager:", poolManager);

  const Token = await ethers.getContractFactory("HybridFHERC20");
  const token0 = await Token.deploy("EncToken0", "eT0");
  await token0.deployed();
  console.log("token0 deployed at:", token0.address);

  const token1 = await Token.deploy("EncToken1", "eT1");
  await token1.deployed();
  console.log("token1 deployed at:", token1.address);

  const Hook = await ethers.getContractFactory("PrivacyHook");
  const hook = await Hook.deploy(poolManager, relayer, token0.address, token1.address);
  await hook.deployed();
  console.log("PrivacyHook deployed at:", hook.address);

  console.log("Export env for frontend:");
  console.log(`NEXT_PUBLIC_PRIVACY_HOOK_ADDRESS=${hook.address}`);
  console.log(`NEXT_PUBLIC_PRIVACY_TOKEN0_ADDRESS=${token0.address}`);
  console.log(`NEXT_PUBLIC_PRIVACY_TOKEN1_ADDRESS=${token1.address}`);
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});

