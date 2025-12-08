import { ethers } from "hardhat";
import * as dotenv from "dotenv";

dotenv.config();

/**
 * ⚠️ WARNING: This deployment script is for Sepolia testnet.
 * 
 * NOTE: The PrivacyHook and HybridFHERC20 contracts use Fhenix FHE precompiles
 * which are NOT available on Sepolia. These contracts will NOT function correctly
 * on Sepolia. They require a Fhenix-compatible network (localfhenix or Fhenix testnet).
 * 
 * This script is provided for testing deployment infrastructure only.
 * 
 * Env vars required:
 *  - PRIVATE_KEY: deployer private key (with Sepolia ETH)
 *  - SEPOLIA_RPC_URL: Sepolia RPC endpoint
 *  - POOL_MANAGER_ADDRESS: Uniswap v4 PoolManager address on Sepolia
 *  - RELAYER_ADDRESS: address that will be allowed to call settleMatched (optional, defaults to deployer)
 */
async function main() {
  const poolManager = process.env.POOL_MANAGER_ADDRESS;
  const relayer = process.env.RELAYER_ADDRESS || (await ethers.getSigners())[0].address;

  if (!poolManager) {
    throw new Error("POOL_MANAGER_ADDRESS must be set in .env");
  }

  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Account balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");
  console.log("Relayer:", relayer);
  console.log("PoolManager:", poolManager);

  console.log("\n⚠️  WARNING: FHE contracts require Fhenix precompiles and will NOT work on Sepolia!");
  console.log("This deployment is for infrastructure testing only.\n");

  // Deploy tokens
  console.log("Deploying HybridFHERC20 tokens...");
  const Token = await ethers.getContractFactory("HybridFHERC20");
  
  const token0 = await Token.deploy("EncToken0", "eT0");
  await token0.waitForDeployment();
  const token0Address = await token0.getAddress();
  console.log("✓ Token0 deployed at:", token0Address);

  const token1 = await Token.deploy("EncToken1", "eT1");
  await token1.waitForDeployment();
  const token1Address = await token1.getAddress();
  console.log("✓ Token1 deployed at:", token1Address);

  // Deploy hook
  console.log("\nDeploying PrivacyHook...");
  const Hook = await ethers.getContractFactory("PrivacyHook");
  const hook = await Hook.deploy(poolManager, relayer, token0Address, token1Address);
  await hook.waitForDeployment();
  const hookAddress = await hook.getAddress();
  console.log("✓ PrivacyHook deployed at:", hookAddress);

  console.log("\n" + "=".repeat(60));
  console.log("DEPLOYMENT SUMMARY");
  console.log("=".repeat(60));
  console.log("Network: Sepolia");
  console.log("Deployer:", deployer.address);
  console.log("\nContract Addresses:");
  console.log(`  PrivacyHook:     ${hookAddress}`);
  console.log(`  HybridFHERC20_0: ${token0Address}`);
  console.log(`  HybridFHERC20_1: ${token1Address}`);
  console.log("\nFrontend Environment Variables:");
  console.log(`NEXT_PUBLIC_PRIVACY_HOOK_ADDRESS=${hookAddress}`);
  console.log(`NEXT_PUBLIC_PRIVACY_TOKEN0_ADDRESS=${token0Address}`);
  console.log(`NEXT_PUBLIC_PRIVACY_TOKEN1_ADDRESS=${token1Address}`);
  console.log("=".repeat(60));
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});

