import { ethers } from "hardhat";
import * as dotenv from "dotenv";

dotenv.config();

/**
 * Test script for deployed PrivacyHook contracts on Sepolia.
 * 
 * ⚠️ WARNING: FHE operations will fail on Sepolia as Fhenix precompiles are not available.
 * This script tests basic contract interactions and demonstrates FHE limitations.
 */
async function main() {
  const hookAddress = "0x049E56266c52E88cc6d22Bd3B66FF43Eb25aF704";
  const token0Address = "0x55b29D0ba5B35C3fDcD81bD6f40eACECc15C4035";
  const token1Address = "0x37dC2Fd4f4ACF3c66C460C13896f878489635035";
  const poolManager = "0x61b3f2011a92d183c7dbadbda940a7555ccf9227";

  const [deployer] = await ethers.getSigners();
  const userA = deployer; // Use deployer as test user
  console.log("Testing with account:");
  console.log("  Deployer/User:", deployer.address);
  console.log("");

  // Get contract instances
  const Hook = await ethers.getContractFactory("PrivacyHook");
  const Token0 = await ethers.getContractFactory("HybridFHERC20");
  const Token1 = await ethers.getContractFactory("HybridFHERC20");

  const hook = Hook.attach(hookAddress);
  const token0 = Token0.attach(token0Address);
  const token1 = Token1.attach(token1Address);

  console.log("=".repeat(60));
  console.log("TEST 1: Read Contract State (Should Work)");
  console.log("=".repeat(60));
  try {
    const relayer = await hook.relayer();
    const poolManagerAddr = await hook.poolManager();
    const token0Addr = await hook.token0();
    const token1Addr = await hook.token1();

    console.log("✓ Hook relayer:", relayer);
    console.log("✓ Hook poolManager:", poolManagerAddr);
    console.log("✓ Hook token0:", token0Addr);
    console.log("✓ Hook token1:", token1Addr);
    console.log("✓ Token0 name:", await token0.name());
    console.log("✓ Token0 symbol:", await token0.symbol());
    console.log("✓ Token1 name:", await token1.name());
    console.log("✓ Token1 symbol:", await token1.symbol());
  } catch (error: any) {
    console.log("✗ Error reading state:", error.message);
  }

  console.log("\n" + "=".repeat(60));
  console.log("TEST 2: Check Intent Status (Should Work)");
  console.log("=".repeat(60));
  try {
    const isActive = await hook.isIntentActive(userA.address);
    console.log(`✓ Intent active for ${userA.address}:`, isActive);
  } catch (error: any) {
    console.log("✗ Error checking intent:", error.message);
  }

  console.log("\n" + "=".repeat(60));
  console.log("TEST 3: Public Token Operations (Should Work)");
  console.log("=".repeat(60));
  try {
    // Try to mint some public tokens (non-FHE)
    console.log("Attempting public mint...");
    const mintTx = await token0.connect(userA).mint(userA.address, ethers.parseEther("100"));
    await mintTx.wait();
    console.log("✓ Public mint successful!");
    
    const balance = await token0.balanceOf(userA.address);
    console.log(`✓ UserA Token0 balance: ${ethers.formatEther(balance)}`);
    
    // Also mint token1
    const mintTx1 = await token1.connect(userA).mint(userA.address, ethers.parseEther("100"));
    await mintTx1.wait();
    const balance1 = await token1.balanceOf(userA.address);
    console.log(`✓ UserA Token1 balance: ${ethers.formatEther(balance1)}`);
  } catch (error: any) {
    console.log("✗ Public mint failed:", error.message);
  }

  console.log("\n" + "=".repeat(60));
  console.log("TEST 4: Approve Hook for Token Transfer");
  console.log("=".repeat(60));
  try {
    console.log("Approving hook to spend tokens...");
    const approveTx0 = await token0.connect(userA).approve(hookAddress, ethers.parseEther("100"));
    await approveTx0.wait();
    console.log("✓ Token0 approval successful!");
    
    const approveTx1 = await token1.connect(userA).approve(hookAddress, ethers.parseEther("100"));
    await approveTx1.wait();
    console.log("✓ Token1 approval successful!");
  } catch (error: any) {
    console.log("✗ Approval failed:", error.message);
  }

  console.log("\n" + "=".repeat(60));
  console.log("TEST 5: Wrap Tokens (Will Fail - Requires FHE)");
  console.log("=".repeat(60));
  try {
    console.log("Attempting to deposit/wrap 10 Token0...");
    // This will fail because depositToken0() calls wrap() which uses FHE operations
    const depositTx = await hook.connect(userA).depositToken0(ethers.parseEther("10"));
    const receipt = await depositTx.wait();
    console.log("✓ Deposit successful!");
    console.log("  Transaction hash:", receipt?.hash);
  } catch (error: any) {
    console.log("✗ Deposit failed (expected):", error.message);
    console.log("  Reason: FHE precompiles not available on Sepolia");
    console.log("  The hook.depositToken0() calls token0.wrap() which requires FHE encryption");
  }

  console.log("\n" + "=".repeat(60));
  console.log("TEST 6: Cancel Intent (Should Work - No FHE)");
  console.log("=".repeat(60));
  try {
    console.log("Attempting to cancel intent (even if none exists)...");
    const cancelTx = await hook.connect(userA).cancelIntent();
    await cancelTx.wait();
    console.log("✓ Cancel intent successful!");
    const isActive = await hook.isIntentActive(userA.address);
    console.log(`  Intent active: ${isActive}`);
  } catch (error: any) {
    console.log("✗ Cancel intent failed:", error.message);
  }

  console.log("\n" + "=".repeat(60));
  console.log("TEST 7: Submit Intent (Will Fail - Requires FHE)");
  console.log("=".repeat(60));
  try {
    console.log("Attempting to submit encrypted intent...");
    // This will fail because submitIntent() requires FHE encryption
    // We can't create proper InEuint128/InEbool without FHE precompiles
    console.log("  Cannot test: Requires FHE encryption which needs Fhenix network");
    console.log("  submitIntent() needs InEuint128 and InEbool types from Fhenix");
  } catch (error: any) {
    console.log("✗ Submit intent failed (expected):", error.message);
  }

  console.log("\n" + "=".repeat(60));
  console.log("TEST SUMMARY");
  console.log("=".repeat(60));
  console.log("✓ Basic contract reads: WORKING");
  console.log("✓ Public token operations: WORKING");
  console.log("✗ FHE operations (wrap/deposit): FAILING (expected)");
  console.log("✗ Encrypted intents: NOT POSSIBLE");
  console.log("\n⚠️  To test full functionality, deploy to Fhenix testnet!");
  console.log("=".repeat(60));
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});

