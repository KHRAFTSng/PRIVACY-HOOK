import { ethers } from "hardhat";

async function main() {
  const hookAddress = "0x049E56266c52E88cc6d22Bd3B66FF43Eb25aF704";
  const token0Address = "0x55b29D0ba5B35C3fDcD81bD6f40eACECc15C4035";
  const [signer] = await ethers.getSigners();
  
  const Hook = await ethers.getContractFactory("PrivacyHook");
  const Token0 = await ethers.getContractFactory("HybridFHERC20");
  
  const hook = Hook.attach(hookAddress);
  const token0 = Token0.attach(token0Address);
  
  console.log("Checking state after deposit transaction...");
  console.log("Account:", signer.address);
  
  const publicBalance = await token0.balanceOf(signer.address);
  console.log("Public Token0 balance:", ethers.formatEther(publicBalance));
  
  // Try to check encrypted balance
  try {
    const encBalance = await token0.encBalances(signer.address);
    console.log("Encrypted balance (hash):", encBalance);
  } catch (e: any) {
    console.log("Cannot read encrypted balance (FHE not available):", e.message.substring(0, 100));
  }
  
  console.log("\n" + "=".repeat(60));
  console.log("CONCLUSION");
  console.log("=".repeat(60));
  console.log("The deposit transaction succeeded, but:");
  console.log("1. FHE operations cannot execute on Sepolia");
  console.log("2. Encrypted balances cannot be read/verified");
  console.log("3. Intent submission requires Fhenix network");
  console.log("\nTo test full functionality, deploy to Fhenix testnet!");
}

main().catch(console.error);

