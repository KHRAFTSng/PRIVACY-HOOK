import { run } from "hardhat";

async function main() {
  const hookAddress = "0x72Acb50A8a6C7d39b08C56558fdeFfaF7C2b885A";
  const poolManager = "0x61b3f2011a92d183c7dbadbda940a7555ccf9227";
  const relayer = "0x4b992F2Fbf714C0fCBb23baC5130Ace48CaD00cd";
  const token0 = "0xd458768065296912E75C7962c7fF502FB85A5255";
  const token1 = "0x9c14e6351eB6a0526EDB6c798bE3a51fF26E1a59";

  console.log("Verifying PrivacyHook on Sepolia...");
  console.log("Hook Address:", hookAddress);
  console.log("");

  try {
    await run("verify:verify", {
      address: hookAddress,
      network: "sepolia",
      constructorArguments: [poolManager, relayer, token0, token1],
    });
    console.log("\n✓ Verification successful!");
    console.log(`View on Etherscan: https://sepolia.etherscan.io/address/${hookAddress}#code`);
  } catch (error: any) {
    if (error.message.includes("Already Verified")) {
      console.log("✓ Contract is already verified!");
    } else {
      console.error("Verification failed:", error.message);
      throw error;
    }
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

