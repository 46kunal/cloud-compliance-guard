// Local:   npx hardhat node   (separate terminal)
//          npx hardhat run scripts/deploy.js --network localhost
// Then set ANCHOR_CONTRACT_ADDRESS, WEB3_RPC_URL, ANCHOR_PRIVATE_KEY for lambdas/audit_logger/blockchain_anchor.py
const hre = require("hardhat");

async function main() {
  const anchor = await hre.ethers.deployContract("AuditAnchor");
  await anchor.waitForDeployment();
  console.log("AuditAnchor deployed to:", await anchor.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
