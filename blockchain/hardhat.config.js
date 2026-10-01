// npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
require("@nomicfoundation/hardhat-toolbox");

const { SEPOLIA_RPC_URL, ANCHOR_PRIVATE_KEY } = process.env;

module.exports = {
  solidity: "0.8.20",
  networks: {
    localhost: { url: "http://127.0.0.1:8545" },
    ...(SEPOLIA_RPC_URL && ANCHOR_PRIVATE_KEY
      ? { sepolia: { url: SEPOLIA_RPC_URL, accounts: [ANCHOR_PRIVATE_KEY] } }
      : {}),
  },
};
