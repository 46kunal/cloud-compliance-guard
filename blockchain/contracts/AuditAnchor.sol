// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title AuditAnchor — stores PolicyGuard audit-chain head hashes on-chain
contract AuditAnchor {
    address public immutable owner;
    bytes32 public latestHash;
    mapping(bytes32 => uint256) public anchoredAt;

    event Anchored(bytes32 indexed entryHash, uint256 timestamp);

    constructor() {
        owner = msg.sender;
    }

    function anchor(bytes32 entryHash) external {
        require(msg.sender == owner, "only owner");
        require(anchoredAt[entryHash] == 0, "already anchored");
        latestHash = entryHash;
        anchoredAt[entryHash] = block.timestamp;
        emit Anchored(entryHash, block.timestamp);
    }
}
