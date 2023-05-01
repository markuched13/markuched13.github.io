// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GetHash {
    bytes32 public hash = blockhash(block.number - 5);
}
