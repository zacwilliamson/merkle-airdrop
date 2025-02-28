// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {BagelToken} from "./BagelToken.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MerkleAirdrop is EIP712 {
    using SafeERC20 for IERC20;
    // list of addresses that can receive tokens
    // allow someone in the list to claim some tokens

    error MerkleAirdrop__InvalidProof();
    error MerkleAirdrop__AlreadyClaimed();
    error MerkleAirdrop__InvalidSignature();

    struct AirdropClaim {
        address account;
        uint256 amount;
    }

    bytes32 private constant MESSAGE_TYPEHASH = keccak256("AirdropClaim(address account,uint256 amount)");
    address[] claimers;
    IERC20 private immutable i_airdropToken;
    bytes32 private immutable i_merkleRoot;
    mapping(address claimer => bool claimed) private s_hasClaimed;

    event Claim(address indexed account, uint256 indexed amount);

    constructor(bytes32 merkleRoot, IERC20 airdropToken) EIP712("Airdrop", "1") {
        i_merkleRoot = merkleRoot;
        i_airdropToken = airdropToken;
    }

    function claim(address account, uint256 amount, bytes32[] calldata merkleProof, uint8 v, bytes32 r, bytes32 s)
        external
    {
        if (s_hasClaimed[account]) {
            revert MerkleAirdrop__AlreadyClaimed();
        }

        // verify the signature
        if (!_isValidSignature(account, getMessage(account, amount), v, r, s)) {
            revert MerkleAirdrop__InvalidSignature();
        }
        // calculate using the account and the amount, the hash -> leaf node
        // double keccak to avoid hash collisions (general way of encoding leaf hashes)
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(account, amount))));
        if (!MerkleProof.verify(merkleProof, i_merkleRoot, leaf)) {
            revert MerkleAirdrop__InvalidProof();
        }
        s_hasClaimed[account] = true;
        emit Claim(account, amount);
        i_airdropToken.safeTransfer(account, amount);
    }

    function getMerkleRoot() public view returns (bytes32) {
        return i_merkleRoot;
    }

    function getAirdropToken() public view returns (IERC20) {
        return i_airdropToken;
    }

    function getMessage(address account, uint256 amount) public view returns (bytes32) {
        return
            _hashTypedDataV4(keccak256(abi.encode(MESSAGE_TYPEHASH, AirdropClaim({account: account, amount: amount}))));
    }

    function _isValidSignature(address account, bytes32 digest, uint8 v, bytes32 r, bytes32 s)
        internal
        pure
        returns (bool)
    {
        (address actualSigner,,) = ECDSA.tryRecover(digest, v, r, s);
        return (actualSigner == account);
    }
}

/*
Merkle Tree Example
{
  "types": ["address", "uint"],
  "count": 4,
  "values": {
    "0": {
      "0": "0x6CA6d1e2D5347Bfab1d91e883F1915560e09129D",
      "1": "2500000000000000000"
    },
    "1": {
      "0": "0xf39Fd6e51aad88F6F4c6aB8827279cffFb92266",
      "1": "2500000000000000000"
    },
    "2": {
      "0": "0c8Ca207e27a1a8224D1b602bf856479b03319e7",
      "1": "2500000000000000000"
    },
    "3": {
      "0": "0xf6dBa02C01AF48Cf926579F77C9f874Ca640D91D",
      "1": "2500000000000000000"
    }
  }
}
 */
