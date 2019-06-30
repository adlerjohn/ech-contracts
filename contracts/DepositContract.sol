pragma solidity ^0.5.8;

pragma experimental ABIEncoderV2;

import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "openzeppelin-solidity/contracts/ownership/Ownable.sol";

import "contracts/libs/MerkleProof256.sol";

contract DepositContract is Ownable {
    using SafeMath for uint256;

    struct BlockHeader {
        bytes32 prev;
        uint256 height;
        bytes32 stateRoot;
        bytes32 txRoot;
    }

    uint256 constant public BOND_SIZE = 1 ether;
    uint256 constant public FINALIZATION_DELAY = 6000;

    bytes32[] public s_blockHashes;
    uint256 public s_tipHeight;
    uint256 public s_tipEthereumHeight;

    function postNewBlock(BlockHeader calldata header, bytes calldata txData, bytes calldata fraudProof) external payable returns (bool) {
        require(header.height > 0);
        require(header.height <= s_tipHeight.add(1));
        require(header.prev == s_blockHashes[s_tipHeight]);
        require(msg.value == BOND_SIZE);
        require(s_tipEthereumHeight != block.number);

        bytes32 blockHash = keccak256(abi.encodePacked(header.prev, header.height, header.txRoot));

        if (fraudProof.length > 0) {
            // TODO process fraud proof
            s_blockHashes.length = header.height;
        }

        // If all checks pass, make the new block the tip
        s_blockHashes.push(blockHash);
        s_tipHeight = header.height;
        s_tipEthereumHeight = block.number;

        return true;
    }
}