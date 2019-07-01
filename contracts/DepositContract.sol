pragma solidity ^0.5.8;

pragma experimental ABIEncoderV2;

import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "openzeppelin-solidity/contracts/ownership/Ownable.sol";

import "contracts/libs/MerkleProof256.sol";

contract DepositContract is Ownable {
    using SafeMath for uint64;
    using SafeMath for uint256;

    struct BlockHeader {
        bytes32 prev;
        uint64 height;
        bytes32 stateRoot;
        bytes32 txRoot;
    }

    struct ExitTransaction {
        address from;
        uint256 amount;
        address color;
        uint64 nonce;
        bytes witness;
    }

    uint256 constant public BOND_SIZE = 1 ether;
    uint256 constant public FINALIZATION_DELAY = 6000; // ~ 1 day
    address constant public ZERO_ADDRESS = 0x0000000000000000000000000000000000000000;

    event Deposit(address from, uint256 amount, address color);

    bytes32[] public s_blockHashes;
    uint64 public s_tipHeight;
    uint256 public s_tipEthereumHeight;

    mapping(uint64 => mapping(bytes32 => bool)) public unspentExitsAtBlock;
    mapping(uint256 => bytes32[]) public unspentExitsNotFinalized;

    function computeBlockHeaderHash(BlockHeader memory header) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(header.prev, header.height, header.stateRoot, header.txRoot));
    }

    function computeExitTransactionID(ExitTransaction memory t) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(t.from, t.amount, t.color, t.nonce));
    }

    function validateFraudProof(bytes32 blockHash, bytes memory proof) internal pure returns (bool) {
        require(proof.length > 0);

        // TODO implement

        return false;
    }

    function postNewBlock(BlockHeader calldata header, bytes calldata txData, uint64 fraudAtHeight, bytes calldata fraudProof) external payable {
        require(header.height > 0);
        require(header.height <= s_tipHeight.add(1));
        require(header.prev == s_blockHashes[s_tipHeight]);
        require(msg.value == BOND_SIZE);
        require(s_tipEthereumHeight != block.number);
        require(fraudAtHeight > s_tipHeight.sub(FINALIZATION_DELAY));

        // Check fraud proof, if any
        if (fraudAtHeight > 0 && fraudAtHeight <= s_tipHeight) {
            require(validateFraudProof(s_blockHashes[fraudAtHeight], fraudProof));

            // Reset unspent exits if proof valid
            // TODO how much gas does this use?
            for (uint64 i = fraudAtHeight; i <= s_tipHeight; i++) {
                bytes32[] storage unspentExits = unspentExitsNotFinalized[i];

                for (uint256 j = 0; j < unspentExits.length; j++) {
                    unspentExitsAtBlock[i][unspentExits[j]] = false;
                }
                unspentExits.length = 0;
            }

            s_blockHashes.length = header.height;
        }
        require(header.height == s_blockHashes.length);

        // Merkleize transactions
        // TODO add exit transactions to unspentExits
        bytes32[] memory unspentExits;

        // If all checks pass, make the new block the tip
        bytes32 blockHash = computeBlockHeaderHash(header);
        s_blockHashes.push(blockHash);
        for (uint256 i = 0; i < unspentExits.length; i++) {
            unspentExitsAtBlock[header.height][unspentExits[i]] = true;
        }
        unspentExitsNotFinalized[header.height] = unspentExits;
        s_tipHeight = header.height;
        s_tipEthereumHeight = block.number;
    }

    function deposit() external payable {
        // TODO implement
        emit Deposit(msg.sender, msg.value, ZERO_ADDRESS);
    }

    function exit(uint64 blockHeight, ExitTransaction calldata exitTransaction) external {
        require(exitTransaction.color == ZERO_ADDRESS);
        require(msg.sender == exitTransaction.from);
        require(blockHeight <= s_tipHeight.sub(FINALIZATION_DELAY));

        bytes32 exitTransactionID = computeExitTransactionID(exitTransaction);
        require(unspentExitsAtBlock[blockHeight][exitTransactionID]);

        // Remove exit from unspent exits
        unspentExitsAtBlock[blockHeight][exitTransactionID] = false;

        // Withdraw funds
        msg.sender.transfer(exitTransaction.amount);
    }
}