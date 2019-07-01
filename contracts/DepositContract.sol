pragma solidity ^0.5.8;

pragma experimental ABIEncoderV2;

import "openzeppelin-solidity/contracts/math/SafeMath.sol";

import "contracts/libs/MerkleProof256.sol";

contract DepositContract  {
    using SafeMath for uint64;

    struct BlockHeader {
        bytes32 prev;
        uint64 height;
        bytes32 stateRoot;
        bytes32 txRoot;
    }

    struct ExitWitness {
        bytes32 witness_r;
        bytes32 witness_s;
        byte witness_v;
    }

    struct ExitTransaction {
        address from;
        uint256 amount;
        address color;
        uint64 nonce;
        ExitWitness witness;
    }

    uint256 constant public BOND_SIZE = 1 ether;
    uint256 constant public FINALIZATION_DELAY = 6000; // ~ 1 day
    address constant public ZERO_ADDRESS = 0x0000000000000000000000000000000000000000;

    event Deposit(address from, uint256 amount, address color, uint256 nonce);

    bytes32[] public s_blockHashes;
    uint64 public s_tipHeight = 0;
    uint256 public s_tipEthereumHeight = 0;
    uint256 public s_depositNonce = 0;

    mapping(uint64 => mapping(bytes32 => bool)) public unspentExitsAtBlock;
    mapping(uint256 => bytes32[]) public unspentExitsNotFinalized;

    function computeBlockHeaderHash(BlockHeader memory header) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(header.prev, header.height, header.stateRoot, header.txRoot));
    }

    function computeExitTransactionID(ExitTransaction memory t) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(t.from, t.amount, t.color, t.nonce));
    }

    function validateFraudProof(uint64 fraudAtHeight, bytes memory proof) internal view returns (bool) {
        require(proof.length > 0);

        bytes32 blockHash = s_blockHashes[fraudAtHeight];

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
            require(validateFraudProof(fraudAtHeight, fraudProof));

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

        // Merkleize transactions and check against tx root
        // TODO add exit transactions to unspentExits
        bytes32 txRoot;
        bytes32[] memory unspentExits;
        require(header.txRoot == txRoot);

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
        emit Deposit(msg.sender, msg.value, ZERO_ADDRESS, s_depositNonce++);
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