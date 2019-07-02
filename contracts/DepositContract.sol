pragma solidity ^0.5.8;

pragma experimental ABIEncoderV2;

import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";

import "contracts/libs/MerkleProof256.sol";

contract DepositContract  {
    using SafeMath for uint256;

    struct BlockCommitment {
        bytes32 hash;
        uint256 ethereumHeight;
        address payable from;
        bool isNotFinalized;
    }

    struct BlockHeader {
        // TODO maybe store a Merkle accumulator of prev blocks?
        bytes32 prev;
        uint256 height;
        bytes32 stateRoot;
        bytes32 txRoot;
    }

    struct ExitWitness {
        bytes32 r;
        bytes32 s;
        byte v;
    }

    struct ExitTransaction {
        address payable from;
        uint256 amount;
        bool isColored;
        address color;
        uint64 nonce;
        ExitWitness witness;
    }

    uint256 constant public BOND_SIZE = 1 ether;
    uint256 constant public FINALIZATION_DELAY = 6000; // ~ 1 day
    address constant public ZERO_ADDRESS = address(0);

    enum FraudType { DoubleSpend, InvalidWitness, InvalidAmounts, SpendNonOutput }

    event Deposit(address from, uint256 amount, address color, uint256 nonce);

    BlockCommitment[] public s_commitments;
    uint256 public s_tipHeight = 0;
    uint256 public s_depositNonce = 0;

    mapping(uint256 => mapping(bytes32 => bool)) public unspentExitsAtBlock;
    mapping(uint256 => bytes32[]) public unspentExitsNotFinalized;
    mapping(uint256 => mapping(bytes32 => bool)) public unspentDepositsAtEthereumBlock;

    function computeBlockHeaderHash(BlockHeader memory header) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(header.prev, header.height, header.stateRoot, header.txRoot));
    }

    function computeDepositID(address sender, uint256 value, address color, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(sender, value, color, nonce));
    }

    function computeExitTransactionID(ExitTransaction memory t) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(t.from, t.amount, t.color, t.nonce));
    }

    function validateFraudProof(uint256 fraudAtHeight, bytes memory proof) internal view returns (bool) {
        require(proof.length > 0);

        bytes32 blockHash = s_commitments[fraudAtHeight].hash;

        // Parse fraud proof
        uint256 offset = 0;

        // First byte is the fraud type
        FraudType fraudType = FraudType(uint8(proof[offset++] & 0xff));

        if (fraudType == FraudType.DoubleSpend) {
            // Double-spending output within block
            // Two transactions included at fraudAtHeight spend the same input

            // Tx 1

            // Inclusion proof 1

            // Input index 1

            // Tx 2

            // Inclusion proof 2

            // Input index 2

            // Check: input at index 1 == input at index 2
        } else if (fraudType == FraudType.InvalidWitness) {
            // Invalid witness for tx
            // A transaction included at fraudAtHeight has witness pubkey != output owner

            // Tx

            // Inclusion proof

            // Witness index

            // Input index

            // Check: witness pubkey != input at index owner
        } else if (fraudType == FraudType.InvalidAmounts) {
            // Invalid amounts in/out for tx
            // A transaction included at fraudAtHeight has outputs > inputs

            // Tx

            // Inclusion proof

            // Check: amounts out > amounts in
        } else if (fraudType == FraudType.SpendNonOutput) {
            // Spending non-existent output
            // An input to a transaction included at fraudAtHeight is excluded from state at fraudAtHeight
            //  TODO also excluded from outputs at fraudAtHeight?

            // Tx

            // Inclusion proof

            // Input index

            // State

            // Exclusion proof

            // Check: input at index == excluded state
        } else {
            revert();
        }

        return false;
    }

    constructor() public {
        // TODO genesis block hash
        s_commitments.push(BlockCommitment(0, block.number, msg.sender, false));
        s_tipHeight = 0;
    }

    function postNewBlock(BlockHeader calldata header, bytes calldata txData, uint256 fraudAtHeight, bytes calldata fraudProof) external payable {
        require(header.height > 0);
        require(header.height <= s_tipHeight.add(1));
        require(header.prev == s_commitments[s_tipHeight].hash);
        require(msg.value == BOND_SIZE);
        require(s_commitments[s_tipHeight].ethereumHeight != block.number);

        // Check fraud proof, if any
        // Note: if fraudAtHeight is higher than tip, then maybe a separate valid fraud proof was posted before
        if (fraudAtHeight > 0 && fraudAtHeight <= s_tipHeight) {
            require(validateFraudProof(fraudAtHeight, fraudProof));
            require(s_commitments[fraudAtHeight].isNotFinalized);
            require(s_commitments[fraudAtHeight].ethereumHeight >= block.number.sub(FINALIZATION_DELAY));

            // Reset unspent exits if proof valid
            // TODO how much gas does this use? maybe split it up and keep track of stale range
            for (uint256 i = fraudAtHeight; i <= s_tipHeight; i++) {
                bytes32[] storage unspentExits = unspentExitsNotFinalized[i];

                for (uint256 j = 0; j < unspentExits.length; j++) {
                    unspentExitsAtBlock[i][unspentExits[j]] = false;
                }
                unspentExits.length = 0;
            }

            s_commitments.length = header.height;
            s_tipHeight = fraudAtHeight.sub(1);
        }
        require(header.height == s_tipHeight.add(1));

        // Merkleize transactions and check against tx root
        // TODO merkleize
        // TODO add exit transactions to unspentExits
        // TODO remove deposit spends from unspent deposits
        // TODO check that deposits are mature (finalized)
        bytes32 txRoot;
        bytes32[] memory unspentExits;
        require(header.txRoot == txRoot);

        // If all checks pass, make the new block the tip
        bytes32 blockHash = computeBlockHeaderHash(header);
        s_commitments.push(BlockCommitment(blockHash, block.number, msg.sender, true));
        for (uint256 i = 0; i < unspentExits.length; i++) {
            unspentExitsAtBlock[header.height][unspentExits[i]] = true;
        }
        unspentExitsNotFinalized[header.height] = unspentExits;
        s_tipHeight = header.height;
    }

    function finalizeBlock(uint256 height) external {
        require(s_commitments[height].isNotFinalized);
        require(s_commitments[height].ethereumHeight < block.number.sub(FINALIZATION_DELAY));

        address payable from = s_commitments[height].from;

        delete s_commitments[height].hash;
        delete s_commitments[height].ethereumHeight;
        delete s_commitments[height].from;
        s_commitments[height].isNotFinalized = false;

        delete unspentExitsNotFinalized[height];

        from.transfer(BOND_SIZE);
    }

    function deposit() external payable {
        bytes32 depositID = computeDepositID(msg.sender, msg.value, ZERO_ADDRESS, s_depositNonce);
        unspentDepositsAtEthereumBlock[block.number][depositID] = true;

        emit Deposit(msg.sender, msg.value, ZERO_ADDRESS, s_depositNonce++);
    }

    function depositTokens(address tokenContract, uint256 value) external {
        require(IERC20(tokenContract).transferFrom(msg.sender, address(this), value));

        bytes32 depositID = computeDepositID(msg.sender, value, tokenContract, s_depositNonce);
        unspentDepositsAtEthereumBlock[block.number][depositID] = true;

        emit Deposit(msg.sender, value, tokenContract, s_depositNonce++);
    }

    function exit(uint256 height, ExitTransaction calldata exitTransaction) external {
        require(exitTransaction.isColored == false);
        require(height <= s_tipHeight);
        require(!s_commitments[height].isNotFinalized);

        bytes32 exitTransactionID = computeExitTransactionID(exitTransaction);
        require(unspentExitsAtBlock[height][exitTransactionID]);

        // Remove exit from unspent exits
        unspentExitsAtBlock[height][exitTransactionID] = false;

        // Withdraw funds
        exitTransaction.from.transfer(exitTransaction.amount);
    }

    function exitTokens(uint256 height, ExitTransaction calldata exitTransaction) external {
        require(exitTransaction.isColored == true);
        require(height <= s_tipHeight);
        require(!s_commitments[height].isNotFinalized);

        bytes32 exitTransactionID = computeExitTransactionID(exitTransaction);
        require(unspentExitsAtBlock[height][exitTransactionID]);

        // Remove exit from unspent exits
        unspentExitsAtBlock[height][exitTransactionID] = false;

        // Withdraw funds
        IERC20(exitTransaction.color).transfer(exitTransaction.from, exitTransaction.amount);
    }
}