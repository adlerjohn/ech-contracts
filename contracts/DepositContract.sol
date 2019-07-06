pragma solidity ^0.5.8;

pragma experimental ABIEncoderV2;

import "openzeppelin-solidity/contracts/cryptography/ECDSA.sol";
import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";

import "contracts/libs/BytesLib.sol";
import "contracts/libs/MerkleProof256.sol";

contract DepositContract  {
    using SafeMath for uint256;

    ///
    /// Data structures
    ///

    struct BlockCommitment {
        bytes32 hash;
        uint256 ethereumHeight;
        address payable from;
        bool isNotFinalized;
        bytes32[] deposits;
        bytes32[] exits;
    }

    struct BlockHeader {
        // TODO maybe store a Merkle accumulator of prev blocks?
        bytes32 prev;
        uint256 height;
        bytes32 stateRoot;
        bytes32 intermediateStateRootRoot;
        bytes32 txRoot;
    }

    // Support only a single token for now
    struct StateElement {
        address account;
        uint256 balance;
        uint256 balanceToken;
        uint256 nonce;
    }

    struct Witness {
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    struct TransactionData {
        address payable from;
        address to;
        uint256 amount;
        bool isColored;
        uint256 fee;
        uint64 nonce;
        bytes32 memo;
    }

    struct Transaction {
        TransactionData data;
        Witness witness;
    }

    ///
    /// Types and constants
    ///

    uint256 constant public BOND_SIZE = 1 ether;
    uint256 constant public FINALIZATION_DELAY = 6000; // ~ 1 day
    address constant public ZERO_ADDRESS = address(0);

    address constant public DAI_ADDRESS = 0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359;

    enum FraudType { InvalidCollectedFee, DoubleSpendDeposit, InvalidStateTransition }

    event Deposit(address from, uint256 amount, uint256 nonce);
    event DepositToken(address from, uint256 amount, address color, uint256 nonce);

    ///
    /// State members
    ///

    // Array of non-finalized block commitments. After finalization, only keep header hash around.
    // TODO store a merkle root of previous header hashes
    BlockCommitment[] public s_commitments;
    // Height of the side chain tip
    uint256 public s_tipHeight = 0;
    // Hash of previous block to side chain tip
    bytes32 public s_tipPrev;
    // Height of the earliest stale side chain block. Used when re-orging due to fraud proof.
    uint256 public s_staleHeight = 1;
    // Incremental nonce for all deposits.
    uint256 public s_depositNonce = 0;
    // Unspent deposits
    mapping(bytes32 => address) public s_unspentDeposits;
    // Unspent exits
    mapping(bytes32 => bool) public s_unspentExits;

    ///
    /// Helper functions
    ///

    function computeBlockHeaderHash(BlockHeader memory header) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(header.prev, header.height, header.stateRoot, header.intermediateStateRootRoot, header.txRoot));
    }

    function computeDepositID(address sender, uint256 value, address color, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(sender, value, color, nonce));
    }

    function computeTransactionID(Transaction memory t) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(t.data.from, t.data.to, t.data.amount, t.data.isColored, t.data.fee, t.data.nonce, t.data.memo));
    }

    function computeStateElementHash(StateElement memory e) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(e.balance, e.balanceToken));
    }

    function parseTxFromProof(bytes memory proof, uint256 offset) internal pure returns (Transaction memory, uint256) {
        address payable from = BytesLib.toAddress(proof, offset);
        offset += 20;
        address to = BytesLib.toAddress(proof, offset);
        offset += 20;
        uint256 amount = BytesLib.toUint256(proof, offset);
        offset += 32;
        bool isColored = (BytesLib.toUint8(proof, offset) == 1);
        offset++;
        uint256 fee = BytesLib.toUint256(proof, offset);
        offset += 32;
        uint64 nonce = BytesLib.toUint64(proof, offset);
        offset += 8;
        bytes32 memo = BytesLib.toBytes32(proof, offset);
        offset += 32;
        bytes32 r = BytesLib.toBytes32(proof, offset);
        offset += 32;
        bytes32 s = BytesLib.toBytes32(proof, offset);
        offset == 32;
        uint8 v = BytesLib.toUint8(proof, offset);
        offset++;

        Transaction memory t = Transaction(TransactionData(from, to, amount, isColored, fee, nonce, memo), Witness(r, s, v));
        return (t, offset);
    }

    function parseMerkleProofFromProof(bytes memory proof, uint256 offset) internal pure returns (bytes32[] memory, uint256, uint256) {
        uint16 len = BytesLib.toUint8(proof, offset);
        offset += 2;

        require(len <= 256);

        bytes32[] memory merkleProof = new bytes32[](len);
        for (uint16 i = 0; i < len; i++) {
            merkleProof[i] = (BytesLib.toBytes32(proof, offset));
            offset += 32;
        }
        uint256 directions = BytesLib.toUint256(proof, offset);
        offset += 32;

        return (merkleProof, directions, offset);
    }

    function parseStateElementFromProof(bytes memory proof, uint256 offset) internal pure returns (StateElement memory, uint256) {
        address account = BytesLib.toAddress(proof, offset);
        offset += 20;
        uint256 balance = BytesLib.toUint256(proof, offset);
        offset += 32;
        uint256 balanceToken = BytesLib.toUint256(proof, offset);
        offset += 32;
        uint256 nonce = BytesLib.toUint256(proof, offset);
        offset += 32;

        StateElement memory e = StateElement(account, balance, balanceToken, nonce);
        return (e, offset);
    }

    function verifyInclusionProof(bytes memory proof, uint256 offset, bytes32 root, bytes32 leafHash) internal pure returns (bool, uint256, uint256) {
        bytes32[] memory inclusionProof;
        uint256 directions;
        (inclusionProof, directions, offset) = parseMerkleProofFromProof(proof, offset);

        if (!MerkleProof256.verify(inclusionProof, directions, root, leafHash)) {
            return (false, directions, offset);
        }

        return (true, directions, offset);
    }

    function validateFraudProof(uint256 fraudAtHeight, BlockHeader memory header, bytes memory proof) internal view returns (bool) {
        require(proof.length > 0);
        require(computeBlockHeaderHash(header) == s_commitments[fraudAtHeight].hash);

        // Parse fraud proof
        uint256 offset = 0;

        // First byte is the fraud type
        FraudType fraudType = FraudType(BytesLib.toUint8(proof, offset++));

        if (fraudType == FraudType.InvalidStateTransition) {
            bool result = false;
            bytes32 tempRoot;
            uint256 directions1;
            uint256 directions2;

            ///
            /// Parse proof and sanity checks
            ///

            // Tx
            Transaction memory t;
            (t, offset) = parseTxFromProof(proof, offset);
            bytes32 txID = computeTransactionID(t);

            // Pre state root
            tempRoot = BytesLib.toBytes32(proof, offset);
            offset += 32;

            // Inclusion proof: pre state root
            (result, directions1, offset) = verifyInclusionProof(proof, offset, header.intermediateStateRootRoot, tempRoot);
            if (!result) {
                return false;
            }

            // Post state root
            tempRoot = BytesLib.toBytes32(proof, offset);
            offset += 32;

            // Inclusion proof: post state root
            (result, directions2, offset) = verifyInclusionProof(proof, offset, header.intermediateStateRootRoot, tempRoot);
            if (!result) {
                return false;
            }

            // Check directions adjacent
            if (directions1.add(1) != directions2) {
                return false;
            }

            // Pre state from
            StateElement memory e_preFrom;
            (e_preFrom, offset) = parseStateElementFromProof(proof, offset);

            // Inclusion proof: pre state from
            (result, directions1, offset) = verifyInclusionProof(proof, offset, tempRoot, computeStateElementHash(e_preFrom));
            if (!result) {
                return false;
            }

            // Post state from
            StateElement memory e_postFrom;
            (e_postFrom, offset) = parseStateElementFromProof(proof, offset);

            // Inclusion proof: post state from
            (result, directions1, offset) = verifyInclusionProof(proof, offset, tempRoot, computeStateElementHash(e_postFrom));
            if (!result) {
                return false;
            }

            // Check pre from == post from
            if (e_preFrom.account != e_postFrom.account) {
                return false;
            }

            // Pre state to
            StateElement memory e_preTo;
            (e_preTo, offset) = parseStateElementFromProof(proof, offset);

            // Inclusion proof: pre state to
            (result, directions2, offset) = verifyInclusionProof(proof, offset, tempRoot, computeStateElementHash(e_preTo));
            if (!result) {
                return false;
            }

            // Post state to
            StateElement memory e_postTo;
            (e_postTo, offset) = parseStateElementFromProof(proof, offset);

            // Inclusion proof: post state to
            (result, directions2, offset) = verifyInclusionProof(proof, offset, tempRoot, computeStateElementHash(e_postTo));
            if (!result) {
                return false;
            }

            // Check pre to == post to
            if (e_preTo.account != e_postTo.account) {
                return false;
            }

            ///
            /// Validate state transition
            ///

            if (t.data.from != e_preFrom.account || t.data.to != e_preTo.account) {
                // Check touched accounts for transaction
                if (computeStateElementHash(e_preFrom) != computeStateElementHash(e_postFrom) && computeStateElementHash(e_preTo) != computeStateElementHash(e_postTo)) {
                    return true;
                }
            } else {
                // Check nonce
                if (e_preFrom.nonce.add(1) != t.data.nonce || e_postFrom.nonce != t.data.nonce) {
                    return true;
                }

                // Check witness
                address a = ecrecover(ECDSA.toEthSignedMessageHash(txID), t.witness.v, t.witness.r, t.witness.s);
                if (a != t.data.from) {
                    return true;
                }

                // Check amounts in transaction
                if (!t.data.isColored) {
                    uint256 paid = t.data.amount + t.data.fee;
                    if (paid < t.data.amount || // no overflow on fees
                        e_preFrom.balance - paid > e_preFrom.balance || // no underflow on paid
                        e_preTo.balance + t.data.amount < e_preTo.balance || // no overflow on paid
                        e_preFrom.balance - paid != e_postFrom.balance || // correct debit
                        e_preTo.balance + t.data.amount != e_postTo.balance // correct credit
                    ) {
                        return true;
                    }
                } else {
                    if (e_preFrom.balance - t.data.fee > e_preFrom.balance || // no underflow on fees
                        e_preFrom.balanceToken - t.data.amount > e_preFrom.balanceToken || // no underflow on paid
                        e_preTo.balanceToken + t.data.amount < e_preTo.balanceToken || // no overflow on paid
                        e_preFrom.balance - t.data.fee != e_postFrom.balance || // correct fees
                        e_preFrom.balanceToken - t.data.amount != e_postFrom.balanceToken || // correct debit
                        e_preTo.balanceToken + t.data.amount != e_postTo.balanceToken // correct credit
                    ) {
                        return true;
                    }
                }
            }
        } else if (fraudType == FraudType.InvalidCollectedFee) {
            // Block producer collected too many fees
            // Fee collected is more than the sum of fees paid

            // Block data

            // Check: amount in first tx of block
            // TODO implement

            // TODO use Merkle sum tree for fees?
        } else if (fraudType == FraudType.DoubleSpendDeposit) {
            // TODO implement
        } else {
            return false;
        }

        return false;
    }

    ///
    /// Constructor
    ///

    constructor() public {
        // TODO genesis block hash
        bytes32 genesis = 0;
        bytes32[] memory deposits;
        bytes32[] memory exits;

        s_commitments.push(BlockCommitment(genesis, block.number, msg.sender, false, deposits, exits));
        s_tipPrev = genesis;
    }

    ///
    /// Public methods
    ///

    function postNewBlock(BlockHeader calldata header, bytes calldata txData, uint256 fraudAtHeight, BlockHeader calldata fraudHeader, bytes calldata fraudProof) external payable {
        require(header.height > 0);
        require(header.height <= s_tipHeight.add(1));
        require(header.prev == s_tipPrev);
        require(msg.value == BOND_SIZE);
        // TODO maybe allow multiple blocks at the same Ethereum height
        require(s_commitments[s_tipHeight].ethereumHeight != block.number);

        // Check fraud proof, if any
        postFraudProof(fraudAtHeight, fraudHeader, fraudProof);

        // Must built upon the tip
        require(header.height == s_tipHeight.add(1));

        // Merkleize transactions and check against tx root
        // TODO merkleize transactions
        // TODO add exit transactions to exits
        // TODO add deposit transactions deposits
        // TODO check that deposits exist

        // TODO merkleize intermediate state roots
        // TODO check first state root is prev block's state root
        // TODO check last state root is current block's state root
        // TODO check num state roots == num txs + 1
        bytes32 txRoot;
        bytes32[] memory deposits;
        bytes32[] memory exits;
        require(header.txRoot == txRoot);

        // If all checks pass, make the new block the tip

        // Clean up any stale block at this location
        uint256 staleHeight = s_staleHeight;
        if (staleHeight == header.height) {
            delete s_commitments[staleHeight];
            s_staleHeight = staleHeight.add(1);
        }

        // Set new chain tip
        bytes32 blockHash = computeBlockHeaderHash(header);
        s_commitments.push(BlockCommitment(blockHash, block.number, msg.sender, true, deposits, exits));
        s_tipHeight = header.height;
        s_tipPrev = header.prev;
    }

    function postFraudProof(uint256 fraudAtHeight, BlockHeader memory fraudHeader, bytes memory fraudProof) public {
        // Note: if fraudAtHeight is higher than tip, then maybe a separate valid fraud proof was posted before
        if (fraudAtHeight > 0 && fraudAtHeight <= s_tipHeight) {
            require(s_commitments[fraudAtHeight].isNotFinalized);
            require(s_commitments[fraudAtHeight].ethereumHeight >= block.number.sub(FINALIZATION_DELAY));
            require(validateFraudProof(fraudAtHeight, fraudHeader, fraudProof));

            // If fraud proof valid, set stale range
            s_staleHeight = fraudAtHeight;

            s_tipHeight = fraudAtHeight.sub(1);
            s_staleHeight = fraudAtHeight;
        }
    }

    function finalizeBlock(uint256 height) external {
        BlockCommitment memory commitment = s_commitments[height];
        require(commitment.isNotFinalized);
        require(commitment.ethereumHeight > 0);
        require(commitment.ethereumHeight < block.number.sub(FINALIZATION_DELAY));
        require(height < s_staleHeight);

        address payable from = commitment.from;

        //delete commitment.hash;
        delete commitment.ethereumHeight;
        delete commitment.from;
        commitment.isNotFinalized = false;

        // Remove deposits from unspent deposits
        for (uint256 i = 0; i < commitment.deposits.length; i++) {
            delete s_unspentDeposits[commitment.deposits[i]];
        }
        delete commitment.deposits;

        // Add exits to unspent exits
        for (uint256 i = 0; i < commitment.exits.length; i++) {
            s_unspentExits[commitment.exits[i]] = true;
        }
        delete commitment.exits;

        // Return bond
        from.transfer(BOND_SIZE);
    }

    function deposit() external payable {
        bytes32 depositID = computeDepositID(msg.sender, msg.value, ZERO_ADDRESS, s_depositNonce);
        s_unspentDeposits[depositID] = msg.sender;

        emit Deposit(msg.sender, msg.value, s_depositNonce++);
    }

    function depositTokens(address tokenContractAddress, uint256 value) external {
        // For now, only support DAI stablecoin
        require(tokenContractAddress == DAI_ADDRESS);
        require(IERC20(tokenContractAddress).transferFrom(msg.sender, address(this), value));

        bytes32 depositID = computeDepositID(msg.sender, value, tokenContractAddress, s_depositNonce);
        s_unspentDeposits[depositID] = msg.sender;

        emit DepositToken(msg.sender, value, tokenContractAddress, s_depositNonce++);
    }

    function exit(uint256 height, Transaction calldata t) external {
        require(t.data.isColored == false);
        require(t.data.to == ZERO_ADDRESS);
        require(height <= s_tipHeight);
        require(!s_commitments[height].isNotFinalized);

        bytes32 exitTransactionID = computeTransactionID(t);
        require(s_unspentExits[exitTransactionID]);

        // Remove exit from unspent exits
        s_unspentExits[exitTransactionID] = false;

        // Withdraw funds
        t.data.from.transfer(t.data.amount);
    }

    function exitTokens(uint256 height, Transaction calldata t) external {
        require(t.data.isColored == true);
        require(t.data.to == ZERO_ADDRESS);
        require(height <= s_tipHeight);
        require(!s_commitments[height].isNotFinalized);

        bytes32 exitTransactionID = computeTransactionID(t);
        require(s_unspentExits[exitTransactionID]);

        // Remove exit from unspent exits
        s_unspentExits[exitTransactionID] = false;

        // Withdraw funds
        IERC20(DAI_ADDRESS).transfer(t.data.from, t.data.amount);
    }
}