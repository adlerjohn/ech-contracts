pragma solidity ^0.5.8;

pragma experimental ABIEncoderV2;

import "openzeppelin-solidity/contracts/cryptography/ECDSA.sol";
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

    // Support only a single token for now
    struct StateElement {
        uint256 balance;
        uint256 balanceToken;
    }

    struct Witness {
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    struct Transaction {
        address payable from;
        address to;
        uint256 amount;
        bool isColored;
        uint256 fee;
        uint64 nonce;
        bytes32 data;
        Witness witness;
    }

    uint256 constant public BOND_SIZE = 1 ether;
    uint256 constant public FINALIZATION_DELAY = 6000; // ~ 1 day
    address constant public ZERO_ADDRESS = address(0);

    address constant public DAI_ADDRESS = 0x89d24A6b4CcB1B6fAA2625fE562bDD9a23260359;

    enum FraudType { MalformedTx, DoubleSpend, InvalidWitness, InvalidAmounts, InvalidCollectedFee }

    event Deposit(address from, uint256 amount, uint256 nonce);
    event DepositToken(address from, uint256 amount, address color, uint256 nonce);

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

    function computeTransactionID(Transaction memory t) internal pure returns (bytes32) {
        if (t.from == ZERO_ADDRESS) {
            return keccak256(abi.encodePacked(t.from, t.to, t.amount, t.isColored, t.fee, t.nonce, t.data));
        }
        return keccak256(abi.encodePacked(t.from, t.amount, t.isColored, t.fee, t.nonce));
    }

    function computeStateElementHash(StateElement memory e) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(e.balance, e.balanceToken));
    }

    function parseTxFromProof(bytes memory proof, uint256 offset) internal pure returns (Transaction memory, uint256) {
        // TODO implement
        Transaction memory t;
        return (t, 0);
    }

    function parseMerkleProofFromProof(bytes memory proof, uint256 offset) internal pure returns (bytes32[] memory, uint256, uint256) {
        // TODO implement
        bytes32[] memory merkleProof;
        uint256 directions;
        return (merkleProof, directions, 0);
    }

    function parseStateElementFromProof(bytes memory proof, uint256 offset) internal pure returns (StateElement memory, uint256) {
        // TODO implement
        StateElement memory e;
        return (e, 0);
    }

    function validateFraudProof(uint256 fraudAtHeight, BlockHeader memory header, bytes memory proof) internal view returns (bool) {
        require(proof.length > 0);

        require(computeBlockHeaderHash(header) == s_commitments[fraudAtHeight].hash);

        // Parse fraud proof
        uint256 offset = 0;

        // First byte is the fraud type
        FraudType fraudType = FraudType(uint8(proof[offset++]));

        if (fraudType == FraudType.MalformedTx) {
            // A transaction isn't properly formed
            // A transaction included at fraudAtHeight is malformed

            // Length of tx
            uint256 len;
            assembly {
                len := mload(add(proof, add(0x20, offset)))
            }
            offset += 32;

            // Tx bytes
            bytes memory txBytes;
            assembly {
                txBytes := mload(add(proof, add(len, offset)))
            }
            offset += len;

            // Inclusion proof
            bytes32[] memory inclusionProof;
            uint256 directions;
            (inclusionProof, directions, offset) = parseMerkleProofFromProof(proof, offset);

            bytes32 txID = keccak256(txBytes);
            if (!MerkleProof256.verify(inclusionProof, directions, header.txRoot, txID)) {
                return false;
            }

            // Check: transaction doesn't parse
            // TODO implement
        } else if (fraudType == FraudType.DoubleSpend) {
            // Double-spending output within block
            // Two transactions included at fraudAtHeight have same account and nonce

            // Tx 1
            Transaction memory t1;
            (t1, offset) = parseTxFromProof(proof, offset);

            // Inclusion proof 1
            bytes32[] memory inclusionProof1;
            uint256 directions1;
            (inclusionProof1, directions1, offset) = parseMerkleProofFromProof(proof, offset);

            if (!MerkleProof256.verify(inclusionProof1, directions1, header.txRoot, computeTransactionID(t1))) {
                return false;
            }

            // Tx 2
            Transaction memory t2;
            (t2, offset) = parseTxFromProof(proof, offset);

            // Inclusion proof 2
            bytes32[] memory inclusionProof2;
            uint256 directions2;
            (inclusionProof2, directions2, ) = parseMerkleProofFromProof(proof, offset);

            if (!MerkleProof256.verify(inclusionProof2, directions2, header.txRoot, computeTransactionID(t2))) {
                return false;
            }

            // Check: from of tx 1 == from of tx2 and nonce of tx 1 == nonce of tx 2
            if (t1.from == t2.from && t1.nonce == t2.nonce) {
                return true;
            }
        } else if (fraudType == FraudType.InvalidWitness) {
            // Invalid witness for tx
            // A transaction included at fraudAtHeight has witness pubkey address != address

            // Tx
            Transaction memory t;
            (t, offset) = parseTxFromProof(proof, offset);

            if (t.from == ZERO_ADDRESS) {
                return false;
            }

            // Inclusion proof
            bytes32[] memory inclusionProof;
            uint256 directions;
            (inclusionProof, directions, offset) = parseMerkleProofFromProof(proof, offset);

            bytes32 txID = computeTransactionID(t);
            if (!MerkleProof256.verify(inclusionProof, directions, header.txRoot, txID)) {
                return false;
            }

            // Check: witness pubkey address != address
            // TODO also handle non-ethSign (Metamask)?
            address a = ecrecover(ECDSA.toEthSignedMessageHash(txID), t.witness.v, t.witness.r, t.witness.s);
            if (a != t.from) {
                return true;
            }
        } else if (fraudType == FraudType.InvalidAmounts) {
            // Invalid amounts in/out for tx
            // A transaction included at fraudAtHeight has sent > balance

            // Tx
            Transaction memory t;
            (t, offset) = parseTxFromProof(proof, offset);

            // Inclusion proof
            bytes32[] memory inclusionProof;
            uint256 directions;
            (inclusionProof, directions, offset) = parseMerkleProofFromProof(proof, offset);

            if (!MerkleProof256.verify(inclusionProof, directions, header.txRoot, computeTransactionID(t))) {
                return false;
            }

            // State element
            StateElement memory e;
            (e, offset) = parseStateElementFromProof(proof, offset);

            // Inclusion proof
            bytes32[] memory inclusionProofState;
            uint256 directionsState;
            (inclusionProofState, directionsState, offset) = parseMerkleProofFromProof(proof, offset);

            if (inclusionProofState.length != 20 || address(uint160(directionsState)) != t.from) {
                return false;
            }

            if (!MerkleProof256.verify(inclusionProofState, directionsState, header.stateRoot, computeStateElementHash(e))) {
                return false;
            }

            // Check: amount sent + fees > balance
            if (!t.isColored && t.amount.add(t.fee) > e.balance ||
                 t.isColored && (t.fee > e.balance || t.amount > e.balanceToken)
                ) {
                return true;
            }
        } else if (fraudType == FraudType.InvalidCollectedFee) {
            // Block producer collected too many fees
            // Fee collected is more than the sum of fees paid

            // Block data

            // Check: amount in first tx of block
            // TODO implement

            // TODO use Merkle sum tree for fees?
        } else {
            return false;
        }

        return false;
    }

    constructor() public {
        // TODO genesis block hash
        s_commitments.push(BlockCommitment(0, block.number, msg.sender, false));
        s_tipHeight = 0;
    }

    function postNewBlock(BlockHeader calldata header, bytes calldata txData, uint256 fraudAtHeight, BlockHeader calldata fraudHeader, bytes calldata fraudProof) external payable {
        require(header.height > 0);
        require(header.height <= s_tipHeight.add(1));
        require(header.prev == s_commitments[s_tipHeight].hash);
        require(msg.value == BOND_SIZE);
        require(s_commitments[s_tipHeight].ethereumHeight != block.number);

        // Check fraud proof, if any
        // Note: if fraudAtHeight is higher than tip, then maybe a separate valid fraud proof was posted before
        if (fraudAtHeight > 0 && fraudAtHeight <= s_tipHeight) {
            require(validateFraudProof(fraudAtHeight, fraudHeader, fraudProof));
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

        emit Deposit(msg.sender, msg.value, s_depositNonce++);
    }

    function depositTokens(address tokenContract, uint256 value) external {
        // For now, only support DAI stablecoin
        require(tokenContract == DAI_ADDRESS);
        require(IERC20(tokenContract).transferFrom(msg.sender, address(this), value));

        bytes32 depositID = computeDepositID(msg.sender, value, tokenContract, s_depositNonce);
        unspentDepositsAtEthereumBlock[block.number][depositID] = true;

        emit DepositToken(msg.sender, value, tokenContract, s_depositNonce++);
    }

    function exit(uint256 height, Transaction calldata t) external {
        require(t.isColored == false);
        require(t.to == ZERO_ADDRESS);
        require(height <= s_tipHeight);
        require(!s_commitments[height].isNotFinalized);

        bytes32 exitTransactionID = computeTransactionID(t);
        require(unspentExitsAtBlock[height][exitTransactionID]);

        // Remove exit from unspent exits
        unspentExitsAtBlock[height][exitTransactionID] = false;

        // Withdraw funds
        t.from.transfer(t.amount);
    }

    function exitTokens(uint256 height, Transaction calldata t) external {
        require(t.isColored == true);
        require(t.to == ZERO_ADDRESS);
        require(height <= s_tipHeight);
        require(!s_commitments[height].isNotFinalized);

        bytes32 exitTransactionID = computeTransactionID(t);
        require(unspentExitsAtBlock[height][exitTransactionID]);

        // Remove exit from unspent exits
        unspentExitsAtBlock[height][exitTransactionID] = false;

        // Withdraw funds
        IERC20(DAI_ADDRESS).transfer(t.from, t.amount);
    }
}