pragma solidity ^0.5.8;

/// @title Library to check Merkle proofs.
/// @dev Only trees of height 256+1 or less are supported.
library MerkleProof256 {
    /// @notice Verify a Merkle proof.
    /// @param proof List of hashes. Leaf's neighbor is first.
    /// @param directions Direction of sibling along Merkle branch as a bitmap. If bit is 1, sibling proof element
    ///         is on the left. If bit is 1, sibling is on the right. Leaf's sibling is LSB.
    /// @param root Root of Merkle tree.
    /// @param leaf Leaf of verify.
    /// @return True is the proof is valid, false otherwise.
    function verify(bytes32[] memory proof, uint256 directions, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        require(proof.length <= 256);

        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            bool isLeft = directions & (1 << i) == 1;

            if (isLeft) {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            } else {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            }
        }

        return computedHash == root;
    }
}