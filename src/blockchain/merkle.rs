use sha2::{Digest, Sha256};

const LEAF_TAG: &[u8] = b"NEZORA-NZR-MERKLE-LEAF-V2";
const NODE_TAG: &[u8] = b"NEZORA-NZR-MERKLE-NODE-V2";
const ODD_TAG: &[u8] = b"NEZORA-NZR-MERKLE-ODD-V2";
const ROOT_TAG: &[u8] = b"NEZORA-NZR-MERKLE-ROOT-V2";
const EMPTY_TAG: &[u8] = b"NEZORA-NZR-EMPTY-MERKLE-V2";

fn hash_tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn hash_leaf(value: &[u8; 32]) -> [u8; 32] {
    hash_tagged(LEAF_TAG, &[value])
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash_tagged(NODE_TAG, &[left, right])
}

fn hash_odd(value: &[u8; 32]) -> [u8; 32] {
    hash_tagged(ODD_TAG, &[value])
}

/// Builds a Merkle root with domain-separated leaves, internal nodes, odd
/// nodes, and a final leaf-count commitment. This avoids the ambiguity caused
/// by duplicating the final leaf at odd tree levels.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let count = (leaves.len() as u64).to_be_bytes();

    if leaves.is_empty() {
        return hash_tagged(EMPTY_TAG, &[&count]);
    }

    let mut level: Vec<[u8; 32]> = leaves.iter().map(hash_leaf).collect();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));

        for pair in level.chunks(2) {
            let parent = if pair.len() == 2 {
                hash_pair(&pair[0], &pair[1])
            } else {
                hash_odd(&pair[0])
            };
            next.push(parent);
        }

        level = next;
    }

    hash_tagged(ROOT_TAG, &[&count, &level[0]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_is_deterministic() {
        assert_eq!(merkle_root(&[]), merkle_root(&[]));
    }

    #[test]
    fn leaf_order_changes_root() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
    }

    #[test]
    fn odd_leaf_count_is_committed_unambiguously() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];

        assert_ne!(merkle_root(&[a, b, c]), merkle_root(&[a, b, c, c]));
    }

    #[test]
    fn different_leaf_counts_have_different_roots() {
        let a = [1u8; 32];
        assert_ne!(merkle_root(&[]), merkle_root(&[a]));
    }

    #[test]
    fn single_leaf_is_supported() {
        let a = [9u8; 32];
        assert_ne!(merkle_root(&[a]), [0u8; 32]);
    }
}
