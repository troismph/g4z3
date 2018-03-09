#!/usr/bin/env python
import hashlib
import functools
import unittest
import os


def get_hash(s):
    m = hashlib.sha256()
    m.update(s)
    return m.digest()


class MerkleTree:
    def __init__(self, leaves):
        def _build_merkle_level(leaves):
            pairs = [x for x in zip(
                leaves[0::2],
                leaves[1::2]
            )]
            if len(leaves) % 2 == 1:
                pairs.append((leaves[-1], ''))
            nodes = [x for x in map(
                lambda x: get_hash(x[0] + x[1]),
                pairs
            )]
            return nodes

        # build a BINARY merkle tree from leaves
        # also return path for each leave
        def _build_merkle_tree(leaves):
            levels = []
            l = leaves
            levels.insert(0, l)
            while len(l) > 1:
                l = _build_merkle_level(l)
                levels.insert(0, l)
            return levels
        self._levels = _build_merkle_tree(leaves)

    def root(self):
        return self._levels[0][0]

    def height(self):
        return len(self._levels)

    def get(self, depth, idx):
        return self._levels[depth][idx]


def get_children(idx):
    return (idx * 2, idx * 2 + 1)


def get_parent(idx):
    return idx // 2


# check leaves for errors
def check(leaves, mtree):
    my_mtree = MerkleTree(leaves)
    if my_mtree.root() == mtree.root():
        return None
    if my_mtree.height() != mtree.height():
        return [x for x in range(len(leaves))]
    mismatches = [0]
    for depth in range(1, my_mtree.height()):
        tests = functools.reduce(
            lambda x, y: x + y,
            [get_children(x) for x in mismatches]
        )
        mismatches = []
        for t in tests:
            mine = my_mtree.get(depth, t)
            theirs = mtree.get(depth, t)
            if mine != theirs:
                mismatches.append(t)
    return mismatches


class TestMerkleTree(unittest.TestCase):
    def get_mock_hash(self):
        return os.urandom(32)

    def get_leaves(self, n):
        return [
            self.get_mock_hash() for x in range(n)
        ]

    def mod(self, leaves, indices):
        mods = leaves.copy()
        for idx in indices:
            mods[idx] = self.get_mock_hash()
        return mods

    def test_check(self):
        leaves = self.get_leaves(256)
        mtree = MerkleTree(leaves)
        mod = [
            [0],
            [0, 1],
            [1, 2],
            [1, 3],
            [3, 4, 5, 6, 8, 11, 19]
        ]
        for mod_idx in mod:
            leaves_mod = self.mod(leaves, mod_idx)
            mismatches = check(leaves_mod, mtree)
            print(mod_idx)
            print(mismatches)
            self.assertEqual(mod_idx, mismatches)


if __name__ == "__main__":
    unittest.main()
