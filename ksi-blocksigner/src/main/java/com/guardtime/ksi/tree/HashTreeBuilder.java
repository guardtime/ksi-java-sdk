/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

package com.guardtime.ksi.tree;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.hashing.HashException;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedList;

import static com.guardtime.ksi.util.Util.notNull;

/**
 * This class is a hash tree (aka Merkle tree) builder implementation. Hash tree is a tree in which every non-leaf node
 * is labelled with the hash of the labels or values (in case of leaves) of its child nodes.
 * <p/>
 * Note that {@link HashTreeBuilder} works only with {@link ImprintNode} objects. Current implementation calculates the
 * parent hash by connecting the child node values and the parent node height before hashing.
 * <p/>
 * Note that this builder can not be used multiple times.
 */
public class HashTreeBuilder implements TreeBuilder<ImprintNode> {

    private static final Logger LOGGER = LoggerFactory.getLogger(HashTreeBuilder.class);

    private static final HashAlgorithm DEFAULT_HASH_ALGORITHM = HashAlgorithm.SHA2_256;

    /**
     * Queue for holding the head (root) nodes of hash subtrees.
     */
    private final LinkedList<ImprintNode> heads = new LinkedList<ImprintNode>();

    /**
     * Hash algorithm used to calculate the tree hashes.
     */
    private final HashAlgorithm algorithm;

    /**
     * Creates a new hash tree builder with given hash algorithm.
     *
     * @param algorithm
     *         hash algorithm to be used to calculate tree node hashes
     */
    public HashTreeBuilder(HashAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Creates a new hash tree builder with default hash algorithm.
     */
    public HashTreeBuilder() {
        this(DEFAULT_HASH_ALGORITHM);
    }

    /**
     * Adds a new single child node to the hash tree
     */
    public void add(ImprintNode node) throws HashException {
        addToHeads(heads, node);
    }

    public long calculateHeight(ImprintNode node) throws HashException {
        LinkedList<ImprintNode> tmpHeads = new LinkedList<ImprintNode>(heads);
        addToHeads(tmpHeads, node);

        ImprintNode root = getRootNode(tmpHeads);
        LOGGER.debug("Adding node with hash {} and height {}, the hash tree height would be {}", node.getValue(), node.getLevel(),
                root.getLevel());
        return root.getLevel();
    }

    /**
     * Adds a new array of child nodes to the hash tree
     */
    public void add(ImprintNode... nodes) throws HashException {
        notNull(nodes, "Nodes");
        for (ImprintNode node : nodes) {
            add(node);
        }
    }

    /**
     * Builds the hash tree and returns the root hash of the tree.
     */
    public ImprintNode build() throws HashException {
        if (heads.isEmpty()) {
            throw new IllegalStateException("Add leaf nodes before building a tree");
        }
        return getRootNode(heads);
    }

    private ImprintNode getRootNode(LinkedList<ImprintNode> heads) {
        ImprintNode previous = heads.getLast();
        if (heads.size() > 1) {
            for (int i = heads.size() - 2; i > -1; i--) {
                ImprintNode current = heads.get(i);
                previous = aggregate(previous, current);
            }
        }
        return previous;
    }

    private void addToHeads(LinkedList<ImprintNode> heads, ImprintNode node) throws HashException {
        notNull(node, "Node");
        LOGGER.debug("Adding node with hash {} and height {} to the hash tree", node.getValue(), node.getLevel());
        ImprintNode n = node;
        if (!heads.isEmpty()) {
            ImprintNode head = heads.getLast();
            if (head.getLevel() <= n.getLevel()) {
                heads.removeLast();
                addToHeads(heads, aggregate(head, n));
                return;
            }
        }
        heads.add(n);
        LOGGER.debug("New root added. Roots size is {}", heads.size());
    }

    private ImprintNode aggregate(ImprintNode left, ImprintNode right) throws HashException {
        long newLevel = Math.max(left.getLevel(), right.getLevel()) + 1;
        LOGGER.debug("Aggregating. Left {}(level={}), right {}(level={}), newLevel={}", left.getValue(), left.getLevel(), right.getValue(), right.getLevel(), newLevel);
        DataHash nodeHash = hash(algorithm, left.getValue(), right.getValue(), newLevel);
        LOGGER.info("Aggregation result {}(level={})", nodeHash, newLevel);
        return new ImprintNode(left, right, nodeHash, newLevel);
    }

    private DataHash hash(HashAlgorithm hashAlgorithm, byte[] left, byte[] right, long level) throws HashException {
        DataHasher hasher = new DataHasher(hashAlgorithm);
        hasher.addData(left).addData(right);
        hasher.addData(Util.encodeUnsignedLong(level));
        return hasher.getHash();
    }

}
