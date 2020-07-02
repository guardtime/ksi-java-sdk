/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */

package com.guardtime.ksi.tree;

import com.guardtime.ksi.blocksigner.IdentityMetadata;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.hashing.HashException;
import com.guardtime.ksi.unisignature.KSISignatureComponentFactory;
import com.guardtime.ksi.unisignature.LinkMetadata;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedList;

import static com.guardtime.ksi.util.Util.notNull;

/**
 * Hash tree (aka Merkle tree) builder implementation.
 * <p>Hash tree is a tree in which every non-leaf node
 * is labelled with the hash of the labels or values (in case of leaves) of its child nodes.
 * </p>
 * <p>
 * Note that {@link HashTreeBuilder} works only with {@link ImprintNode} objects.
 * Current implementation calculates the parent hash by connecting the child node
 * values and the parent node height before hashing.
 * </p>
 * This builder can not be used multiple times.
 */
public class HashTreeBuilder implements TreeBuilder<ImprintNode> {
    private static final KSISignatureComponentFactory SIGNATURE_COMPONENT_FACTORY = new InMemoryKsiSignatureComponentFactory();
    private static final Logger logger = LoggerFactory.getLogger(HashTreeBuilder.class);

    /**
     * Queue for holding the head (root) nodes of hash subtrees.
     */
    private final LinkedList<ImprintNode> heads = new LinkedList<>();

    /**
     * Hash algorithm used to calculate the tree hashes.
     */
    private final HashAlgorithm algorithm;

    /**
     * Creates a new hash tree builder with given hash algorithm.
     *
     * @param algorithm
     *         hash algorithm to be used to calculate tree node hashes.
     */
    public HashTreeBuilder(HashAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Creates a new hash tree builder with {@link Util#DEFAULT_AGGREGATION_ALGORITHM} hash algorithm.
     */
    public HashTreeBuilder() {
        this(Util.DEFAULT_AGGREGATION_ALGORITHM);
    }

    /**
     * Adds a new single child node to the hash tree.
     *
     * @param node child node to be added.
     *
     * @throws HashException
     */
    public void add(ImprintNode node) throws HashException {
        addToHeads(heads, node);
    }

    /**
     * Adds a new leaf with its metadata to the hash tree.
     *
     * @param node leaf node to be added, must not be null.
     * @param metadata node's metadata, must not be null
     * @throws HashException
     * @throws KSIException
     */
    public void add(ImprintNode node, IdentityMetadata metadata) throws HashException, KSIException {
        addToHeads(heads, aggregate(node, metadata));
    }

    /**
     * Calculates the height of the hash tree in case a new node would be added.
     *
     * @param node
     *         a leaf to be added to the tree, must not be null.
     *
     * @return Height of the hash tree.
     *
     * @throws HashException
     */
    public long calculateHeight(ImprintNode node) throws HashException {
        LinkedList<ImprintNode> tmpHeads = new LinkedList<>();
        for (ImprintNode in : heads) {
            tmpHeads.add(new ImprintNode(in));
        }

        addToHeads(tmpHeads, new ImprintNode(node));

        ImprintNode root = getRootNode(tmpHeads);
        logger.debug("Adding node with hash {} and height {}, the hash tree height would be {}", node.getValue(), node.getLevel(),
                root.getLevel());
        return root.getLevel();
    }

    /**
     * Calculates the height of the hash tree in case a new node with metadata would be added.
     *
     * @param node     a leaf to be added to the tree, must not be null.
     * @param metadata metadata associated with the node.
     * @return Height of the hash tree.
     * @throws HashException
     * @throws KSIException
     */
    public long calculateHeight(ImprintNode node, IdentityMetadata metadata) throws HashException, KSIException {
        return calculateHeight(aggregate(node, metadata));
    }

    /**
     * Adds a new array of child nodes to the hash tree.
     *
     * @param nodes array of nodes to be added.
     *
     * @throws HashException
     */
    public void add(ImprintNode... nodes) throws HashException {
        notNull(nodes, "Nodes");
        for (ImprintNode node : nodes) {
            add(node);
        }
    }

    /**
     * Builds the hash tree and returns the root hash of the tree.
     *
     * @return Root hash of the finished tree.
     *
     * @throws HashException
     */
    public ImprintNode build() throws HashException {
        if (heads.isEmpty()) {
            throw new IllegalStateException("Add leaf nodes before building a tree");
        }
        return getRootNode(heads);
    }

    protected ImprintNode getRootNode(LinkedList<ImprintNode> heads) {
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
        logger.debug("Adding node with hash {} and height {} to the hash tree", node.getValue(), node.getLevel());
        ImprintNode n = node.hasMetadata() ? (ImprintNode) node.getParent() : node;
        if (!heads.isEmpty()) {
            ImprintNode head = heads.getLast();
            if (head.getLevel() <= n.getLevel()) {
                heads.removeLast();
                addToHeads(heads, aggregate(head, n));
                return;
            }
        }
        heads.add(n);
        logger.debug("New root added. Roots size is {}", heads.size());
    }

    protected ImprintNode aggregate(ImprintNode left, ImprintNode right) throws HashException {
        long newLevel = Math.max(left.getLevel(), right.getLevel()) + 1;
        logger.debug("Aggregating. Left {}(level={}), right {}(level={}), newLevel={}", left.getValue(), left.getLevel(), right.getValue(), right.getLevel(), newLevel);
        DataHash nodeHash = com.guardtime.ksi.tree.Util.hash(algorithm, left.getValue(), right.getValue(), newLevel);
        logger.info("Aggregation result {}(level={})", nodeHash, newLevel);
        return new ImprintNode(left, right, nodeHash, newLevel);
    }

    private ImprintNode aggregate(ImprintNode node, IdentityMetadata metadata) throws KSIException {
        notNull(metadata, "IdentityMetadata");
        notNull(node, "ImprintNode");
        byte[] metadataBytes = getMetadataBytes(metadata);
        MetadataNode metadataNode = new MetadataNode(metadataBytes, node.getLevel());
        long parentLevel = node.getLevel() + 1;
        DataHash hash = com.guardtime.ksi.tree.Util.hash(algorithm, node.getValue(), metadataBytes, parentLevel);
        return new ImprintNode(node, metadataNode, hash, parentLevel);
    }

    private byte[] getMetadataBytes(IdentityMetadata metadata) throws KSIException {
        LinkMetadata linkMetadata = SIGNATURE_COMPONENT_FACTORY.createLinkMetadata(metadata.getClientId(),
                metadata.getMachineId(), metadata.getSequenceNumber(), metadata.getRequestTime());
        return linkMetadata.getMetadataStructure().getRootElement().getContent();
    }
}
