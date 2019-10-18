/*
 * Copyright 2013-2019 Guardtime, Inc.
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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.util.Util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

/**
 * Hash tree (aka Merkle tree) builder implementation using blinding masks.
 *
 * <p>
 * Background:
 * A strong hash function can’t be directly reversed to learn the input value from which the hash value
 * in the chain was created. However, a typical log record may contain insufficient entropy to make that argument — an
 * attacker who knows the pattern of the input could exhaustively test all possible variants to find the one that yields
 * the hash value actually in the chain and thus learn the contents of the record. To prevent this kind of informed
 * brute-force attack, a blinding mask with sufficient entropy can be added to each record before aggregating the hash
 * values. (Source: https://www.researchgate.net/profile/Ahto_Truu/publication/290563005_Efficient_Record-Level_Keyless_Signatures_for_Audit_Logs/links/58b96d1092851c471d4a5888/Efficient-Record-Level-Keyless-Signatures-for-Audit-Logs.pdf page 3)
 *
 * <p>
 * {@link BlindingMaskLinkingHashTreeBuilder} does not support {@link IdentityMetadata} aggregation and methods
 * {@link BlindingMaskLinkingHashTreeBuilder#add(ImprintNode, IdentityMetadata)} and
 * {@link BlindingMaskLinkingHashTreeBuilder#calculateHeight(ImprintNode, IdentityMetadata)} will throw an
 * {@link UnsupportedOperationException} exception.
 *
 * <p>
 * This builder can not be used multiple times and it is not thread safe.
 */
public class BlindingMaskLinkingHashTreeBuilder implements TreeBuilder<ImprintNode> {

    private static final Logger logger = LoggerFactory.getLogger(HashTreeBuilder.class);
    private static final long MASKED_NODE_LEVEL = 1;
    private final HashTreeBuilder hashTreeBuilder = new HashTreeBuilder();

    private final byte[] initializationVector;
    private final HashAlgorithm hashAlgorithm;
    private DataHash previousBlockHash;

    /**
     * Creates an instance of {@link BlindingMaskLinkingHashTreeBuilder} using a
     * {@link com.guardtime.ksi.tree.Util#DEFAULT_AGGREGATION_ALGORITHM} hash algorithm and a zero hash value as
     * previous block hash.
     *
     * @param initializationVector initialization vector used to calculate masking nodes, must not be null. The length
     *                             of the initialization vector should be as long as the output of the
     *                             {@link com.guardtime.ksi.tree.Util#DEFAULT_AGGREGATION_ALGORITHM} hash algorithm.
     * @throws IllegalArgumentException if initializationVector length is not as long as the output of the
     *                                  {@link com.guardtime.ksi.tree.Util#DEFAULT_AGGREGATION_ALGORITHM} hash
     *                                  algorithm.
     * @throws NullPointerException     if one of the required input parameters is null.
     */
    public BlindingMaskLinkingHashTreeBuilder(byte[] initializationVector) {
        this(com.guardtime.ksi.tree.Util.DEFAULT_AGGREGATION_ALGORITHM, initializationVector, null);
    }

    /**
     * Creates an instance of {@link BlindingMaskLinkingHashTreeBuilder} using
     * {@link com.guardtime.ksi.tree.Util#DEFAULT_AGGREGATION_ALGORITHM} hash algorithm and a {@link DataHash} from
     * previous block.
     *
     * @param previousBlockHash    previous block data hash used to calculate first blinding mask, must not be null.
     * @param initializationVector initialization vector used to calculate masking nodes, must not be null. The length
     *                             of the initialization vector should be as long as the output of the
     *                             {@link com.guardtime.ksi.tree.Util#DEFAULT_AGGREGATION_ALGORITHM} hash algorithm.
     * @throws IllegalArgumentException if initializationVector length is not as long as the output of the
     *                                  {@link com.guardtime.ksi.tree.Util#DEFAULT_AGGREGATION_ALGORITHM} hash algorithm.
     * @throws NullPointerException     if one of the required input parameters is null.
     */
    public BlindingMaskLinkingHashTreeBuilder(byte[] initializationVector, DataHash previousBlockHash) {
        this(com.guardtime.ksi.tree.Util.DEFAULT_AGGREGATION_ALGORITHM, initializationVector, previousBlockHash);
    }

    /**
     * Creates an instance of {@link BlindingMaskLinkingHashTreeBuilder}.
     *
     * @param algorithm            hash algorithm used to calculate inner nodes of the hash tree, must not be null.
     * @param initializationVector initialization vector used to calculate masking nodes, must not be null. The length
     *                             of the initialization vector should be as long as the output of the hash
     *                             {@code algorithm}.
     * @param previousBlockHash    previous block data hash used to calculate first blinding mask. In case this
     *                             parameter is null a zero data hash is used to calculate the first blinding mask.
     * @throws IllegalArgumentException if initializationVector length is not as long as the output of the
     *                                  {@code algorithm} hash algorithm.
     * @throws NullPointerException     if one of the required input parameters is null.
     */
    public BlindingMaskLinkingHashTreeBuilder(HashAlgorithm algorithm, byte[] initializationVector, DataHash previousBlockHash) {
        Util.notNull(algorithm, "HashAlgorithm");
        Util.notNull(initializationVector, "Initialization vector");
        if (initializationVector.length < algorithm.getLength()) {
            logger.warn("Initialization vector is shorter than the output of the hash algorithm.");
        }
        this.hashAlgorithm = algorithm;
        this.initializationVector = Arrays.copyOf(initializationVector, initializationVector.length);
        if (previousBlockHash != null) {
            this.previousBlockHash = new DataHash(previousBlockHash.getImprint());
        } else {
            this.previousBlockHash = new DataHash(algorithm, new byte[algorithm.getLength()]);
        }
    }

    /**
     * Adds a new node to the tree.
     *
     * @param node a leaf to add to the tree, must not be null. The level of the node must be 0.
     * @throws IllegalArgumentException if node level is greater than 0.
     */
    @Override
    public void add(ImprintNode node) {
        Util.notNull(node, "Node");
        if (node.getLevel() != 0) {
            throw new IllegalArgumentException("ImprintNode with level greater than 0 is not supported by BlindingMaskLinkingHashTreeBuilder");
        }
        ImprintNode newNode = calculateNewNode(node);
        hashTreeBuilder.add(newNode);
        previousBlockHash = new DataHash(newNode.getValue());
    }

    /**
     * {@link IdentityMetadata} isn't supported by {@link BlindingMaskLinkingHashTreeBuilder} and this method always
     * throws an {@link UnsupportedOperationException} exception.
     */
    @Override
    public void add(ImprintNode node, IdentityMetadata metadata) {
        throw new UnsupportedOperationException("Identity metadata is not supported by BlindingMaskLinkingHashTreeBuilder");
    }

    /**
     * Calculates the binary tree height if new leaf would be added.
     *
     * @param node a leaf to be added to the tree, must not be null. The level of the node must be 0.
     * @return Hash tree height.
     * @throws IllegalArgumentException if node level is greater than 0.
     */
    @Override
    public long calculateHeight(ImprintNode node) {
        Util.notNull(node, "Node");
        return hashTreeBuilder.calculateHeight(calculateNewNode(node));
    }

    /**
     * {@link IdentityMetadata} isn't supported by {@link BlindingMaskLinkingHashTreeBuilder}. This method always
     * throws an {@link UnsupportedOperationException} exception.
     */
    @Override
    public long calculateHeight(ImprintNode node, IdentityMetadata metadata) {
        throw new UnsupportedOperationException("Identity metadata is not supported by BlindingMaskLinkingHashTreeBuilder");
    }

    /**
     * Adds a new list of leaves to the binary tree.
     *
     * @param nodes a list of leaves to be added to the tree, must not be null.
     * @throws IllegalArgumentException if node level is greater than 0.
     **/
    @Override
    public void add(ImprintNode... nodes) {
        Util.notNull(nodes, "Nodes");
        for (ImprintNode node : nodes) {
            add(node);
        }
    }

    /**
     * Builds the binary tree and returns the root hash of the tree.
     */
    @Override
    public ImprintNode build() {
        return hashTreeBuilder.build();
    }

    private ImprintNode calculateNewNode(ImprintNode node) {
        ImprintNode mask = calculateBlindingMaskNode();
        DataHash newLeafNodeDataHash = com.guardtime.ksi.tree.Util.hash(
                hashAlgorithm, mask.getValue(), node.getValue(), MASKED_NODE_LEVEL);
        return new ImprintNode(mask, node, newLeafNodeDataHash, MASKED_NODE_LEVEL);
    }

    private ImprintNode calculateBlindingMaskNode() {
        DataHasher hasher = new DataHasher(hashAlgorithm);
        hasher.addData(previousBlockHash.getImprint()).addData(initializationVector);
        return new ImprintNode(hasher.getHash());
    }

    /**
     * Returns the last leaf hash of this block/tree (for linking next block/tree).
     */
    public DataHash getLastNodeHash() {
        return previousBlockHash;
    }

}
