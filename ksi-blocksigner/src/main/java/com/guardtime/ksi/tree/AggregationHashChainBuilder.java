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

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.KSISignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.util.Util;

import java.util.Date;
import java.util.LinkedList;

import static com.guardtime.ksi.unisignature.AggregationHashChainUtil.calculateIndex;

/**
 * Builder for creating {@link AggregationHashChain} from a {@link TreeNode} leaf
 * <p>
 * Resulting hash chain consists of all nodes on the path from leaf node to the root node
 * <p>
 * This builder can not be used multiple times.
 */
public class AggregationHashChainBuilder {
    private static final KSISignatureComponentFactory SIGNATURE_COMPONENT_FACTORY = new InMemoryKsiSignatureComponentFactory();

    private Date aggregationTime;
    private TreeNode leaf;
    private LinkedList<Long> chainIndex = new LinkedList<>();

    /**
     * Creates a new aggregation hash chain builder
     *
     * @param leaf            leaf node from which aggregation hash chain will be created, must not have any child nodes
     * @param aggregationTime aggregation time of the aggregation hash chain
     */
    public AggregationHashChainBuilder(TreeNode leaf, Date aggregationTime) {
        Util.notNull(leaf, "TreeNode");
        Util.notNull(aggregationTime, "Aggregation time");
        this.leaf = leaf;
        this.aggregationTime = aggregationTime;
    }

    /**
     * @param chainIndex index of upper aggregation hash chain, may not be null
     * @return instance of the builder itself
     */
    public AggregationHashChainBuilder setChainIndex(LinkedList<Long> chainIndex) {
        this.chainIndex = chainIndex;
        return this;
    }

    /**
     * Builds the {@link AggregationHashChain} instance
     *
     * @return instance of {@link AggregationHashChain}
     * @throws KSIException in case any error occurs.
     */
    public AggregationHashChain build() throws KSIException {
        if (!leaf.isLeaf() || leaf.isRoot() || leaf instanceof MetadataNode) {
            throw new IllegalArgumentException("Aggregation hash chain can be built only from leaf nodes");
        }

        LinkedList<AggregationChainLink> links = new LinkedList<>();
        long levelCorrection = 0L;
        TreeNode node;
        if (leaf.getParent().getRightChildNode() instanceof MetadataNode) {
            links.add(createMetadataChainLink((MetadataNode) leaf.getParent().getRightChildNode()));
            node = leaf.getParent();
        } else {
            node = leaf;
            levelCorrection = node.getLevel();
        }
        createChainLinks(links, levelCorrection, node);
        chainIndex.add(calculateIndex(links));
        HashAlgorithm aggregationAlgorithm = new DataHash(leaf.getParent().getValue()).getAlgorithm();
        return SIGNATURE_COMPONENT_FACTORY.createAggregationHashChain(
                new DataHash(leaf.getValue()), aggregationTime, chainIndex, links, aggregationAlgorithm);
    }

    private void createChainLinks(LinkedList<AggregationChainLink> links, long levelCorrection, TreeNode node) throws KSIException {
        while (!node.isRoot()) {
            TreeNode parent = node.getParent();
            links.add(createLink(node, parent, levelCorrection));
            levelCorrection = 0L; // reset hash level, so only the first link gets the extra level correction
            node = parent;
        }
    }

    private AggregationChainLink createMetadataChainLink(MetadataNode node) throws KSIException {
        byte[] metadataBytes = node.getValue();
        return SIGNATURE_COMPONENT_FACTORY.createLeftAggregationChainLink(metadataBytes, leaf.getLevel());
    }

    private AggregationChainLink createLink(TreeNode node, TreeNode parent, long hashLevel) throws KSIException {
        AggregationChainLink link;
        long parentLevel = parent.getLevel();
        if (node.isLeft()) {
            long levelCorrection = calculateLevelCorrection(parentLevel, parent.getLeftChildNode()) + hashLevel;
            link = SIGNATURE_COMPONENT_FACTORY.createLeftAggregationChainLink(new DataHash(parent.getRightChildNode().getValue()), levelCorrection);
        } else {
            long levelCorrection = calculateLevelCorrection(parentLevel, parent.getRightChildNode()) + hashLevel;
            link = SIGNATURE_COMPONENT_FACTORY.createRightAggregationChainLink(new DataHash(parent.getLeftChildNode().getValue()), levelCorrection);
        }
        return link;
    }

    private long calculateLevelCorrection(long parentLevel, TreeNode childNode) {
        return parentLevel - childNode.getLevel() - 1;
    }
}
