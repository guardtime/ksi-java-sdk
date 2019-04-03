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
 * NB! This class is not thread safe.
 */
public class BlindingMaskLinkingHashTreeBuilder implements TreeBuilder<ImprintNode> {

    public static final long MASKED_NODE_LEVEL = 1;
    private static final HashAlgorithm DEFAULT_HASH_ALGORITHM = HashAlgorithm.SHA2_256;
    private final HashTreeBuilder hashTreeBuilder = new HashTreeBuilder();

    private final byte[] initializationVector;
    private final HashAlgorithm hashAlgorithm;
    private DataHash previousBlockHash;

    public BlindingMaskLinkingHashTreeBuilder(byte[] initializationVector) {
        this(DEFAULT_HASH_ALGORITHM, initializationVector, null);
    }

    public BlindingMaskLinkingHashTreeBuilder(byte[] initializationVector, DataHash previousBlockHash) {
        this(DEFAULT_HASH_ALGORITHM, initializationVector, previousBlockHash);
    }
    
    public BlindingMaskLinkingHashTreeBuilder(HashAlgorithm algorithm, byte[] initializationVector, DataHash previousBlockHash) {
        Util.notNull(algorithm, "HashAlgorithm");
        Util.notNull(initializationVector, "Initialization vector");
        if (initializationVector.length != algorithm.getLength()) {
            throw new IllegalArgumentException("Initialization vector should be as long as the output of the hash algorithm");
        }
        this.hashAlgorithm = algorithm;
        this.initializationVector = initializationVector;
        if (previousBlockHash != null) {
            this.previousBlockHash = new DataHash(previousBlockHash.getImprint());
        } else {
            this.previousBlockHash = new DataHash(algorithm, new byte[algorithm.getLength()]);
        }
    }

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

    @Override
    public void add(ImprintNode node, IdentityMetadata metadata) {
        if (metadata != null) {
            throw new IllegalArgumentException("Identity metadata is not supported by BlindingMaskLinkingHashTreeBuilder");
        }
        add(node);
    }

    @Override
    public long calculateHeight(ImprintNode node) {
        Util.notNull(node, "Node");
        return hashTreeBuilder.calculateHeight(calculateNewNode(node));
    }

    @Override
    public long calculateHeight(ImprintNode node, IdentityMetadata metadata) {
        if (metadata != null) {
            throw new IllegalArgumentException("Identity metadata is not supported by BlindingMaskLinkingHashTreeBuilder");
        }
        return calculateHeight(node);
    }

    @Override
    public void add(ImprintNode... nodes) {
        Util.notNull(nodes, "Nodes");
        for (ImprintNode node : nodes) {
            add(node);
        }
    }

    @Override
    public ImprintNode build() {
        return hashTreeBuilder.build();
    }

    private ImprintNode calculateNewNode(ImprintNode node) {
        ImprintNode mask = calculateBlindingMaskNode();
        DataHash newLeafNodeDataHash = hashTreeBuilder.hash(hashAlgorithm, mask.getValue(), node.getValue(), MASKED_NODE_LEVEL);
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
