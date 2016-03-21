/*
 * Copyright 2013-2015 Guardtime, Inc.
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

package com.guardtime.ksi.aggregation;

import java.io.ByteArrayOutputStream;
import java.util.*;

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.service.KSIServiceImpl;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.LeftAggregationChainLink;
import com.guardtime.ksi.unisignature.inmemory.RightAggregationChainLink;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KsiBlockSigner {

    private static final Logger LOGGER = LoggerFactory.getLogger(KsiBlockSigner.class);
    private final KSI ksi;

    private Map<TreeNode, LocalAggregationHashChain> chains = new HashMap<TreeNode, LocalAggregationHashChain>();
    private HashAlgorithm algorithm = HashAlgorithm.SHA2_256;

    private MerkleTreeBuilder treeBuilder;

    public KsiBlockSigner(KSI ksi) {
        //TODO input validation
        this.ksi = ksi;
        this.treeBuilder = new MerkleTreeBuilder(algorithm);
    }

    public void add(DataHash dataHash, SignatureMetadata metadata) throws KSIException {
        add(dataHash, 0L, metadata);
    }

    public void add(DataHash dataHash, long level, SignatureMetadata metadata) throws KSIException {
        //TODO input check
        LOGGER.info("New input hash '{}' with level '{}' added to block signer.", dataHash, level);
        LocalAggregationHashChain chain = new LocalAggregationHashChain(dataHash, level, metadata);
        DataHash output = chain.getLatestOutputHash();
        ImprintNode leaf = new ImprintNode(output, chain.getCurrentLevel());
        chains.put(leaf, chain);
        treeBuilder.add(leaf);
    }

    public List<KSISignature> sign() throws KSIException {
        TreeNode rootNode = treeBuilder.build();
        LOGGER.info("Root node calculated. {}(level={})", new DataHash(rootNode.getValue()), rootNode.getLevel());

        //TODO sign the root
        KSISignature result = ksi.sign(new DataHash(rootNode.getValue()), rootNode.getLevel());
        AggregationHashChain firstChain = result.getAggregationHashChains()[0];
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        result.writeTo(output);
        byte[] bytes = output.toByteArray();
        List<LocalAggregationHashChain> aggregatedChains = buildChains();
        LinkedList<Long> indexes = new LinkedList<Long>(firstChain.getChainIndex());
        indexes.addLast(3L);

        List<KSISignature> signatures = new LinkedList<KSISignature>();
        for (LocalAggregationHashChain chain : aggregatedChains) {
            chain.setAggregationTime(firstChain.getAggregationTime());
            chain.addChainIndexes(indexes);
            TLVElement signature = TLVElement.create(bytes);
            signature.addFirstChildElement(chain.getRootElement());

            KSISignature signature1 = ksi.read(signature.getEncoded());

            VerificationResult verRes = ksi.verify(signature1, new KeyBasedVerificationPolicy());
            System.out.println(verRes.isOk());
            if(!verRes.isOk()) {
                System.out.println(verRes.getErrorCode());
            }

            signatures.add(signature1);
        }


        return signatures;
    }

    private List<LocalAggregationHashChain> buildChains() throws KSIException {
        List<LocalAggregationHashChain> chains = new LinkedList<LocalAggregationHashChain>();
        for (TreeNode treeNode : this.chains.keySet()) {
            LocalAggregationHashChain chain = this.chains.get(treeNode);
            TreeNode n = treeNode;
            while (!n.isRoot()) {
                TreeNode parent = n.getParent();
                if (n.isLeft()) {
                    long levelCorrection = parent.getLevel() - parent.getLeftChild().getLevel() - 1;
                    System.out.println("Left Level correction " + levelCorrection);
                    chain.addChainLink(new LeftAggregationChainLink(levelCorrection, new DataHash(parent.getRightChild().getValue())));
                } else {
                    long levelCorrection = parent.getLevel() - parent.getRightChild().getLevel() - 1;
                    System.out.println("Right  Level correction " + levelCorrection);
                    chain.addChainLink(new RightAggregationChainLink(
                            levelCorrection, new DataHash(parent.getLeftChild().getValue())));
                }
                n = parent;
            }
            chains.add(chain);
        }

        for (LocalAggregationHashChain chain : chains) {
            System.out.println("Result is " + chain.getLatestOutputHash());
        }

        return chains;
    }

}
