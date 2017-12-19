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

package com.guardtime.ksi.blocksigner;

import com.guardtime.ksi.SigningFuture;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.PduIdentifierProvider;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSISigningClientServiceAdapter;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.tree.HashTreeBuilder;
import com.guardtime.ksi.tree.ImprintNode;
import com.guardtime.ksi.tree.TreeNode;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureComponentFactory;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.unisignature.LinkMetadata;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static com.guardtime.ksi.util.Util.notNull;
import static java.util.Arrays.asList;

/**
 * A signer class to create a list of unisigantures. Methods {@link KsiBlockSigner#add(DataHash, long, IdentityMetadata)},
 * {@link KsiBlockSigner#add(DataHash)} and/or {@link KsiBlockSigner#add(DataHash, long, IdentityMetadata)} can be used
 * to add new input hash to the block signer. Method {@link KsiBlockSigner#sign()} must be called to get the final
 * signatures. The signatures are returned the same order as the data hashes were added to block signer. <p/>
 * Current implementation returns one signature per input hash. <p/> Note that this class can not be
 * used multiple times. </p> The following sample shows how to use {@link KsiBlockSigner} class:
 * <p>
 * <pre>
 * {@code
 *
 * // initialize ksi block signer
 * KSISigningClient signingClient = getSigningClient()
 * KsiBlockSigner signer = new KsiBlockSigner(signingClient);
 *
 * // add data hashes
 * signer.add(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
 * signer.add(dataHash2);
 * signer.add(dataHash3);
 * signer.add(dataHash4, new IdentityMetadata("my_client_id", "my_machine_id", SEQUENCE_NUMBER, REQUEST_TIME));
 *
 * // call sign methods to get final signatures
 * List<KSISignature> signatures = signer.sign();
 * }
 * </pre>
 * This class isn't thread safe.
 */
public class KsiBlockSigner implements BlockSigner<List<KSISignature>> {

    private static final Logger logger = LoggerFactory.getLogger(KsiBlockSigner.class);

    private static final KSISignatureComponentFactory SIGNATURE_COMPONENT_FACTORY = new InMemoryKsiSignatureComponentFactory();
    protected static final int MAXIMUM_LEVEL = 255;

    private final Map<LeafKey, AggregationChainLink> chains = new LinkedHashMap<>();
    private final HashTreeBuilder treeBuilder;

    private final KSISigningService signingService;

    private KSISignatureFactory signatureFactory = new InMemoryKsiSignatureFactory();
    private HashAlgorithm algorithm = HashAlgorithm.SHA2_256;
    private DataHasher linkDataHasher;
    private int maxTreeHeight;

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningService}. Default hash algorithm is
     * used to create signature.
     *
     * @param signingService an instance of {@link KSISigningService}
     */
    public KsiBlockSigner(KSISigningService signingService) {
        this(signingService, null);
    }

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningService} and {@link HashAlgorithm}.
     */
    public KsiBlockSigner(KSISigningService signingService, HashAlgorithm algorithm) {
        notNull(signingService, "KSI signing service");
        if (algorithm != null) {
            this.algorithm = algorithm;
        }
        this.signingService = signingService;
        this.treeBuilder = new HashTreeBuilder(this.algorithm);
        this.linkDataHasher = new DataHasher(this.algorithm);
        this.maxTreeHeight = MAXIMUM_LEVEL;
    }

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningClient}. Default hash algorithm is
     * used to create signature.
     *
     * @param signingClient an instance of {@link KSISigningClient}
     */
    public KsiBlockSigner(KSISigningClient signingClient) {
        this(signingClient, null);
    }

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningClient} and {@link HashAlgorithm}.
     */
    public KsiBlockSigner(KSISigningClient signingClient, HashAlgorithm algorithm) {
       this(new KSISigningClientServiceAdapter(signingClient), algorithm);
    }

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningClient}, {@link KSISignatureFactory}
     * and {@link HashAlgorithm}.
     */
    public KsiBlockSigner(KSISigningClient signingClient, KSISignatureFactory signatureFactory, HashAlgorithm algorithm) {
        this(new KSISigningClientServiceAdapter(signingClient), signatureFactory, algorithm);
    }

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningService}, {@link KSISignatureFactory}
     * and {@link HashAlgorithm}.
     */
    public KsiBlockSigner(KSISigningService signingService, KSISignatureFactory signatureFactory, HashAlgorithm algorithm) {
        this(signingService, algorithm);
        notNull(signatureFactory, "KSI signature factory");
        this.signatureFactory = signatureFactory;
    }

    KsiBlockSigner(KSISigningService signingService, KSISignatureFactory signatureFactory, HashAlgorithm algorithm, int maxTreeHeight) {
        this(signingService, signatureFactory, algorithm);
        this.maxTreeHeight = maxTreeHeight;
    }

    @Deprecated
    KsiBlockSigner(KSISigningClient signingClient, PduFactory pduFactory, PduIdentifierProvider pduIdentifierProvider,
                   KSISignatureFactory signatureFactory, HashAlgorithm algorithm) {
        this(signingClient, signatureFactory, algorithm);
    }

    @Deprecated
    KsiBlockSigner(KSISigningClient signingClient, PduFactory pduFactory, PduIdentifierProvider pduIdentifierProvider,
                   KSISignatureFactory signatureFactory, HashAlgorithm algorithm, int maxTreeHeight) {
        this(new KSISigningClientServiceAdapter(signingClient), signatureFactory, algorithm, maxTreeHeight);
    }

    /**
     * Adds a hash and a signature metadata to the {@link KsiBlockSigner}.
     */
    public boolean add(DataHash dataHash, IdentityMetadata metadata) throws KSIException {
        return add(dataHash, 0L, metadata);
    }

    /**
     * Adds a hash to the {@link KsiBlockSigner}.
     */
    public boolean add(DataHash dataHash) throws KSIException {
        return add(dataHash, 0L, null);
    }

    /**
     * Adds a hash (with specific level) and a signature metadata to the {@link KsiBlockSigner}.
     */
    public boolean add(DataHash dataHash, long level, IdentityMetadata metadata) throws KSIException {
        notNull(dataHash, "DataHash");
        dataHash.getAlgorithm().checkExpiration();
        if (level < 0 || level > MAXIMUM_LEVEL) {
            throw new IllegalStateException("Level must be between 0 and 255");
        }
        logger.debug("New input hash '{}' with level '{}' added to block signer.", dataHash, level);

        ImprintNode leaf = null;
        AggregationChainLink metadataLink = null;
        if (metadata != null) {
            LinkMetadata linkMetadata = SIGNATURE_COMPONENT_FACTORY.createLinkMetadata(metadata.getClientId(),
                    metadata.getMachineId(), metadata.getSequenceNumber(), metadata.getRequestTime());

            metadataLink = SIGNATURE_COMPONENT_FACTORY.createLeftAggregationChainLink(linkMetadata, level);
            leaf = calculateChainStepLeft(dataHash.getImprint(), metadataLink.getSiblingData(), level);
        } else {
            leaf = new ImprintNode(dataHash, level);
        }

        if (treeBuilder.calculateHeight(new ImprintNode(leaf)) > maxTreeHeight) {
            return false;
        }
        chains.put(new LeafKey(leaf, dataHash), metadataLink);

        treeBuilder.add(leaf);
        return true;
    }

    private ImprintNode calculateChainStepLeft(byte[] left, byte[] right, long length) throws KSIException {
        long level = length + 1;
        DataHash hash = hash(left, right, level);
        return new ImprintNode(hash, level);
    }

    private final DataHash hash(byte[] hash1, byte[] hash2, long level)  {
        linkDataHasher.reset();
        linkDataHasher.addData(hash1);
        linkDataHasher.addData(hash2);
        linkDataHasher.addData(Util.encodeUnsignedLong(level));
        return linkDataHasher.getHash();
    }

    /**
     * Creates a block signature
     */
    public List<KSISignature> sign() throws KSIException {
        TreeNode rootNode = treeBuilder.build();
        logger.debug("Root node calculated. {}(level={})", new DataHash(rootNode.getValue()), rootNode.getLevel());
        if (chains.keySet().size() == 1 && chains.get(chains.keySet().iterator().next()) == null) {
            return Collections.singletonList(signSingleNodeWithLevel(rootNode));
        }
        KSISignature rootNodeSignature = signRootNode(rootNode);
        AggregationHashChain firstChain = rootNodeSignature.getAggregationHashChains()[0];

        List<KSISignature> signatures = new LinkedList<>();
        for (LeafKey leafKey : this.chains.keySet()) {
            LinkedList<AggregationChainLink> links = new LinkedList<>();

            long initialHashLevel = 0L;
            if (this.chains.get(leafKey) != null) { // if IdentityMetadata was added
                links.add(this.chains.get(leafKey)); // Add metadata link
            } else if (leafKey.getLeaf().getLevel() > 0) {
                initialHashLevel = leafKey.getLeaf().getLevel();
            }

            TreeNode node = leafKey.getLeaf();
            while (!node.isRoot()) {
                TreeNode parent = node.getParent();
                links.add(createLink(node, parent, initialHashLevel));
                initialHashLevel = 0L; //reset hash level, so only the first link gets the extra level correction
                node = parent;
            }

            List<AggregationHashChain> aggregationHashChains =
                    new LinkedList<>(asList(rootNodeSignature.getAggregationHashChains()));
            if (!links.isEmpty()) {
                LinkedList<Long> chainIndex = new LinkedList<>(firstChain.getChainIndex());
                chainIndex.add(calculateIndex(links));
                AggregationHashChain aggregationHashChain = SIGNATURE_COMPONENT_FACTORY.createAggregationHashChain(
                        leafKey.getInputDataHash(), firstChain.getAggregationTime(), chainIndex, links, algorithm);
                aggregationHashChains.add(0, aggregationHashChain);
            }

            KSISignature signature = signatureFactory.createSignature(aggregationHashChains,
                    rootNodeSignature.getCalendarHashChain(), rootNodeSignature.getCalendarAuthenticationRecord(),
                    rootNodeSignature.getPublicationRecord(), rootNodeSignature.getRfc3161Record());
            signatures.add(signature);

        }
        return signatures;
    }

    private KSISignature signRootNode(TreeNode rootNode) throws KSIException {
        DataHash dataHash = new DataHash(rootNode.getValue());
        Future<AggregationResponse> future = signingService.sign(dataHash, rootNode.getLevel());
        SigningFuture SigningFuture = new SigningFuture(future, new InMemoryKsiSignatureFactory(), dataHash);
        return SigningFuture.getResult();
    }

    private KSISignature signSingleNodeWithLevel(TreeNode rootNode) throws KSIException {
        DataHash dataHash = new DataHash(rootNode.getValue());
        long level = rootNode.getLevel();
        Future<AggregationResponse> future = signingService.sign(dataHash, level);
        SigningFuture SigningFuture =
                new SigningFuture(future, new InMemoryKsiSignatureFactory(new InMemoryKsiSignatureComponentFactory()), dataHash,
                        level);
        return SigningFuture.getResult();
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

    private long calculateIndex(LinkedList<AggregationChainLink> links) {
        long index = 1;
        for (int i = links.size(); i > 0; i--) {
            AggregationChainLink link = links.get(i - 1);
            index <<= 1;
            if (link.isLeft()) {
                index |= 1;
            }
        }
        return index;
    }

    private static class LeafKey {
        private ImprintNode leaf;
        private DataHash inputDataHash;

        public LeafKey(ImprintNode leaf, DataHash inputDataHash) {
            this.leaf = leaf;
            this.inputDataHash = inputDataHash;
        }

        public DataHash getInputDataHash() {
            return inputDataHash;
        }

        public ImprintNode getLeaf() {
            return leaf;
        }
    }

}
