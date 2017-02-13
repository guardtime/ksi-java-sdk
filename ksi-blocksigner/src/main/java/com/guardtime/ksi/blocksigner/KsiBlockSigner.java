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

import com.guardtime.ksi.AggregationFuture;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.DefaultPduIdentifierProvider;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.PduIdentifierProvider;
import com.guardtime.ksi.pdu.v1.PduV1Factory;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static com.guardtime.ksi.util.Util.notNull;
import static java.util.Arrays.asList;

/**
 * A signer class to create a list of unisigantures. Methods {@link KsiBlockSigner#add(DataHash, long, IdentityMetadata)},
 * {@link KsiBlockSigner#add(DataHash)} and/or {@link KsiBlockSigner#add(DataHash, long, IdentityMetadata)} can be used
 * to add new input hash to the block signer. Method {@link KsiBlockSigner#sign()} must be called to get the final
 * signatures. <p/> Current implementation returns one signature per input hash. <p/> Note that this class can not be
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
    private static final String DEFAULT_CLIENT_ID_LOCAL_AGGREGATION = "local-aggregation";
    private static final int MAXIMUM_LEVEL = 255;

    private final Map<LeafKey, AggregationChainLink> chains = new HashMap<LeafKey, AggregationChainLink>();
    private final HashTreeBuilder treeBuilder;

    private final KSISigningClient signingClient;
    private PduFactory pduFactory = new PduV1Factory();
    private PduIdentifierProvider pduIdentifierProvider = new DefaultPduIdentifierProvider();

    private KSISignatureFactory signatureFactory = new InMemoryKsiSignatureFactory();
    private HashAlgorithm algorithm = HashAlgorithm.SHA2_256;
    private DataHasher linkDataHasher;

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
        notNull(signingClient, "KSI signing client");
        if (algorithm != null) {
            this.algorithm = algorithm;
        }
        this.signingClient = signingClient;
        this.treeBuilder = new HashTreeBuilder(this.algorithm);
        this.linkDataHasher = new DataHasher(algorithm);
    }

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningClient}, {@link KSISignatureFactory}
     * and {@link HashAlgorithm}.
     */
    public KsiBlockSigner(KSISigningClient signingClient, KSISignatureFactory signatureFactory, HashAlgorithm algorithm) {
        this(signingClient, algorithm);
        notNull(signatureFactory, "KSI signature factory");
        this.signatureFactory = signatureFactory;
    }

    KsiBlockSigner(KSISigningClient signingClient, PduFactory pduFactory, PduIdentifierProvider pduIdentifierProvider,
                   KSISignatureFactory signatureFactory, HashAlgorithm algorithm) {
        this(signingClient, signatureFactory, algorithm);
        this.pduFactory = pduFactory;
        this.pduIdentifierProvider = pduIdentifierProvider;
    }

    /**
     * Adds a hash and a signature metadata to the {@link KsiBlockSigner}.
     */
    public KsiBlockSigner add(DataHash dataHash, IdentityMetadata metadata) throws KSIException {
        return add(dataHash, 0L, metadata);
    }

    /**
     * Adds a hash and a signature metadata to the {@link KsiBlockSigner}.
     */
    public KsiBlockSigner add(DataHash dataHash) throws KSIException {
        return add(dataHash, 0L, null);
    }

    /**
     * Adds a hash (with specific level) and a signature metadata to the {@link KsiBlockSigner}.
     */
    public KsiBlockSigner add(DataHash dataHash, long level, IdentityMetadata metadata) throws KSIException {
        notNull(dataHash, "DataHash");
        if (level < 0 || level > MAXIMUM_LEVEL) {
            throw new IllegalStateException("Level must be between 0 and 255");
        }
        if (metadata == null) {
            metadata = new IdentityMetadata(DEFAULT_CLIENT_ID_LOCAL_AGGREGATION);
        }
        logger.debug("New input hash '{}' with level '{}' added to block signer.", dataHash, level);
        LinkMetadata linkMetadata = SIGNATURE_COMPONENT_FACTORY.createLinkMetadata(metadata.getClientId(),
                metadata.getMachineId(), metadata.getSequenceNumber(), metadata.getRequestTime());

        AggregationChainLink metadataLink = SIGNATURE_COMPONENT_FACTORY.createLeftAggregationChainLink(linkMetadata, level);
        ImprintNode leaf = calculateChainStepLeft(dataHash.getImprint(), metadataLink.getSiblingData(), level );
        chains.put(new LeafKey(leaf, dataHash), metadataLink);
        treeBuilder.add(leaf);
        return this;
    }

    public boolean checkAdd(DataHash dataHash, long level, IdentityMetadata metadata, long maxTreeHeight) throws KSIException {
        notNull(dataHash, "DataHash");
        if (level < 0 || level > MAXIMUM_LEVEL) {
            throw new IllegalStateException("Level must be between 0 and 255");
        }
        logger.debug("New input hash '{}' with level '{}' checked against block signer.", dataHash, level);
        LinkMetadata linkMetadata = SIGNATURE_COMPONENT_FACTORY.createLinkMetadata(DEFAULT_CLIENT_ID_LOCAL_AGGREGATION,
                null, null, null);

        AggregationChainLink metadataLink = SIGNATURE_COMPONENT_FACTORY.createLeftAggregationChainLink(linkMetadata, level);
        ImprintNode leaf = calculateChainStepLeft(dataHash.getImprint(), metadataLink.getSiblingData(), level);

        return treeBuilder.calculateHeight(leaf) <= maxTreeHeight;
    }

    public ImprintNode calculateChainStepLeft(byte[] left, byte[] right, long length) throws KSIException {
        long level = length + 1;
        DataHash hash = hash(left,right, level);
        return new ImprintNode(hash, level);
    }

    protected final DataHash hash(byte[] hash1, byte[] hash2, long level)  {
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
        KSISignature rootNodeSignature = signRootNode(rootNode);
        AggregationHashChain firstChain = rootNodeSignature.getAggregationHashChains()[0];
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        rootNodeSignature.writeTo(output);

        List<KSISignature> signatures = new LinkedList<KSISignature>();
        for (LeafKey leafKey : this.chains.keySet()) {
            LinkedList<AggregationChainLink> links = new LinkedList<AggregationChainLink>();
            links.add(this.chains.get(leafKey)); // Add metadata link
            TreeNode node = leafKey.getLeaf();

            while (!node.isRoot()) {
                TreeNode parent = node.getParent();
                links.add(createLink(node, parent));
                node = parent;
            }

            LinkedList<Long> chainIndex = new LinkedList<Long>(firstChain.getChainIndex());
            chainIndex.add(calculateIndex(links));
            AggregationHashChain aggregationHashChain = SIGNATURE_COMPONENT_FACTORY.createAggregationHashChain(leafKey.getInputDataHash(), firstChain.getAggregationTime(), chainIndex, links, algorithm);
            List<AggregationHashChain> aggregationHashChains = new LinkedList<AggregationHashChain>();
            aggregationHashChains.add(aggregationHashChain);
            aggregationHashChains.addAll(asList(rootNodeSignature.getAggregationHashChains()));
            KSISignature signature = signatureFactory.createSignature(aggregationHashChains, rootNodeSignature.getCalendarHashChain(), rootNodeSignature.getCalendarAuthenticationRecord(), rootNodeSignature.getPublicationRecord(), rootNodeSignature.getRfc3161Record());
            signatures.add(signature);

        }
        return signatures;
    }

    private KSISignature signRootNode(TreeNode rootNode) throws KSIException {
        DataHash dataHash = new DataHash(rootNode.getValue());
        Long requestId = pduIdentifierProvider.nextRequestId();
        ServiceCredentials credentials = signingClient.getServiceCredentials();
        KSIRequestContext requestContext = new KSIRequestContext(credentials, requestId, pduIdentifierProvider.getInstanceId(), pduIdentifierProvider.nextMessageId());
        AggregationRequest requestMessage = pduFactory.createAggregationRequest(requestContext, dataHash, rootNode.getLevel());
        Future<TLVElement> future = signingClient.sign(new ByteArrayInputStream(requestMessage.toByteArray()));
        AggregationFuture aggregationFuture = new AggregationFuture(future, requestContext, signatureFactory, dataHash, pduFactory);
        return aggregationFuture.getResult();
    }

    private AggregationChainLink createLink(TreeNode node, TreeNode parent) throws KSIException {
        AggregationChainLink link;
        long parentLevel = parent.getLevel();
        if (node.isLeft()) {
            long levelCorrection = calculateLevelCorrection(parentLevel, parent.getLeftChildNode());
            link = SIGNATURE_COMPONENT_FACTORY.createLeftAggregationChainLink(new DataHash(parent.getRightChildNode().getValue()), levelCorrection);
        } else {
            long levelCorrection = calculateLevelCorrection(parentLevel, parent.getRightChildNode());
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
