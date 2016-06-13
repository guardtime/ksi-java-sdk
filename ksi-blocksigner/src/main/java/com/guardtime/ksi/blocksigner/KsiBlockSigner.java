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

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.service.*;
import com.guardtime.ksi.service.aggregation.AggregationRequest;
import com.guardtime.ksi.service.aggregation.AggregationRequestPayload;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.tree.HashTreeBuilder;
import com.guardtime.ksi.tree.ImprintNode;
import com.guardtime.ksi.tree.TreeNode;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.IdentityMetadata;
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

/**
 * A signer class to create a list of unisigantures. Methods {@link KsiBlockSigner#add(DataHash, long, IdentityMetadata)},
 * {@link KsiBlockSigner#add(DataHash)} and/or {@link KsiBlockSigner#add(DataHash, long, IdentityMetadata)} can be used
 * to add new input hash to the block signer. Method {@link KsiBlockSigner#sign()} must be called to get the final
 * signatures. <p/> Current implementation returns one signature per input hash. <p/> Note that this class can not be
 * used multiple times. </p> The following sample shows how to use {@link KsiBlockSigner} class:
 * <p/>
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
 */
public class KsiBlockSigner implements BlockSigner<List<KSISignature>> {

    private static final Logger LOGGER = LoggerFactory.getLogger(KsiBlockSigner.class);

    private static final InMemoryKsiSignatureFactory SIGNATURE_ELEMENT_FACTORY = new InMemoryKsiSignatureFactory();
    private static final String DEFAULT_CLIENT_ID_LOCAL_AGGREGATION = "local-aggregation";
    private static final int MAXIMUM_LEVEL = 255;

    private final KSISigningClient signingClient;
    private final Map<TreeNode, LocalAggregationHashChain> chains = new HashMap<TreeNode, LocalAggregationHashChain>();
    private final HashTreeBuilder treeBuilder;

    private HashAlgorithm algorithm = HashAlgorithm.SHA2_256;

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningClient}. Default hash algorithm is
     * used to create signature.
     *
     * @param signingClient
     *         an instance of {@link KSISigningClient}
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
        LOGGER.debug("New input hash '{}' with level '{}' added to block signer.", dataHash, level);
        LocalAggregationHashChain chain = new LocalAggregationHashChain(dataHash, level, metadata, algorithm);
        DataHash output = chain.getLatestOutputHash();
        ImprintNode leaf = new ImprintNode(output, chain.getCurrentLevel());
        chains.put(leaf, chain);
        treeBuilder.add(leaf);
        return this;
    }

    /**
     * Creates a block signature
     */
    public List<KSISignature> sign() throws KSIException {
        TreeNode rootNode = treeBuilder.build();
        LOGGER.debug("Root node calculated. {}(level={})", new DataHash(rootNode.getValue()), rootNode.getLevel());
        KSISignature rootNodeSignature = signRootNode(rootNode);
        AggregationHashChain firstChain = rootNodeSignature.getAggregationHashChains()[0];
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        rootNodeSignature.writeTo(output);
        byte[] bytes = output.toByteArray();
        List<LocalAggregationHashChain> aggregatedChains = buildChains();

        List<KSISignature> signatures = new LinkedList<KSISignature>();
        for (LocalAggregationHashChain chain : aggregatedChains) {
            LinkedList<Long> chainIndex = new LinkedList<Long>(firstChain.getChainIndex());
            chainIndex.add(calculateIndex(chain.getLinks()));
            AggregationHashChain aggregationHashChain = SIGNATURE_ELEMENT_FACTORY.createAggregationHashChain(chain.getInputHash(), firstChain.getAggregationTime(), chainIndex, chain.getLinks(), algorithm);
            KSISignature signature = SIGNATURE_ELEMENT_FACTORY.createSignature(new ByteArrayInputStream(bytes));
            signature.addAggregationHashChain(aggregationHashChain);
            signatures.add(signature);
        }
        return signatures;
    }

    private KSISignature signRootNode(TreeNode rootNode) throws KSIException {
        DataHash dataHash = new DataHash(rootNode.getValue());
        Long requestId = Util.nextLong();
        AggregationRequestPayload request = new AggregationRequestPayload(dataHash, requestId, rootNode.getLevel());
        ServiceCredentials credentials = signingClient.getServiceCredentials();
        KSIRequestContext requestContext = new KSIRequestContext(credentials, requestId);
        KSIMessageHeader header = new KSIMessageHeader(credentials.getLoginId(), PduIdentifiers.getInstanceId(), PduIdentifiers.getInstanceId());
        AggregationRequest requestMessage = new AggregationRequest(header, request, credentials.getLoginKey());
        Future<TLVElement> future = signingClient.sign(convert(requestMessage));
        CreateSignatureFuture signatureFuture = new CreateSignatureFuture(future, requestContext, SIGNATURE_ELEMENT_FACTORY);
        return signatureFuture.getResult();
    }

    private ByteArrayInputStream convert(TLVStructure request) throws KSIException {
        return new ByteArrayInputStream(request.getRootElement().getEncoded());
    }

    private List<LocalAggregationHashChain> buildChains() throws KSIException {
        List<LocalAggregationHashChain> chains = new LinkedList<LocalAggregationHashChain>();
        for (TreeNode treeNode : this.chains.keySet()) {
            LocalAggregationHashChain chain = this.chains.get(treeNode);
            TreeNode node = treeNode;
            while (!node.isRoot()) {
                TreeNode parent = node.getParent();
                chain.addChainLink(createLink(node, parent));
                node = parent;
            }
            chains.add(chain);
        }
        return chains;
    }

    private AggregationChainLink createLink(TreeNode node, TreeNode parent) throws KSIException {
        AggregationChainLink link;
        long parentLevel = parent.getLevel();
        if (node.isLeft()) {
            long levelCorrection = calculateLevelCorrection(parentLevel, parent.getLeftChildNode());
            link = SIGNATURE_ELEMENT_FACTORY.createLeftAggregationChainLink(new DataHash(parent.getRightChildNode().getValue()), levelCorrection);
        } else {
            long levelCorrection = calculateLevelCorrection(parentLevel, parent.getRightChildNode());
            link = SIGNATURE_ELEMENT_FACTORY.createRightAggregationChainLink(new DataHash(parent.getLeftChildNode().getValue()), levelCorrection);
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

}
