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

package com.guardtime.ksi.blocksigner;

import com.guardtime.ksi.SigningFuture;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.PduIdentifierProvider;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSISigningClientServiceAdapter;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.tree.AggregationHashChainBuilder;
import com.guardtime.ksi.tree.HashTreeBuilder;
import com.guardtime.ksi.tree.ImprintNode;
import com.guardtime.ksi.tree.TreeNode;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import static com.guardtime.ksi.util.Util.notNull;

/**
 * Creates multiple signatures with one request..
 * <p>
 * Methods {@link KsiBlockSigner#add(DataHash, long, IdentityMetadata)},
 * {@link KsiBlockSigner#add(DataHash)} and/or
 * {@link KsiBlockSigner#add(DataHash, long, IdentityMetadata)} can be used
 * to add new input hash to the block signer.
 * </p>
 * <p>
 * Method {@link KsiBlockSigner#sign()} must be called to get the final group of
 * signatures.
 * The signatures are returned the same order as the data hashes were added to block signer.
 * </p>
 * <p>
 * Current implementation returns one signature per input hash.
 * </p>
 * <p>
 * Note that this class can not be used multiple times. </p>
 * <p> The following sample shows how to use {@link KsiBlockSigner} class:
 * </p>
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

    protected static final int MAXIMUM_LEVEL = 255;

    private final List<ImprintNode> leafs = new LinkedList<>();
    private final HashTreeBuilder treeBuilder;

    private final KSISigningService signingService;

    private KSISignatureFactory signatureFactory = new InMemoryKsiSignatureFactory();
    private HashAlgorithm algorithm = HashAlgorithm.SHA2_256;
    private int maxTreeHeight;

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningService}. Default hash algorithm is
     * used to create signatures.
     *
     * @param signingService an instance of {@link KSISigningService}.
     */
    public KsiBlockSigner(KSISigningService signingService) {
        this(signingService, null);
    }

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningService} and {@link HashAlgorithm}.
     *
     * @param signingService an instance of {@link KSISigningService}.
     * @param algorithm hash algorithm to be used.
     */
    public KsiBlockSigner(KSISigningService signingService, HashAlgorithm algorithm) {
        notNull(signingService, "KSI signing service");
        if (algorithm != null) {
            this.algorithm = algorithm;
        }
        this.signingService = signingService;
        this.treeBuilder = new HashTreeBuilder(this.algorithm);
        this.maxTreeHeight = MAXIMUM_LEVEL;
    }

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningClient}. Default hash algorithm is
     * used to create signatures.
     *
     * @param signingClient an instance of {@link KSISigningClient}.
     */
    public KsiBlockSigner(KSISigningClient signingClient) {
        this(signingClient, null);
    }

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningClient}
     * and {@link HashAlgorithm}.
     *
     * @param signingClient an instance of {@link KSISigningClient}.
     * @param algorithm hash algorithm to be used.
     */
    public KsiBlockSigner(KSISigningClient signingClient, HashAlgorithm algorithm) {
       this(new KSISigningClientServiceAdapter(signingClient), algorithm);
    }

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningClient},
     * {@link KSISignatureFactory}
     * and {@link HashAlgorithm}.
     *
     * @param signingClient an instance of {@link KSISigningClient}.
     * @param signatureFactory an instance of {@link KSISignatureFactory}.
     * @param algorithm hash algorithm to be used.
     */
    public KsiBlockSigner(KSISigningClient signingClient, KSISignatureFactory signatureFactory, HashAlgorithm algorithm) {
        this(new KSISigningClientServiceAdapter(signingClient), signatureFactory, algorithm);
    }

    /**
     * Creates a new instance of {@link KsiBlockSigner} with given {@link KSISigningService},
     * {@link KSISignatureFactory}
     * and {@link HashAlgorithm}.
     *
     * @param signingService an instance of {@link KSISigningService}.
     * @param signatureFactory an instance of {@link KSISignatureFactory}.
     * @param algorithm hash algorithm to be used.
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
     *
     * @param dataHash data hash.
     * @param metadata metadata to be added.
     *
     * @return True, if data hash and metadata were added.
     *
     * @throws KSIException
     */
    public boolean add(DataHash dataHash, IdentityMetadata metadata) throws KSIException {
        return add(dataHash, 0L, metadata);
    }

    /**
     * Adds a hash to the {@link KsiBlockSigner}.
     *
     * @param dataHash data hash.
     *
     * @return True, if data hash was added.
     *
     * @throws KSIException
     */
    public boolean add(DataHash dataHash) throws KSIException {
        return add(dataHash, 0L, null);
    }

    /**
     * Adds a hash (with specific level) and a signature metadata to the {@link KsiBlockSigner}.
     *
     * @param dataHash data hash.
     * @param level hash level.
     * @param metadata metadata to be added.
     *
     * @return True, if data hash and metadata were added.
     *
     * @throws KSIException
     */
    public boolean add(DataHash dataHash, long level, IdentityMetadata metadata) throws KSIException {
        notNull(dataHash, "DataHash");
        dataHash.getAlgorithm().checkExpiration();
        if (level < 0 || level > MAXIMUM_LEVEL) {
            throw new IllegalStateException("Level must be between 0 and 255");
        }
        logger.debug("New input hash '{}' with level '{}' added to block signer.", dataHash, level);

        ImprintNode leaf = new ImprintNode(dataHash, level);
        if (metadata != null) {
            if (treeBuilder.calculateHeight(leaf, metadata) > maxTreeHeight) {
                return false;
            }
            treeBuilder.add(leaf, metadata);
        } else {
            if (treeBuilder.calculateHeight(leaf) > maxTreeHeight) {
                return false;
            }
            treeBuilder.add(leaf);
        }
        leafs.add(leaf);
        return true;
    }

    /**
     * Creates a block of multiple signatures.
     *
     * @return Multiple signatures, according to number of input hashes.
     *
     * @throws KSIException
     */
    public List<KSISignature> sign() throws KSIException {
        TreeNode rootNode = treeBuilder.build();
        logger.debug("Root node calculated. {}(level={})", new DataHash(rootNode.getValue()), rootNode.getLevel());
        KSISignature rootNodeSignature = signRootNode(rootNode);
        if (leafs.size() == 1 && !leafs.get(0).hasMetadata()) {
            return Collections.singletonList(rootNodeSignature);
        }
        List<KSISignature> signatures = new LinkedList<>();
        AggregationHashChainBuilder chainBuilder = new AggregationHashChainBuilder();
        for (ImprintNode leaf : leafs) {
            signatures.add(signatureFactory.createSignature(rootNodeSignature, chainBuilder.build(leaf), new DataHash(leaf.getValue())));
        }
        return signatures;
    }

    private KSISignature signRootNode(TreeNode rootNode) throws KSIException {
        DataHash dataHash = new DataHash(rootNode.getValue());
        long level = rootNode.getLevel();
        Future<AggregationResponse> future = signingService.sign(dataHash, level);
        SigningFuture signingFuture = new SigningFuture(future, signatureFactory, dataHash, level);
        return signingFuture.getResult();
    }
}
