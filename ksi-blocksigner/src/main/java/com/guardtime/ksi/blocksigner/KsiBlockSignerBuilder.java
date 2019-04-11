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

import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.PduIdentifierProvider;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.KSISigningClientServiceAdapter;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.tree.HashTreeBuilder;
import com.guardtime.ksi.tree.TreeBuilder;
import com.guardtime.ksi.tree.Util;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.guardtime.ksi.util.Util.notNull;

/**
 * Provides functionality to obtain {@link KsiBlockSigner} object(s), offering multiple
 * methods to configure {@link KsiBlockSigner} object.
 *
 * <p> The following sample shows how to use {@link KsiBlockSigner} class:
 * </p>
 * <pre>
 * {@code
 *
 * KSISigningClient signingClient = getSigningClient();
 * TreeBuilder treeBuilder = new HashTreeBuilder();
 * KsiBlockSigner signer = new KsiBlockSignerBuilder()
 *                 .setKsiSigningClient(signingClient)
 *                 .setTreeBuilder(treeBuilder)
 *                 .build();
 * }
 *
 */
public class KsiBlockSignerBuilder {

    private static final Logger logger = LoggerFactory.getLogger(KsiBlockSignerBuilder.class);

    private KSISigningService signingService;
    private HashAlgorithm algorithm = Util.DEFAULT_AGGREGATION_ALGORITHM;
    private KSISignatureFactory signatureFactory = new InMemoryKsiSignatureFactory();
    private int maxTreeHeight = Util.MAXIMUM_LEVEL;
    private TreeBuilder treeBuilder;

    /**
     * Sets the {@link KSISigningClient}. Either this method or
     * {@link KsiBlockSignerBuilder#setKsiSigningService} method should be called.
     */
    public KsiBlockSignerBuilder setKsiSigningClient(KSISigningClient signingClient) {
        notNull(signingClient, "Signing client");
        return setKsiSigningService(new KSISigningClientServiceAdapter(signingClient));
    }

    /**
     * Sets the {@link KSISigningService}. Either this method or
     * {@link KsiBlockSignerBuilder#setKsiSigningClient} method should be called.
     */
    public KsiBlockSignerBuilder setKsiSigningService(KSISigningService signingService) {
        notNull(signingService, "Signing service");
        this.signingService = signingService;
        return this;
    }

    /**
     * Sets the hash algorithm used by {@link HashTreeBuilder}.
     * @deprecated Use {@link KsiBlockSignerBuilder#setTreeBuilder(TreeBuilder)} instead.
     */
    @Deprecated
    public KsiBlockSignerBuilder setDefaultHashAlgorithm(HashAlgorithm algorithm) {
        notNull(algorithm, "Hash algorithm");
        algorithm.checkExpiration();
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Sets the {@link KSISignatureFactory}. Default value is {@link InMemoryKsiSignatureFactory}.
     */
    public KsiBlockSignerBuilder setSignatureFactory(KSISignatureFactory signatureFactory) {
        notNull(signatureFactory, "KSI signature factory");
        this.signatureFactory = signatureFactory;
        return this;
    }

    /**
     * Sets the maximum height of the aggregation tree. Default value is {@link Util#MAXIMUM_LEVEL}.
     */
    public KsiBlockSignerBuilder setMaxTreeHeight(Integer maxTreeHeight) {
        notNull(maxTreeHeight, "Maximum aggregation tree height");
        this.maxTreeHeight = maxTreeHeight;
        return this;
    }

    /**
     * Allows to configure a custom {@link TreeBuilder} for the local aggregation. If used then the algorithm set
     * by {@link KsiBlockSignerBuilder#setMaxTreeHeight(Integer)} method will be ignored. If this method is not called
     * then {@link HashTreeBuilder} will be used for aggregation.
     */
    public KsiBlockSignerBuilder setTreeBuilder(TreeBuilder treeBuilder) {
        notNull(treeBuilder, "HashTreeBuilder");
        this.treeBuilder = treeBuilder;
        return this;
    }

    @Deprecated
    public KsiBlockSignerBuilder setPduVersion(PduVersion pduVersion) {
        logger.warn("KsiBlockSignerBuilder.setPduVersion(PduVersion) is deprecated and has no affect. PDU version is determined " +
                "by the KSISigningService that the KSIBlockSigner is initialized with.");
        return this;
    }

    @Deprecated
    public KsiBlockSignerBuilder setPduIdentifierProvider(PduIdentifierProvider pduIdentifierProvider) {
        logger.warn("KsiBlockSignerBuilder.setPduIdentifierProvider(PduIdentifierProvider) is deprecated and has no affect.");
        return this;
    }

    public KsiBlockSigner build() {
        notNull(signingService, "KSI signing service");
        if (treeBuilder == null) {
            this.treeBuilder = new HashTreeBuilder(algorithm);
        }
        return new KsiBlockSigner(signingService, signatureFactory, maxTreeHeight, treeBuilder);
    }
}
