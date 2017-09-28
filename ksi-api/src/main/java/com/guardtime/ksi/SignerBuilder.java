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

package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureComponentFactory;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.unisignature.inmemory.InvalidSignatureContentException;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.util.Util;

import java.io.File;
import java.io.IOException;

import static com.guardtime.ksi.util.Util.notNull;

/**
 * Obtaining and configuring the {@link Signer} object(s). This class offers multiple methods to configure
 * {@link Signer} object. It is mandatory to set the signing client.
 */
public final class SignerBuilder {
    private HashAlgorithm defaultHashAlgorithm = HashAlgorithm.SHA2_256;
    private KSISigningService signingService;
    private ContextAwarePolicy policy;

    /**
     * Sets the default signing hash algorithm to be used to create new KSI signatures. When using
     * {@link KSI#sign(DataHash)} or {@link KSI#asyncSign(DataHash)} method, this algorithm is
     * ignored. By default {@link HashAlgorithm#SHA2_256} algorithm is used.
     */
    public SignerBuilder setDefaultSigningHashAlgorithm(HashAlgorithm defaultHashAlgorithm) {
        this.defaultHashAlgorithm = defaultHashAlgorithm;
        return this;
    }

    /**
     * Sets the signing service to be used in signing process.
     */
    public SignerBuilder setSigningService(KSISigningService signingService) {
        this.signingService = signingService;
        return this;
    }

    /**
     * Sets the default verification policy. Verification will be ran before signature is returned to the user.
     * If signature verification fails,
     * {@link com.guardtime.ksi.unisignature.inmemory.InvalidSignatureContentException} exception is thrown. If needed,
     * user can access the invalid signature and verification result using the methods
     * {@link InvalidSignatureContentException#getSignature()} and
     * {@link InvalidSignatureContentException#getVerificationResult()}.
     * <p>
     * By default the policy returned by method {@link ContextAwarePolicyAdapter#createInternalPolicy()} is used.
     */
    public SignerBuilder setDefaultVerificationPolicy(ContextAwarePolicy policy) {
        this.policy = policy;
        return this;
    }

    /**
     * Builds and returns the {@link Signer} instance. If signing client isn't configured, {@link NullPointerException} is thrown.
     */
    public Signer build() {
        Util.notNull(signingService, "KSI signing service");
        if (defaultHashAlgorithm == null) {
            this.defaultHashAlgorithm = HashAlgorithm.SHA2_256;
        }
        if (policy == null) {
            this.policy = ContextAwarePolicyAdapter.createInternalPolicy();
        }
        KSISignatureComponentFactory signatureComponentFactory = new InMemoryKsiSignatureComponentFactory();
        KSISignatureFactory uniSignatureFactory = new InMemoryKsiSignatureFactory(policy, signatureComponentFactory);
        return new SignerImpl(signingService, uniSignatureFactory, defaultHashAlgorithm);
    }

    private class SignerImpl implements Signer {

        private final Long DEFAULT_LEVEL = 0L;

        private final KSISignatureFactory signatureFactory;
        private final HashAlgorithm defaultHashAlgorithm;
        private final KSISigningService signingService;

        public SignerImpl(KSISigningService signingService, KSISignatureFactory signatureFactory,
                          HashAlgorithm defaultHashAlgorithm) {
            this.signingService = signingService;
            this.signatureFactory = signatureFactory;
            this.defaultHashAlgorithm = defaultHashAlgorithm;
        }

        public KSISignature sign(DataHash dataHash) throws KSIException {
            Future<KSISignature> future = asyncSign(dataHash);
            return future.getResult();
        }

        public KSISignature sign(File file) throws KSIException {
            Future<KSISignature> future = asyncSign(file);
            return future.getResult();
        }

        public KSISignature sign(byte[] bytes) throws KSIException {
            Future<KSISignature> future = asyncSign(bytes);
            return future.getResult();
        }

        public Future<KSISignature> asyncSign(DataHash dataHash) throws KSIException {
            notNull(dataHash, "Data hash");
            Future<AggregationResponse> aggregationResponseFuture = signingService.sign(dataHash, DEFAULT_LEVEL);
            return new SigningFuture(aggregationResponseFuture, signatureFactory, dataHash);
        }

        public Future<KSISignature> asyncSign(File file) throws KSIException {
            notNull(file, "File");
            DataHasher hasher = new DataHasher(defaultHashAlgorithm);
            hasher.addData(file);
            return asyncSign(hasher.getHash());
        }

        public Future<KSISignature> asyncSign(byte[] bytes) throws KSIException {
            notNull(bytes, "Byte array");
            DataHasher hasher = new DataHasher(defaultHashAlgorithm);
            hasher.addData(bytes);
            return asyncSign(hasher.getHash());
        }

        public KSISigningService getSigningService() {
            return signingService;
        }

        @Deprecated
        public AggregatorConfiguration getAggregatorConfiguration() throws KSIException {
            return signingService.getAggregationConfiguration().getResult();
        }

        public void close() throws IOException {
            signingService.close();
        }
    }

}
