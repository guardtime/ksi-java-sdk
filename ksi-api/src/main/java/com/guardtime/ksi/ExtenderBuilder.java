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

package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureComponentFactory;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.unisignature.inmemory.InvalidSignatureContentException;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.util.Util;

import java.io.IOException;

import static com.guardtime.ksi.util.Util.notNull;

/**
 * Obtaining and configuring the {@link Extender} object(s).
 * At least extending service and publication handler must be set to build the {@link Extender} object,
 * otherwise the {@link NullPointerException} is thrown.
 */
public final class ExtenderBuilder {
    private KSIExtendingService extendingService;
    private PublicationsHandler publicationsHandler;
    private ContextAwarePolicy policy;

    /**
     * Sets the extending service to be used in extending and verification process.
     */
    public ExtenderBuilder setExtendingService(KSIExtendingService extendingService) {
        this.extendingService = extendingService;
        return this;
    }

    /**
     * Sets the publications file handler to be used to download the publications file.
     */
    public ExtenderBuilder setPublicationsHandler(PublicationsHandler publicationsHandler) {
        this.publicationsHandler = publicationsHandler;
        return this;
    }

    /**
     * Sets the default verification policy. Verification will be ran before signature is
     * returned to the user. If signature verification fails,
     * {@link com.guardtime.ksi.unisignature.inmemory.InvalidSignatureContentException} exception is thrown.
     * If needed, user can access the invalid signature and verification result using the methods
     * {@link InvalidSignatureContentException#getSignature()} and
     * {@link InvalidSignatureContentException#getVerificationResult()}.
     * <p>
     * By default the policy returned by method {@link ContextAwarePolicyAdapter#createInternalPolicy()} is used.
     */
    public ExtenderBuilder setDefaultVerificationPolicy(ContextAwarePolicy policy) {
        this.policy = policy;
        return this;
    }

    /**
     * Builds the {@link Extender} instance. Checks that the extender and the publications file handler are set.
     * If not configured, {@link NullPointerException} is thrown.
     *
     * @return Instance of {@link Extender} class.
     * @throws KSIException will be thrown when errors occur on {@link Extender} class initialization.
     */
    public Extender build() throws KSIException {
        Util.notNull(extendingService, "KSI extending service");
        Util.notNull(publicationsHandler, "KSI publications handler");
        if (policy == null) {
            this.policy = ContextAwarePolicyAdapter.createInternalPolicy();
        }
        KSISignatureComponentFactory signatureComponentFactory = new InMemoryKsiSignatureComponentFactory();
        KSISignatureFactory signatureFactory = new InMemoryKsiSignatureFactory(policy, signatureComponentFactory);
        return new ExtenderImpl(extendingService, publicationsHandler, signatureFactory, signatureComponentFactory);
    }

    private class ExtenderImpl implements Extender {
        private final KSISignatureFactory signatureFactory;
        private final KSISignatureComponentFactory signatureComponentFactory;
        private final KSIExtendingService extendingService;
        private final PublicationsHandler publicationsHandler;

        public ExtenderImpl(KSIExtendingService extendingService,
                PublicationsHandler publicationsHandler, KSISignatureFactory signatureFactory,
                            KSISignatureComponentFactory signatureComponentFactory) {
            this.signatureFactory = signatureFactory;
            this.signatureComponentFactory = signatureComponentFactory;
            this.extendingService = extendingService;
            this.publicationsHandler = publicationsHandler;
        }

        public KSISignature extend(KSISignature signature) throws KSIException {
            Future<KSISignature> future = asyncExtend(signature);
            return future.getResult();
        }

        public KSISignature extend(KSISignature signature, PublicationRecord publicationRecord) throws KSIException {
            Future<KSISignature> future = asyncExtend(signature, publicationRecord);
            return future.getResult();
        }

        public Future<KSISignature> asyncExtend(KSISignature signature) throws KSIException {
            notNull(signature, "KSI signature");
            PublicationRecord publicationRecord = publicationsHandler.getPublicationsFile().getPublicationRecord(signature.getAggregationTime());
            if (publicationRecord == null) {
                throw new KSIException("No suitable publication yet");
            }
            return asyncExtend(signature, publicationRecord);
        }

        public Future<KSISignature> asyncExtend(KSISignature signature, PublicationRecord publicationRecord) throws KSIException {
            notNull(signature, "KSI signature");
            notNull(publicationRecord, "Publication record");
            if (signature.getAggregationTime().after(publicationRecord.getPublicationTime())) {
                throw new IllegalArgumentException("Publication is before signature");
            }
            Future<ExtensionResponse> extenderFuture = extendingService.extend(signature.getAggregationTime(), publicationRecord.getPublicationTime());
            return new ExtensionFuture(extenderFuture, publicationRecord, signature, signatureComponentFactory, signatureFactory);
        }

        public KSIExtendingService getExtendingService() {
            return extendingService;
        }

        @Deprecated
        public ExtenderConfiguration getExtenderConfiguration() throws KSIException {
            return extendingService.getExtendingConfiguration().getResult();
        }

        public void close() throws IOException {
            extendingService.close();
        }

    }
}
