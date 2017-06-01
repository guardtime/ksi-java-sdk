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
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFileFactory;
import com.guardtime.ksi.publication.adapter.CachingPublicationsFileClientAdapter;
import com.guardtime.ksi.publication.adapter.NonCachingPublicationsFileClientAdapter;
import com.guardtime.ksi.publication.adapter.PublicationsFileClientAdapter;
import com.guardtime.ksi.publication.inmemory.InMemoryPublicationsFileFactory;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.trust.JKSTrustStore;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
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
import java.security.KeyStore;
import java.security.cert.CertSelector;

import static com.guardtime.ksi.util.Util.*;

/**
 * This class provides functionality to obtain {@link Extender} object(s). This class offers multiple methods to configure
 * {@link Extender} object. It is mandatory to set extender client and publications file client and publications file certificate constraint.
 */
public final class ExtenderBuilder {
    private KSIExtenderClient extenderClient;
    private CertSelector certSelector;
    private KSIPublicationsFileClient publicationsFileClient;
    private KeyStore trustStore;
    private long publicationsFileCacheExpirationTime = 0L;
    private ContextAwarePolicy policy;

    /**
     * Sets the extender client to be used in verification and extending process.
     */
    public ExtenderBuilder setExtenderClient(KSIExtenderClient extenderClient) {
        this.extenderClient = extenderClient;
        return this;
    }

    /**
     * Sets the publications file client to be used to download publications file.
     */
    public ExtenderBuilder setKsiProtocolPublicationsFileClient(KSIPublicationsFileClient publicationsFileClient) {
        this.publicationsFileClient = publicationsFileClient;
        return this;
    }

    /**
     * Sets the {@link KeyStore} to be used as trust store to verify the certificate that was used to sign the
     * publications file. If not set then the default java key store is used.
     */
    public ExtenderBuilder setPublicationsFilePkiTrustStore(KeyStore trustStore) {
        this.trustStore = trustStore;
        return this;
    }

    /**
     * Loads the {@link KeyStore} from the file system and sets the {@link KeyStore} to be used as trust store to verify
     * the certificate that was used to sign the publications file.
     *
     * @param file     key store file on disk. not null.
     * @param password password of the key store. null if key store isn't protected by password.
     * @return instance of builder
     * @throws KSIException when error occurs
     */
    public ExtenderBuilder setPublicationsFilePkiTrustStore(File file, String password) throws KSIException {
        this.trustStore = loadKeyStore(file, password);
        return this;
    }

    /**
     * This method is used to set the {@link CertSelector} to be used to verify the certificate that was used to sign
     * the publications file. {@link java.security.cert.X509CertSelector} can be used to instead of {@link
     * X509CertificateSubjectRdnSelector}
     *
     * @param certSelector instance of {@link CertSelector}.
     * @return instance of builder
     * @see java.security.cert.X509CertSelector
     */
    public ExtenderBuilder setPublicationsFileCertificateConstraints(CertSelector certSelector) {
        this.certSelector = certSelector;
        return this;
    }

    /**
     * This method can be used to set the publications file expiration time. Default value is 0.
     */
    public ExtenderBuilder setPublicationsFileCacheExpirationTime(long expirationTime) {
        this.publicationsFileCacheExpirationTime = expirationTime;
        return this;
    }

    /**
     * This method can be used to set a default verification policy. Verification will be ran before signature is
     * returned to the user. If signature verification fails,
     * {@link com.guardtime.ksi.unisignature.inmemory.InvalidSignatureContentException} exception is thrown.
     * If needed, user can access the invalid signature and verification result using the methods
     * {@link InvalidSignatureContentException#getSignature()} and
     * {@link InvalidSignatureContentException#getVerificationResult()}.
     * <p>
     * By default policy returned by method {@link ContextAwarePolicyAdapter#createInternalPolicy()} is used.
     */
    public ExtenderBuilder setDefaultVerificationPolicy(ContextAwarePolicy policy) {
        this.policy = policy;
        return this;
    }

    /**
     * Builds the {@link Extender} instance. Checks that the extender and publications file clients are set.
     *
     * @return instance of {@link Extender} class
     * @throws KSIException will be thrown when errors occur on {@link Extender} class initialization.
     */
    public Extender build() throws KSIException {
        Util.notNull(extenderClient, "KSI extender client");
        Util.notNull(publicationsFileClient, "KSI publications file");
        Util.notNull(certSelector, "KSI publications file trusted certificate selector");
        if (trustStore == null) {
            this.setPublicationsFilePkiTrustStore(new File(getDefaultTrustStore()), null);
        }
        if (policy == null) {
            this.policy = ContextAwarePolicyAdapter.createInternalPolicy();
        }
        PKITrustStore jksTrustStore = new JKSTrustStore(trustStore, certSelector);
        PublicationsFileFactory publicationsFileFactory = new InMemoryPublicationsFileFactory(jksTrustStore);
        PublicationsFileClientAdapter publicationsFileAdapter = createPublicationsFileAdapter(publicationsFileClient, publicationsFileFactory, publicationsFileCacheExpirationTime);
        KSISignatureComponentFactory signatureComponentFactory = new InMemoryKsiSignatureComponentFactory();
        KSISignatureFactory signatureFactory = new InMemoryKsiSignatureFactory(policy, signatureComponentFactory);
        return new ExtenderImpl(extenderClient, publicationsFileAdapter, signatureFactory, signatureComponentFactory);
    }

    private PublicationsFileClientAdapter createPublicationsFileAdapter(KSIPublicationsFileClient publicationsFileClient, PublicationsFileFactory publicationsFileFactory, long expirationTime) {
        if (expirationTime > 0) {
            return new CachingPublicationsFileClientAdapter(publicationsFileClient, publicationsFileFactory, expirationTime);
        }
        return new NonCachingPublicationsFileClientAdapter(publicationsFileClient, publicationsFileFactory);
    }

    private class ExtenderImpl implements Extender {
        private final KSISignatureFactory signatureFactory;
        private final KSISignatureComponentFactory signatureComponentFactory;
        private final KSIExtenderClient extenderClient;
        private final PublicationsFileClientAdapter publicationsFileAdapter;

        public ExtenderImpl(KSIExtenderClient extenderClient,
                            PublicationsFileClientAdapter publicationsFileAdapter, KSISignatureFactory signatureFactory,
                            KSISignatureComponentFactory signatureComponentFactory) {
            this.signatureFactory = signatureFactory;
            this.signatureComponentFactory = signatureComponentFactory;
            this.extenderClient = extenderClient;
            this.publicationsFileAdapter = publicationsFileAdapter;
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
            PublicationRecord publicationRecord = publicationsFileAdapter.getPublicationsFile().getPublicationRecord(signature.getAggregationTime());
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
            Future<ExtensionResponse> extenderFuture = extenderClient.extend(signature.getAggregationTime(), publicationRecord.getPublicationTime());
            return new ExtensionFuture(extenderFuture, publicationRecord, signature, signatureComponentFactory, signatureFactory);
        }

        public KSIExtenderClient getExtenderClient() {
            return extenderClient;
        }

        public void close() throws IOException {
            extenderClient.close();
            publicationsFileClient.close();
        }
    }
}
