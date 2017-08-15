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
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.PublicationsFileFactory;
import com.guardtime.ksi.publication.adapter.CachingPublicationsFileClientAdapter;
import com.guardtime.ksi.publication.adapter.NonCachingPublicationsFileClientAdapter;
import com.guardtime.ksi.publication.adapter.PublicationsFileClientAdapter;
import com.guardtime.ksi.publication.inmemory.InMemoryPublicationsFileFactory;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.trust.JKSTrustStore;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import com.guardtime.ksi.util.Util;

import java.io.File;
import java.security.KeyStore;
import java.security.cert.CertSelector;

import static com.guardtime.ksi.util.Util.getDefaultTrustStore;

/**
 * <p>This class provides functionality to obtain {@link PublicationsHandler} object(s). This class offers multiple methods to configure
 * {@link PublicationsHandler} object. </p>
 * It is mandatory to set publications file client and publications file trusted certificate selector.
 */
public final class PublicationsHandlerBuilder {

    private CertSelector certSelector;
    private KSIPublicationsFileClient publicationsFileClient;
    private KeyStore trustStore;
    private long publicationsFileCacheExpirationTime = 0L;

    /**
     * Sets the publications file client to be used to download publications file.
     *
     * @param publicationsFileClient
     *         instance of publication file client
     * @return instance of the builder class
     */
    public PublicationsHandlerBuilder setKsiProtocolPublicationsFileClient(KSIPublicationsFileClient publicationsFileClient) {
        this.publicationsFileClient = publicationsFileClient;
        return this;
    }

    /**
     * Sets the {@link KeyStore} to be used as trust store to verify the certificate that was used to sign the
     * publications file. If not set then the default java key store is used.
     *
     * @param trustStore
     *         trust store to be used to verify certificates.
     * @return instance of builder class
     * @throws KSIException
     *         when error occurs
     */
    public PublicationsHandlerBuilder setPublicationsFilePkiTrustStore(KeyStore trustStore) throws KSIException {
        this.trustStore = trustStore;
        return this;
    }

    /**
     * Loads the {@link KeyStore} from the file system and sets the {@link KeyStore} to be used as trust store to verify
     * the certificate that was used to sign the publications file.
     *
     * @param file
     *         key store file on disk. not null.
     * @param password
     *         password of the key store. null if key store isn't protected by password.
     * @return instance of builder
     * @throws KSIException
     *         when error occurs
     */
    public PublicationsHandlerBuilder setPublicationsFilePkiTrustStore(File file, String password) throws KSIException {
        this.trustStore = Util.loadKeyStore(file, password);
        return this;
    }

    /**
     * This method is used to set the {@link CertSelector} to be used to verify the certificate that was used to sign
     * the publications file. {@link java.security.cert.X509CertSelector} can be used to instead of {@link
     * X509CertificateSubjectRdnSelector}
     *
     * @param certSelector
     *         instance of {@link CertSelector}.
     * @return instance of builder
     * @see java.security.cert.X509CertSelector
     */
    public PublicationsHandlerBuilder setPublicationsFileCertificateConstraints(CertSelector certSelector) {
        this.certSelector = certSelector;
        return this;
    }

    /**
     * This method can be used to set the publications file expiration time. Default value is 0.
     */
    public PublicationsHandlerBuilder setPublicationsFileCacheExpirationTime(long expirationTime) {
        this.publicationsFileCacheExpirationTime = expirationTime;
        return this;
    }

    /**
     * Builds the {@link PublicationsHandler} instance.  Checks that publications file client and
     * KSI publications file trusted certificate selector are set. If not configured {@link NullPointerException} is thrown.
     *
     * @return instance of {@link PublicationsHandler} class
     * @throws KSIException
     *         will be thrown when errors occur on {@link PublicationsHandler} class initialization.
     */
    public PublicationsHandler build() throws KSIException {
        Util.notNull(publicationsFileClient, "KSI publications file");
        Util.notNull(certSelector, "KSI publications file trusted certificate selector");

        if (trustStore == null) {
            this.setPublicationsFilePkiTrustStore(new File(getDefaultTrustStore()), null);
        }
        PKITrustStore jksTrustStore = new JKSTrustStore(trustStore, certSelector);
        PublicationsFileFactory publicationsFileFactory = new InMemoryPublicationsFileFactory(jksTrustStore);
        PublicationsFileClientAdapter publicationsFileAdapter = createPublicationsFileAdapter(publicationsFileClient, publicationsFileFactory, publicationsFileCacheExpirationTime);

        return new PublicationsHandlerImpl(publicationsFileAdapter);
    }

    private PublicationsFileClientAdapter createPublicationsFileAdapter(KSIPublicationsFileClient publicationsFileClient, PublicationsFileFactory publicationsFileFactory, long expirationTime) {
        if (expirationTime > 0) {
            return new CachingPublicationsFileClientAdapter(publicationsFileClient, publicationsFileFactory, expirationTime);
        }
        return new NonCachingPublicationsFileClientAdapter(publicationsFileClient, publicationsFileFactory);
    }

    /**
     * {@link PublicationsHandler} class implementation
     */
    private class PublicationsHandlerImpl implements PublicationsHandler {
        private final PublicationsFileClientAdapter publicationsFileAdapter;

        PublicationsHandlerImpl(PublicationsFileClientAdapter publicationsFileAdapter) {
            this.publicationsFileAdapter = publicationsFileAdapter;
        }

        public PublicationsFile getPublicationsFile() throws KSIException {
            return publicationsFileAdapter.getPublicationsFile();
        }

    }

}