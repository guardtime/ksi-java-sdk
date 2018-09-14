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

package com.guardtime.ksi.trust;

import com.guardtime.ksi.util.Util;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.util.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 * Java key store based trust store implementation. Uses JKS to hold trusted certificates and JKS is used check if
 * certificate is trusted or not. <p/> <p>NB! Certificate is trusted if valid certificate path can be built starting
 * from input certificate and up to trust anchor in JKS file.</p> <p>NB! This implementation does not check certificate
 * revocation information. </p>
 */
public class JKSTrustStore implements PKITrustStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(JKSTrustStore.class);
    private static final String ALGORITHM_PKIX = "PKIX";
    private static final String KEY_STORE_TYPE_JKS = "JKS";

    private final KeyStore keyStore;
    private final CertSelector certSelector;

    /**
     * Creates new instance with given java key store.
     *
     * @param keyStore
     *         java key store to use
     * @param certSelector
     *         if present then all certificates that will be checked must with this certificate selector
     */
    public JKSTrustStore(KeyStore keyStore, CertSelector certSelector) throws InvalidKeyStoreException {
        if (keyStore == null) {
            throw new InvalidKeyStoreException("Invalid input parameter. Key store must be present");
        }
        this.keyStore = keyStore;
        this.certSelector = certSelector;
    }

    /**
     * Creates new instance with given java key store path and password.
     *
     * @param keyStorePath
     *         java key store to load
     * @param password
     *         java key store password
     * @param certSelector
     *         if present then all certificates that will be checked must with this certificate selector
     * @throws InvalidKeyStoreException
     *         if key store loading fails.
     */
    public JKSTrustStore(String keyStorePath, char[] password, CertSelector certSelector) throws InvalidKeyStoreException {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Loading JKS key store {}", keyStorePath);
        }
        if (keyStorePath == null) {
            throw new InvalidKeyStoreException("Invalid input parameter. Key store path must be present");
        }
        InputStream input = null;
        try {
            this.keyStore = KeyStore.getInstance(KEY_STORE_TYPE_JKS);
            input = loadFile(keyStorePath);
            keyStore.load(input, password);
            this.certSelector = certSelector;
        } catch (GeneralSecurityException | IOException e) {
            throw new InvalidKeyStoreException("Loading java key store with path " + keyStorePath + " failed", e);
        } finally {
            Util.closeQuietly(input);
        }
    }

    /**
     * Creates new instance with given java key store path. <p>NB! Does not use password.</p>
     *
     * @param keyStore
     *         java key store to load
     * @param certSelector
     *         if present then all certificates that will be checked must with this certificate selector
     * @throws InvalidKeyStoreException
     *         if key store loading fails.
     */
    public JKSTrustStore(String keyStore, CertSelector certSelector) throws InvalidKeyStoreException {
        this(keyStore, null, certSelector);
    }

    /**
     * This method is used to check if certificate is trusted or not.
     *
     * @param certificate
     *         instance of PKI X.509 certificate. not null.
     * @param certStore
     *         additional certificates to be used to check if certificate chain is trusted or not.
     * @return true if certificate is trusted, false otherwise
     * @throws CryptoException
     *         will be thrown when exception occurs turning certificate path building
     */
    public boolean isTrusted(X509Certificate certificate, Store certStore) throws CryptoException {
        try {
            if (certificate == null) {
                throw new CryptoException("Invalid input parameter. Certificate can not be null");
            }
            LOGGER.info("Checking if certificate with subjectDN={} is trusted", certificate.getSubjectDN());
            Store certificateStore = certStore;
            if (certificateStore == null) {
                certificateStore = new JcaCertStore(new ArrayList());
            }
            checkConstraints(certSelector, certificate);

            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(certificate);

            CertStore pkixParamsCertStore = new JcaCertStoreBuilder().addCertificates(certificateStore).build();

            PKIXBuilderParameters buildParams = new PKIXBuilderParameters(keyStore, selector);
            buildParams.addCertStore(pkixParamsCertStore);
            buildParams.setRevocationEnabled(false);

            CertPathBuilder builder = CertPathBuilder.getInstance(ALGORITHM_PKIX);
            PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(buildParams);

            // Build certificate path
            CertPath certPath = result.getCertPath();

            // Set validation parameters
            PKIXParameters params = new PKIXParameters(keyStore);
            params.setRevocationEnabled(false);

            // Validate certificate path
            CertPathValidator validator = CertPathValidator.getInstance(ALGORITHM_PKIX);
            validator.validate(certPath, params);
            return true;
        } catch (CertPathValidatorException e) {
            LOGGER.debug("Cert path validation failed", e);
            return false;
        } catch (CertPathBuilderException e) {
            LOGGER.debug("Cert path building failed", e);
            return false;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("General security error occurred. " + e.getMessage(), e);
        }
    }


    /**
     * This method is used to find file from disk or classpath.
     *
     * @param trustStorePath
     *         file to load
     * @return instance of {@link InputStream} containing content of the file
     * @throws FileNotFoundException
     *         if file does not exist
     */
    @SuppressWarnings("resource")
    private InputStream loadFile(String trustStorePath) throws FileNotFoundException {
        InputStream input;
        try {
            input = new FileInputStream(trustStorePath);
        } catch (FileNotFoundException e) {
            LOGGER.warn("File {} not found. Fallback to classpath.", trustStorePath);
            input = Thread.currentThread().getContextClassLoader().getResourceAsStream(trustStorePath);
        }
        if (input == null) {
            throw new FileNotFoundException("File " + trustStorePath + " does not exist");
        }
        return input;
    }

    private void checkConstraints(CertSelector certSelector, X509Certificate certificate) throws CryptoException {
        if (certSelector == null) {
            return;
        }
        if(!certSelector.match(certificate)) {
            throw new InvalidCertificateException(certificate);
        }

    }

}
