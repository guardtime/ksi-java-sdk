/*
 * Copyright 2013-2015 Guardtime, Inc.
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
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.PublicationsFileFactory;
import com.guardtime.ksi.publication.inmemory.InMemoryPublicationsFileFactory;
import com.guardtime.ksi.service.*;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.trust.JKSTrustStore;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.unisignature.verifier.KSISignatureVerifier;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.util.Util;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertSelector;
import java.util.Date;

/**
 * <p>This class provides functionality to obtain {@link KSI} object(s). This cass offers multiple methods to configure
 * {@link KSI} object.</p> <p>It is mandatory to set signing, extender and publications file client.</p>
 */
public final class KSIBuilder {

    private HashAlgorithm defaultHashAlgorithm = HashAlgorithm.SHA2_256;
    private CertSelector certSelector;

    private KSISigningClient signingClient;
    private KSIExtenderClient extenderClient;
    private KSIPublicationsFileClient publicationsFileClient;

    private KSISignatureFactory uniSignatureFactory = new InMemoryKsiSignatureFactory();

    private KeyStore trustStore;

    /**
     * Sets the default signing algorithm to be used to create new KSI signatures. When using {@link KSI#sign(DataHash)}
     * method then this algorithm is ignored. Default value is {@link HashAlgorithm#SHA2_256}
     *
     * @param defaultHashAlgorithm
     *         the hash algorithm to be used to create new KSI signatures.
     * @return the instance of the builder class
     */
    public KSIBuilder setDefaultSigningHashAlgorithm(HashAlgorithm defaultHashAlgorithm) {
        this.defaultHashAlgorithm = defaultHashAlgorithm;
        return this;
    }

    /**
     * Sets the signer client to be used in signing process.
     *
     * @param signingClient
     *         instance of signing client.
     * @return the instance of the builder class
     */
    public KSIBuilder setKsiProtocolSignerClient(KSISigningClient signingClient) {
        this.signingClient = signingClient;
        return this;
    }

    /**
     * Sets the extender client to be used in verification and extending process.
     *
     * @param extenderClient
     *         instance of extender client
     * @return the instance of the builder class
     */
    public KSIBuilder setKsiProtocolExtenderClient(KSIExtenderClient extenderClient) {
        this.extenderClient = extenderClient;
        return this;
    }

    /**
     * Sets the publications file client to be used to download publications file.
     *
     * @param publicationsFileClient
     *         instance of publication file client
     * @return instance of the builder class
     */
    public KSIBuilder setKsiProtocolPublicationsFileClient(KSIPublicationsFileClient publicationsFileClient) {
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
    public KSIBuilder setPublicationsFilePkiTrustStore(KeyStore trustStore) throws KSIException {
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
    public KSIBuilder setPublicationsFilePkiTrustStore(File file, String password) throws KSIException {
        if (file == null) {
            throw new KSIException("Invalid input parameter. Trust store file is null");
        }
        FileInputStream input = null;
        try {
            this.trustStore = KeyStore.getInstance("JKS");
            char[] passwordCharArray = password == null ? null : password.toCharArray();
            input = new FileInputStream(file);
            trustStore.load(input, passwordCharArray);
        } catch (GeneralSecurityException e) {
            throw new KSIException("Loading java key store with path " + file + " failed", e);
        } catch (IOException e) {
            throw new KSIException("Loading java key store with path " + file + " failed", e);
        } finally {
            Util.closeQuietly(input);
        }
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
    public KSIBuilder setPublicationsFileTrustedCertSelector(CertSelector certSelector) {
        this.certSelector = certSelector;
        return this;
    }

    /**
     * Builds the {@link KSI} instance. Checks that the signing, extender and publications file clients are set.
     *
     * @return instance of {@link KSI} class
     * @throws KSIException
     *         will be thrown when some client is null.
     */
    public KSI build() throws KSIException {
        if (defaultHashAlgorithm == null) {
            this.defaultHashAlgorithm = HashAlgorithm.SHA2_256;
        }
        if (signingClient == null) {
            throw new KSIException("Invalid input parameter. KSI signing client must be present");
        }
        if (extenderClient == null) {
            throw new KSIException("Invalid input parameter. KSI extender client must be present");
        }
        if (publicationsFileClient == null) {
            throw new KSIException("Invalid input parameter. KSI publications file client must be present");
        }
        if (certSelector == null) {
            throw new KSIException("Invalid input parameter. KSI publications file trusted certificate selector must be present");
        }
        if (trustStore == null) {
            this.setPublicationsFilePkiTrustStore(new File(getDefaultTrustStore()), null);
        }
        PKITrustStore jksTrustStore = new JKSTrustStore(trustStore, certSelector);
        PublicationsFileFactory publicationsFileFactory = new InMemoryPublicationsFileFactory(jksTrustStore);
        KSIService ksiService = new KSIServiceImpl(signingClient, extenderClient, publicationsFileClient, uniSignatureFactory, publicationsFileFactory);
        return new KSIImpl(ksiService, uniSignatureFactory, defaultHashAlgorithm);
    }

    private String getDefaultTrustStore() {
        return System.getProperty("java.home") + File.separatorChar + "lib" + File.separatorChar
                + "security" + File.separatorChar + "cacerts";
    }

    /**
     * {@link KSI} class implementation
     */
    private class KSIImpl implements KSI {

        private final KSISignatureFactory uniSignatureFactory;
        private final HashAlgorithm defaultHashAlgorithm;
        private KSIService ksiService;

        private KSIImpl(KSIService ksiService, KSISignatureFactory uniSignatureFactory, HashAlgorithm defaultHashAlgorithm) {
            this.ksiService = ksiService;
            this.uniSignatureFactory = uniSignatureFactory;

            this.defaultHashAlgorithm = defaultHashAlgorithm;
        }

        public KSISignature read(InputStream input) throws KSIException {
            if (input == null) {
                throw new KSIException("Invalid input parameter. Input stream can not be null");
            }
            return uniSignatureFactory.createSignature(input);
        }

        public KSISignature read(byte[] bytes) throws KSIException {
            if (bytes == null) {
                throw new KSIException("Invalid input parameter. Byte array can not be null");
            }
            return read(new ByteArrayInputStream(bytes));
        }

        public KSISignature read(File file) throws KSIException {
            if (file == null) {
                throw new KSIException("Invalid input parameter. File can not be null");
            }
            FileInputStream input = null;
            try {
                input = new FileInputStream(file);
                return read(input);
            } catch (FileNotFoundException e) {
                throw new KSIException("File " + file + " not found", e);
            } finally {
                Util.closeQuietly(input);
            }

        }

        public KSISignature sign(DataHash dataHash) throws KSIException {
            CreateSignatureFuture future = asyncSign(dataHash);
            return future.getResult();
        }

        public KSISignature sign(File file) throws KSIException {
            CreateSignatureFuture future = asyncSign(file);
            return future.getResult();
        }

        public KSISignature sign(byte[] bytes) throws KSIException {
            CreateSignatureFuture future = asyncSign(bytes);
            return future.getResult();
        }

        public CreateSignatureFuture asyncSign(DataHash dataHash) throws KSIException {
            if (dataHash == null) {
                throw new KSIException("Invalid input parameter. Data hash must not be null");
            }
            return ksiService.sign(dataHash);
        }

        public CreateSignatureFuture asyncSign(File file) throws KSIException {
            if (file == null) {
                throw new KSIException("Invalid input parameter. File must not be null");
            }
            DataHasher hasher = new DataHasher(defaultHashAlgorithm);
            hasher.addData(file);
            return asyncSign(hasher.getHash());
        }

        public CreateSignatureFuture asyncSign(byte[] bytes) throws KSIException {
            if (bytes == null) {
                throw new KSIException("Invalid input parameter. Byte array must not be null");
            }
            DataHasher hasher = new DataHasher(defaultHashAlgorithm);
            hasher.addData(bytes);
            return asyncSign(hasher.getHash());
        }

        public KSISignature extend(KSISignature signature) throws KSIException {
            SignatureExtensionRequestFuture future = asyncExtend(signature);
            return future.getResult();
        }

        public KSISignature extend(KSISignature signature, PublicationRecord publicationRecord) throws KSIException {
            SignatureExtensionRequestFuture future = asyncExtend(signature, publicationRecord);
            return future.getResult();
        }

        public KSISignature extendToCalendarHead(KSISignature signature) throws KSIException {
            SignatureExtensionRequestFuture future = asyncExtendToCalendarHead(signature);
            return future.getResult();
        }

        public SignatureExtensionRequestFuture asyncExtend(KSISignature signature) throws KSIException {
            if (signature == null) {
                throw new KSIException("Invalid input parameter. KSI signature must be present.");
            }

            PublicationRecord publicationRecord = getPublicationsFile().getPublicationRecord(signature.getAggregationTime());
            Date publicationDate = publicationRecord != null ? publicationRecord.getPublicationTime() : null;
            ExtensionRequestFuture serviceFuture = ksiService.extend(signature.getAggregationTime(), publicationDate);
            return new SignatureExtensionRequestFuture(serviceFuture, publicationRecord, signature);
        }

        public SignatureExtensionRequestFuture asyncExtend(KSISignature signature, PublicationRecord publicationRecord) throws KSIException {
            if (signature == null) {
                throw new KSIException("Invalid input parameter. KSI signature must be present.");
            }
            if (publicationRecord == null) {
                throw new KSIException("Invalid input parameter. Publication record must be present");
            }
            if (signature.getAggregationTime().after(publicationRecord.getPublicationTime())) {
                throw new KSIException("No suitable publication yet");
            }
            Date publicationDate = publicationRecord.getPublicationTime();
            ExtensionRequestFuture serviceFuture = ksiService.extend(signature.getAggregationTime(), publicationDate);
            return new SignatureExtensionRequestFuture(serviceFuture, publicationRecord, signature);
        }

        public SignatureExtensionRequestFuture asyncExtendToCalendarHead(KSISignature signature) throws KSIException {
            if (signature == null) {
                throw new KSIException("Invalid input parameter. KSI signature must be present.");
            }
            PublicationRecord publicationRecord = getPublicationsFile().getLatestPublication();
            return asyncExtend(signature, publicationRecord);
        }

        public VerificationResult verify(VerificationContext context, Policy policy) throws KSIException {
            if (context == null) {
                throw new KSIException("Invalid input parameter. Verification context is null.");
            }
            if (policy == null) {
                throw new KSIException("Invalid input parameter. Policy is null.");
            }
            KSISignatureVerifier verifier = new KSISignatureVerifier();
            return verifier.verify(context, policy);
        }

        public PublicationsFile getPublicationsFile() throws KSIException {
            return ksiService.getPublicationsFile().getResult();
        }

        public void close() {
            signingClient.close();
            extenderClient.close();
            publicationsFileClient.close();
        }
    }

}
