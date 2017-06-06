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
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.DefaultPduIdentifierProvider;
import com.guardtime.ksi.pdu.PduIdentifierProvider;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;
import com.guardtime.ksi.unisignature.inmemory.InvalidSignatureContentException;
import com.guardtime.ksi.unisignature.verifier.KSISignatureVerifier;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.unisignature.verifier.policies.InternalVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.unisignature.verifier.policies.UserProvidedPublicationBasedVerificationPolicy;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertSelector;

import static com.guardtime.ksi.util.Util.getDefaultTrustStore;
import static com.guardtime.ksi.util.Util.notNull;

/**
 * <p>This class provides functionality to obtain {@link KSI} object(s). This cass offers multiple methods to configure
 * {@link KSI} object.</p> <p>It is mandatory to set signing, extender and publications file client.</p>
 */
public final class KSIBuilder {

    private static final Logger logger = LoggerFactory.getLogger(KSIBuilder.class);

    private HashAlgorithm defaultHashAlgorithm = HashAlgorithm.SHA2_256;
    private CertSelector certSelector;

    private KSISigningClient signingClient;
    private KSIExtenderClient extenderClient;
    private KSIPublicationsFileClient publicationsFileClient;

    private KeyStore trustStore;

    private long publicationsFileCacheExpirationTime = 0L;
    private PduIdentifierProvider pduIdentifierProvider = new DefaultPduIdentifierProvider();

    private Policy defaultVerificationPolicy;

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
     * This method can be used to set the publications file expiration time. Default value is 0.
     */
    public KSIBuilder setPublicationsFileCacheExpirationTime(long expirationTime) {
        this.publicationsFileCacheExpirationTime = expirationTime;
        return this;
    }

    /**
     * Sets the PDU identifier provider used to generate different identifiers for PDU requests. Default value is
     * {@link DefaultPduIdentifierProvider}.
     */
    public KSIBuilder setPduIdentifierProvider(PduIdentifierProvider pduIdentifierProvider) {
        this.pduIdentifierProvider = pduIdentifierProvider;
        return this;
    }

    /**
     * This method can be used to set a default verification policy. Default verification policy is used to perform
     * signature verification in the following cases:
     * <ul>
     * <li>new signature is created</li>
     * <li>existing signature is extended</li>
     * <li>existing signature is read from stream, byte array or file</li>
     * </ul>
     *
     * Verification will be ran before signature is returned to the user. If signature verification fails,
     * {@link com.guardtime.ksi.unisignature.inmemory.InvalidSignatureContentException} exception is thrown.
     * If needed, user can access the invalid signature and verification result using the methods
     * {@link InvalidSignatureContentException#getSignature()} and
     * {@link InvalidSignatureContentException#getVerificationResult()}.
     * </p>
     * The following values are used to build a verification context that will be used by default verification policy:
     * <ul>
     * <li>{@link VerificationContextBuilder#setExtendingAllowed(boolean)} is set to true</li>
     * <li>{@link VerificationContextBuilder#setExtenderClient(KSIExtenderClient)} - an extender client configure by
     * {@link KSIBuilder} class is used</li>
     * <li>{@link VerificationContextBuilder#setPublicationsFile(PublicationsFile)} - a publication file configured
     * by {@link KSIBuilder} class is used</li>
     * <li>{@link VerificationContextBuilder#setDocumentHash(DataHash)} - in case of signature creation input hash
     * is used, otherwise null value is used.</li>
     * <li>{@link VerificationContextBuilder#setUserPublication(PublicationData)} - null value is always used</li>
     * <li>{@link VerificationContextBuilder#setSignature(KSISignature)} - the signature to be returned to the user</li>
     * </ul>
     * </p>
     * Policies that are using {@link com.guardtime.ksi.publication.PublicationData} can not
     * be used as default verification policy by API users because user publication is always null.
     * <p/>
     * By default {@link InternalVerificationPolicy} is used.
     */
    public KSIBuilder setDefaultVerificationPolicy(Policy defaultVerificationPolicy) {
        if (defaultVerificationPolicy instanceof UserProvidedPublicationBasedVerificationPolicy) {
            throw new IllegalArgumentException("Unsupported default verification policy.");
        }
        this.defaultVerificationPolicy = defaultVerificationPolicy;
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
        notNull(signingClient, "KSI signing client");
        notNull(extenderClient, "KSI extender client");
        notNull(publicationsFileClient, "KSI publications file");
        notNull(certSelector, "KSI publications file trusted certificate selector");
        if (defaultHashAlgorithm == null) {
            this.defaultHashAlgorithm = HashAlgorithm.SHA2_256;
        }
        if (trustStore == null) {
            this.setPublicationsFilePkiTrustStore(new File(getDefaultTrustStore()), null);
        }
        if (defaultVerificationPolicy == null) {
            this.defaultVerificationPolicy = new InternalVerificationPolicy();
        }
        logger.info("KSI SDK initialized with signing client: {}", signingClient);
        logger.info("KSI SDK initialized with extender client: {}", extenderClient);

        PublicationsHandler publicationsHandler =
                new PublicationsHandlerBuilder().setKsiProtocolPublicationsFileClient(publicationsFileClient)
                .setPublicationsFileCacheExpirationTime(publicationsFileCacheExpirationTime)
                .setPublicationsFilePkiTrustStore(trustStore)
                .setPublicationsFileCertificateConstraints(certSelector).build();

        ContextAwarePolicy contextAwarePolicy =
                ContextAwarePolicyAdapter.createPolicy(defaultVerificationPolicy, publicationsHandler, extenderClient);

        Reader reader = new SignatureReader(contextAwarePolicy);
        Signer signer = new SignerBuilder().setDefaultSigningHashAlgorithm(defaultHashAlgorithm)
                .setDefaultVerificationPolicy(contextAwarePolicy)
                .setSignerClient(signingClient).build();
        Extender extender = new ExtenderBuilder().setDefaultVerificationPolicy(contextAwarePolicy)
                .setExtenderClient(extenderClient)
                .setKsiProtocolPublicationsFileClient(publicationsFileClient)
                .setPublicationsFileCacheExpirationTime(publicationsFileCacheExpirationTime)
                .setPublicationsFilePkiTrustStore(trustStore)
                .setPublicationsFileCertificateConstraints(certSelector).build();
        return new KSIImpl(reader, signer, extender, publicationsHandler);
    }

    /**
     * {@link KSI} class implementation
     */
    private class KSIImpl extends SignatureVerifier implements KSI {
        private final Reader reader;
        private final Signer signer;
        private final Extender extender;
        private final PublicationsHandler publicationsHandler;
        private final KSISignatureComponentFactory signatureComponentFactory = new InMemoryKsiSignatureComponentFactory();

        public KSIImpl(Reader reader, Signer signer, Extender extender, PublicationsHandler publicationsHandler) {
            this.reader = reader;
            this.signer = signer;
            this.extender = extender;
            this.publicationsHandler = publicationsHandler;
        }

        public KSISignature read(InputStream input) throws KSIException {
            return reader.read(input);
        }

        public KSISignature read(byte[] bytes) throws KSIException {
            return reader.read(bytes);
        }

        public KSISignature read(File file) throws KSIException {
            return reader.read(file);
        }

        public KSISignature sign(DataHash dataHash) throws KSIException {
            return signer.sign(dataHash);
        }

        public KSISignature sign(File file) throws KSIException {
            return signer.sign(file);
        }

        public KSISignature sign(byte[] bytes) throws KSIException {
            return signer.sign(bytes);
        }

        public Future<KSISignature> asyncSign(DataHash dataHash) throws KSIException {
            return signer.asyncSign(dataHash);
        }

        public Future<KSISignature> asyncSign(File file) throws KSIException {
            return signer.asyncSign(file);
        }

        public Future<KSISignature> asyncSign(byte[] bytes) throws KSIException {
            return signer.asyncSign(bytes);
        }

        public KSISignature extend(KSISignature signature) throws KSIException {
            return extender.extend(signature);
        }

        public KSISignature extend(KSISignature signature, PublicationRecord publicationRecord) throws KSIException {
            return extender.extend(signature, publicationRecord);
        }

        public Future<KSISignature> asyncExtend(KSISignature signature) throws KSIException {
            return extender.asyncExtend(signature);
        }

        public Future<KSISignature> asyncExtend(KSISignature signature, PublicationRecord publicationRecord) throws KSIException {
            return extender.asyncExtend(signature, publicationRecord);
        }

        public VerificationResult verify(VerificationContext context, Policy policy) throws KSIException {
            Util.notNull(context, "Verification context");
            Util.notNull(policy, "Policy");
            KSISignatureVerifier verifier = new KSISignatureVerifier();
            context.setKsiSignatureComponentFactory(signatureComponentFactory);
            return verifier.verify(context, policy);
        }

        public VerificationResult verify(KSISignature signature, Policy policy) throws KSIException {
            return verify(signature, policy, null, null);
        }

        public VerificationResult verify(KSISignature signature, Policy policy, PublicationData publicationData) throws KSIException {
            return verify(signature, policy, null, publicationData);
        }

        public VerificationResult verify(KSISignature signature, Policy policy, DataHash documentHash) throws KSIException {
            return verify(signature, policy, documentHash, null);
        }

        public VerificationResult verify(KSISignature signature, Policy policy, DataHash documentHash, PublicationData publicationData) throws KSIException {
            VerificationContextBuilder builder = new VerificationContextBuilder();
            builder.setDocumentHash(documentHash).setSignature(signature);
            builder.setExtenderClient(extenderClient).setExtendingAllowed(true).setUserPublication(publicationData);
            VerificationContext context = builder.setPublicationsFile(getPublicationsFile()).createVerificationContext();
            return verify(context, policy);
        }

        public PublicationsFile getPublicationsFile() throws KSIException {
            return publicationsHandler.getPublicationsFile();
        }

        public KSISigningClient getSigningClient() {
            return signer.getSigningClient();
        }

        public KSIExtenderClient getExtenderClient() {
            return extender.getExtenderClient();
        }

        public void close() throws IOException {
            signer.close();
            extender.close();
        }
    }

}
