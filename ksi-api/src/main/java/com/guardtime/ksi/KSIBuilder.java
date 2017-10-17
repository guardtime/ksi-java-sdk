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
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.PduIdentifierProvider;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSIExtendingClientServiceAdapter;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.KSISigningClientServiceAdapter;
import com.guardtime.ksi.service.KSISigningService;
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
 * <p>Obtaining and configuring the {@link KSI} object(s).</p>
 * <p>It is mandatory to set signing, extender, publications file client and publications file trusted certificate selector.</p>
 */
public final class KSIBuilder {

    private static final Logger logger = LoggerFactory.getLogger(KSIBuilder.class);

    private HashAlgorithm defaultHashAlgorithm = HashAlgorithm.SHA2_256;
    private CertSelector certSelector;

    private KSISigningService signingService;
    private KSIExtendingService extendingService;
    private KSIPublicationsFileClient publicationsFileClient;

    private KeyStore trustStore;

    private long publicationsFileCacheExpirationTime = 0L;

    private Policy defaultVerificationPolicy;

    /**
     * Sets the default signing algorithm to be used to create new KSI signatures. When using {@link KSI#sign(DataHash)}
     * method, this algorithm is ignored. Default value is {@link HashAlgorithm#SHA2_256}
     *
     * @param defaultHashAlgorithm
     *         the hash algorithm to be used to create new KSI signatures.
     * @return Instance of {@link KSIBuilder}.
     */
    public KSIBuilder setDefaultSigningHashAlgorithm(HashAlgorithm defaultHashAlgorithm) {
        this.defaultHashAlgorithm = defaultHashAlgorithm;
        return this;
    }


    /**
     * Sets the signing service to be used in signing process.
     *
     * @param signingService
     *         instance of {@link KSISigningService}.
     * @return Instance of {@link KSIBuilder}.
     */
    public KSIBuilder setKsiProtocolSigningService(KSISigningService signingService) {
        this.signingService = signingService;
        return this;
    }

    /**
     * Sets the extending service to be used in extending process.
     *
     * @param extendingService
     *         instance of {@link KSIExtendingService}.
     * @return Instance of {@link KSIBuilder}.
     */
    public KSIBuilder setKsiProtocolExtendingService(KSIExtendingService extendingService) {
        this.extendingService = extendingService;
        return this;
    }

    /**
     * Sets the signer client to be used in signing process.
     *
     * @param signingClient
     *         instance of {@link KSISigningClient}.
     * @return Instance of {@link KSIBuilder}.
     */
    public KSIBuilder setKsiProtocolSignerClient(KSISigningClient signingClient) {
        Util.notNull(signingClient, "KSI Signing Client");
        return setKsiProtocolSigningService(new KSISigningClientServiceAdapter(signingClient));
    }

    /**
     * Sets the extender client to be used in verification and extending process.
     *
     * @param extenderClient
     *         instance of {@link KSIExtenderClient}.
     * @return Instance of {@link KSIBuilder}.
     */
    public KSIBuilder setKsiProtocolExtenderClient(KSIExtenderClient extenderClient) {
        Util.notNull(extenderClient, "KSI Extender Client");
        return setKsiProtocolExtendingService(new KSIExtendingClientServiceAdapter(extenderClient));
    }

    /**
     * Sets the publications file client to be used to download publications file.
     *
     * @param publicationsFileClient
     *         instance of {@link KSIPublicationsFileClient}.
     * @return Instance of {@link KSIBuilder}.
     */
    public KSIBuilder setKsiProtocolPublicationsFileClient(KSIPublicationsFileClient publicationsFileClient) {
        this.publicationsFileClient = publicationsFileClient;
        return this;
    }

    /**
     * Sets the {@link KeyStore} to be used as truststore to verify the certificate that was used to sign the
     * publications file. If not set, the default Java keystore is used.
     *
     * @param trustStore
     *         truststore to be used to verify certificates.
     * @return Instance of {@link KSIBuilder}.
     * @throws KSIException
     *         when any error occurs.
     */
    public KSIBuilder setPublicationsFilePkiTrustStore(KeyStore trustStore) throws KSIException {
        this.trustStore = trustStore;
        return this;
    }

    /**
     * Loads the {@link KeyStore} from the file system and sets the {@link KeyStore} to be used as a truststore to verify
     * the certificate that was used to sign the publications file.
     *
     * @param file
     *         keystore file on disk, not null.
     * @param password
     *         password of the keystore, null if keystore isn't protected by password.
     * @return Instance of {@link KSIBuilder}.
     * @throws KSIException
     *         when any error occurs.
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
        } catch (GeneralSecurityException | IOException e) {
            throw new KSIException("Loading java key store with path " + file + " failed", e);
        } finally {
            Util.closeQuietly(input);
        }
        return this;
    }

    /**
     * Sets the {@link CertSelector} to be used to verify the certificate that was used to sign
     * the publications file. {@link java.security.cert.X509CertSelector} can be used instead of {@link
     * X509CertificateSubjectRdnSelector}
     *
     * @param certSelector
     *         instance of {@link CertSelector}.
     * @return Instance of {@link KSIBuilder}.
     * @see java.security.cert.X509CertSelector
     */
    public KSIBuilder setPublicationsFileTrustedCertSelector(CertSelector certSelector) {
        this.certSelector = certSelector;
        return this;
    }

    /**
     * Sets the publications file expiration time. Default value is 0.
     */
    public KSIBuilder setPublicationsFileCacheExpirationTime(long expirationTime) {
        this.publicationsFileCacheExpirationTime = expirationTime;
        return this;
    }

    @Deprecated
    public KSIBuilder setPduIdentifierProvider(PduIdentifierProvider pduIdentifierProvider) {
        return this;
    }

    /**
     * Sets a default verification policy. Default verification policy is used to perform
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
     * <li>{@link VerificationContextBuilder#setExtendingAllowed(boolean)} is set to true.</li>
     * <li>{@link VerificationContextBuilder#setExtenderClient(KSIExtenderClient)} - an extender client configured by
     * {@link KSIBuilder} class is used.</li>
     * <li>{@link VerificationContextBuilder#setPublicationsFile(PublicationsFile)} - a publication file configured
     * by {@link KSIBuilder} class is used.</li>
     * <li>{@link VerificationContextBuilder#setDocumentHash(DataHash)} - input hash is used only in case of signature creation, otherwise null value is used.</li>
     * <li>{@link VerificationContextBuilder#setUserPublication(PublicationData)} - null value is always used.</li>
     * <li>{@link VerificationContextBuilder#setSignature(KSISignature)} - the signature to be returned to the user.</li>
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
     * @return Instance of {@link KSI} class.
     * @throws KSIException
     *         will be thrown when some client is null.
     */
    public KSI build() throws KSIException {
        notNull(signingService, "KSI signing service");
        notNull(extendingService, "KSI extending service");
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

        logger.info("KSI SDK initialized with signing service: {}", signingService);
        logger.info("KSI SDK initialized with extender service: {}", extendingService);

        PublicationsHandler publicationsHandler =
                new PublicationsHandlerBuilder().setKsiProtocolPublicationsFileClient(publicationsFileClient)
                .setPublicationsFileCacheExpirationTime(publicationsFileCacheExpirationTime)
                .setPublicationsFilePkiTrustStore(trustStore)
                .setPublicationsFileCertificateConstraints(certSelector).build();

        ContextAwarePolicy contextAwarePolicy =
                ContextAwarePolicyAdapter.createPolicy(defaultVerificationPolicy, publicationsHandler, extendingService);

        Reader reader = new SignatureReader(contextAwarePolicy);
        Signer signer = new SignerBuilder().setDefaultSigningHashAlgorithm(defaultHashAlgorithm)
                .setDefaultVerificationPolicy(contextAwarePolicy)
                .setSigningService(signingService).build();
        Extender extender = new ExtenderBuilder().setDefaultVerificationPolicy(contextAwarePolicy)
                .setExtendingService(extendingService)
                .setPublicationsHandler(publicationsHandler).build();
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

        public KSISignature sign(DataHash dataHash, long level) throws KSIException {
            return signer.sign(dataHash, level);
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

        public Future<KSISignature> asyncSign(DataHash dataHash, long level) throws KSIException {
            return signer.asyncSign(dataHash, level);
        }

        public Future<KSISignature> asyncSign(File file) throws KSIException {
            return signer.asyncSign(file);
        }

        public Future<KSISignature> asyncSign(byte[] bytes) throws KSIException {
            return signer.asyncSign(bytes);
        }

        public KSISigningService getSigningService() {
            return signer.getSigningService();
        }

        @Deprecated
        public AggregatorConfiguration getAggregatorConfiguration() throws KSIException {
            return signer.getAggregatorConfiguration();
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

        public KSIExtendingService getExtendingService() {
            return extender.getExtendingService();
        }

        @Deprecated
        public ExtenderConfiguration getExtenderConfiguration() throws KSIException {
            return extender.getExtenderConfiguration();
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

        public VerificationResult verify(KSISignature signature, Policy policy, PublicationData publicationData) throws
                KSIException {
            return verify(signature, policy, null, publicationData);
        }

        public VerificationResult verify(KSISignature signature, Policy policy, DataHash documentHash) throws KSIException {
            return verify(signature, policy, documentHash, null);
        }

        public VerificationResult verify(KSISignature signature, Policy policy, DataHash documentHash, PublicationData
                publicationData) throws KSIException {
            VerificationContextBuilder builder = new VerificationContextBuilder();
            builder.setDocumentHash(documentHash).setSignature(signature);
            builder.setExtendingService(extendingService).setExtendingAllowed(true).setUserPublication(publicationData);
            VerificationContext context = builder.setPublicationsFile(getPublicationsFile()).build();
            return verify(context, policy);
        }

        public PublicationsFile getPublicationsFile() throws KSIException {
            return publicationsHandler.getPublicationsFile();
        }

        public void close() throws IOException {
            signer.close();
            extender.close();
        }
    }
}
