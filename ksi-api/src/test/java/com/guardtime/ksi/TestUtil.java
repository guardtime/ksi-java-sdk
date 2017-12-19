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
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.inmemory.InMemoryPublicationsFileFactory;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVInputStream;
import com.guardtime.ksi.trust.CryptoException;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.util.Util;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.security.cert.X509Certificate;

import static org.testng.AssertJUnit.fail;

public final class TestUtil extends CommonTestUtil {

    public static final KSIServiceCredentials CREDENTIALS_ANONYMOUS = new KSIServiceCredentials("anon", "anon");

    private static InMemoryKsiSignatureFactory signatureFactory = new InMemoryKsiSignatureFactory();
    private static InMemoryPublicationsFileFactory publicationsFileFactory;

    static {
        try {
            publicationsFileFactory = new InMemoryPublicationsFileFactory(new PKITrustStore() {
                public boolean isTrusted(X509Certificate certificate, Store certStore) throws CryptoException {
                    return true;
                }
            });
        } catch (KSIException e) {
            throw new RuntimeException(e);
        }
    }

    private TestUtil() {
    }

    public static byte[] loadBytes(String file) throws IOException {
        return Util.toByteArray(Thread.currentThread().getContextClassLoader().getResourceAsStream(file));
    }

    public static KSISignature loadSignature(String file) throws Exception {
        return signatureFactory.createSignature(loadTlv(file), null);
    }

    public static PublicationsFile loadPublicationsFile(String file) throws Exception {
        return publicationsFileFactory.create(new TLVInputStream(load(file)));
    }

    public static VerificationContext buildContext(KSISignature signature, KSI ksi, KSIExtendingService extendingService, DataHash documentHash) throws Exception {
        return buildContext(signature, ksi, extendingService, documentHash, 0L);
    }

    public static VerificationContext buildContext(KSISignature signature, KSI ksi, KSIExtendingService extendingService, DataHash documentHash, long level) throws Exception {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setPublicationsFile(ksi.getPublicationsFile()).setExtendingService(extendingService);
        return builder.setDocumentHash(documentHash, level).build();
    }

    public static VerificationContext buildContext(KSISignature signature, KSI ksi, KSIExtenderClient extenderClient, DataHash documentHash) throws Exception {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setPublicationsFile(ksi.getPublicationsFile()).setExtenderClient(extenderClient);
        return builder.setDocumentHash(documentHash).build();
    }

    public static VerificationContext buildContext(KSISignature signature, KSI ksi, KSIExtenderClient extenderClient, PublicationData publicationData) throws Exception {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setPublicationsFile(ksi.getPublicationsFile()).setExtenderClient(extenderClient);
        return builder.setUserPublication(publicationData).build();
    }

    public static VerificationContext buildContext(KSISignature signature, KSI ksi, KSIExtenderClient extenderClient, PublicationData publicationData, boolean allowExtending) throws Exception {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setPublicationsFile(ksi.getPublicationsFile()).setExtenderClient(extenderClient);
        return builder.setUserPublication(publicationData).setExtendingAllowed(allowExtending).build();
    }

    /**
     * Asserts that {@param thrown} or it's cause (or it's causes cause and so on) is of type {@param expectedClass} and with
     * message {@param expectedMessage}.
     */
    public static void assertCause(Class<? extends Exception> expectedClass, String expectedMessage, Throwable thrown) {
        if (thrown == null) {
            fail("Expected thrown exception to be caused by " + expectedClass + "(\"" + expectedMessage + "\"), but that was not the case.");
        }
        if (!expectedClass.isAssignableFrom(thrown.getClass()) || !expectedMessage.equals(thrown.getMessage())) {
            assertCause(expectedClass, expectedMessage, thrown.getCause());
        }
    }

    /**
     * Calculates HMAC with given {@param hmacAlgorithm} from given {@param rootElement} and {@param loginKey}.
     */
    public static DataHash calculateHash(TLVElement rootElement, HashAlgorithm hmacAlgorithm, byte[] loginKey) throws Exception {
        byte[] tlvBytes = rootElement.getEncoded();
        byte[] macCalculationInput = Util.copyOf(tlvBytes, 0, tlvBytes.length - hmacAlgorithm.getLength());
        return new DataHash(hmacAlgorithm, Util.calculateHMAC(macCalculationInput, loginKey, hmacAlgorithm.getName()));
    }

}
