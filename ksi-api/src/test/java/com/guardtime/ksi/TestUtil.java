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
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.inmemory.InMemoryPublicationsFileFactory;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.tlv.TLVInputStream;
import com.guardtime.ksi.trust.CryptoException;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.util.Util;
import org.bouncycastle.util.Store;

import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;

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
        return signatureFactory.createSignature(loadTlv(file));
    }

    public static PublicationsFile loadPublicationsFile(String file) throws Exception {
        return publicationsFileFactory.create(new TLVInputStream(load(file)));
    }

    public static DataHash getFileHash(File file, String name) throws Exception {
        DataHasher dataHasher = new DataHasher(HashAlgorithm.getByName(name));
        dataHasher.addData(file);
        return dataHasher.getHash();
    }

    public static VerificationContext buildContext(KSISignature signature, KSI ksi, KSIExtenderClient extenderClient, DataHash documentHash) throws Exception {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setPublicationsFile(ksi.getPublicationsFile()).setExtenderClient(extenderClient);
        return builder.setDocumentHash(documentHash).createVerificationContext();
    }

    public static VerificationContext buildContext(KSISignature signature, KSI ksi, KSIExtenderClient extenderClient, PublicationData publicationData) throws Exception {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setPublicationsFile(ksi.getPublicationsFile()).setExtenderClient(extenderClient);
        return builder.setUserPublication(publicationData).createVerificationContext();
    }

    public static VerificationContext buildContext(KSISignature signature, KSI ksi, KSIExtenderClient extenderClient, PublicationData publicationData, boolean allowExtending) throws Exception {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setPublicationsFile(ksi.getPublicationsFile()).setExtenderClient(extenderClient);
        return builder.setUserPublication(publicationData).setExtendingAllowed(allowExtending).createVerificationContext();
    }

    public static VerificationContext buildContext(KSISignature sig, KSI ksi, KSIExtenderClient extenderClient, DataHash fileHash, PublicationsFile pub) throws KSIException {
        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(sig).setPublicationsFile(pub).setExtenderClient(extenderClient);
        return builder.setDocumentHash(fileHash).createVerificationContext();
    }


}
