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
import com.guardtime.ksi.integration.AbstractCommonIntegrationTest;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy;
import com.guardtime.ksi.util.Base16;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.util.Date;

import static org.testng.Assert.assertNotNull;

public class KSITest {

    private KSI ksi;
    private SimpleHttpClient client;
    private X509CertificateSubjectRdnSelector certSelector;

    @BeforeMethod
    public void setUp() throws Exception {
        this.client = new SimpleHttpClient(AbstractCommonIntegrationTest.loadHTTPSettings());
        this.certSelector = new X509CertificateSubjectRdnSelector("E=publications@guardtime.com");
        this.ksi = new KSIBuilder().
                setKsiProtocolSignerClient(client).
                setKsiProtocolExtenderClient(client).
                setKsiProtocolPublicationsFileClient(client).
                setDefaultSigningHashAlgorithm(HashAlgorithm.SHA2_256).
                setPublicationsFileTrustedCertSelector(certSelector).
                build();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. KSI signing client must be present")
    public void testCreateKsiInstanceWithoutSigningClient_ThrowsKsiException() throws Exception {
        this.ksi = new KSIBuilder().
                setKsiProtocolExtenderClient(client).
                setKsiProtocolPublicationsFileClient(client).
                setPublicationsFileTrustedCertSelector(certSelector)
                .build();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. KSI publications file client must be present")
    public void testCreateKsiInstanceWithoutPublicationsFileClient_ThrowsKsiException() throws Exception {
        this.ksi = new KSIBuilder().
                setKsiProtocolSignerClient(client).
                setKsiProtocolExtenderClient(client).
                setPublicationsFileTrustedCertSelector(certSelector).
                build();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. KSI extender client must be present")
    public void testCreateKsiInstanceWithoutExtenderClient_ThrowsKsiException() throws Exception {
        this.ksi = new KSIBuilder().
                setKsiProtocolSignerClient(client).
                setKsiProtocolPublicationsFileClient(client).
                setPublicationsFileTrustedCertSelector(certSelector).build();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. KSI publications file trusted certificate selector must be present")
    public void testCreateKsiInstanceWithoutPublicationsFileTrustedCertSelector_ThrowsKsiException() throws Exception {
        this.ksi = new KSIBuilder().
                setKsiProtocolSignerClient(client).
                setKsiProtocolExtenderClient(client).
                setKsiProtocolPublicationsFileClient(client).build();
    }

    @Test
    public void testReadUniSignatureFromFile_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.loadFile("ok-sig-2014-04-30.1.ksig"));
        assertNotNull(signature);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "File not-present-signature.ksig not found")
    public void testReadUniSignatureUsingFileNotPresent_ThrowsKSIException() throws Exception {
        ksi.read(new File("not-present-signature.ksig"));
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. File can not be null")
    public void testReadUniSignatureUsingInvalidFileInput_ThrowsKSIException() throws Exception {
        ksi.read((File) null);
    }

    @Test
    public void testReadUniSignatureFromByteArray_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.loadBytes("ok-sig-2014-04-30.1.ksig"));
        assertNotNull(signature);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Byte array can not be null")
    public void testReadUniSignatureUsingInvalidByteArrayInput_ThrowsKSIException() throws Exception {
        ksi.read((byte[]) null);
    }

    @Test
    public void testReadUniSignatureFromInputStream_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load("ok-sig-2014-04-30.1.ksig"));
        assertNotNull(signature);
    }

    @Test
    public void testWriteUniSignatureToOutputStream_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load("ok-sig-2014-04-30.1.ksig"));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        signature.writeTo(output);
        Assert.assertEquals(signature, ksi.read(output.toByteArray()));
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Output stream can not be null")
    public void testWriteUniSignatureToNullStream_ThrowsKSIException() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load("ok-sig-2014-04-30.1.ksig"));
        signature.writeTo(null);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Input stream can not be null")
    public void testReadUniSignatureUsingInvalidInputStream_ThrowsKSIException() throws Exception {
        ksi.read((InputStream) null);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Data hash must not be null")
    public void testSignDataHashUsingInvalidInputStream_ThrowsKSIException() throws Exception {
        ksi.sign((DataHash) null);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. File must not be null")
    public void testSignFileUsingInvalidInputStream_ThrowsKSIException() throws Exception {
        ksi.sign((File) null);
    }

    @Test
    public void testVerifySignatureWithoutContext_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load("ok-sig-2014-04-30.1.ksig"));
        VerificationResult result = ksi.verify(signature, new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test
    public void testVerifySignatureWithFileDataHashWithoutContext_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load("ok-sig-2014-04-30.1.ksig"));
        VerificationResult result = ksi.verify(signature, new KeyBasedVerificationPolicy(), new DataHash(HashAlgorithm.SHA2_256, Base16.decode("11A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D")));
        Assert.assertTrue(result.isOk());
    }

    @Test
    public void testVerifyExtendedSignatureWithoutContext_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load("ok-sig-2014-06-2-extended.ksig"));
        VerificationResult result = ksi.verify(signature, new PublicationsFileBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test
    public void testVerifyExtendedSignatureWithFileHashAndPublicationDataAndWithoutContext_OK() throws Exception {
        KSISignature signature = ksi.read(TestUtil.load("ok-sig-2014-06-2-extended.ksig"));
        PublicationData publicationData = new PublicationData(new Date(1410739200000L), new DataHash(HashAlgorithm.SHA2_256, Base16.decode("C1679EDC2E2A23D1BA9B4F49845C7607AEEF48AD1A344A1572A70907A86FF040")));
        DataHash documentHash = new DataHash(HashAlgorithm.SHA2_256, Base16.decode("11A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"));
        VerificationResult result = ksi.verify(signature, new PublicationsFileBasedVerificationPolicy(), documentHash, publicationData);
        Assert.assertTrue(result.isOk());
    }


}
