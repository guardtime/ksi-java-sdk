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
import com.guardtime.ksi.pdu.PduIdentifierProvider;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.trust.X509CertificateSubjectRdnSelector;
import com.guardtime.ksi.unisignature.verifier.AlwaysSuccessfulPolicy;
import com.guardtime.ksi.util.Util;
import org.bouncycastle.util.Store;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.File;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.Resources.KSI_TRUSTSTORE;
import static com.guardtime.ksi.Resources.KSI_TRUSTSTORE_PASSWORD;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE;

public class KsiTest {

    private X509CertificateSubjectRdnSelector certSelector;

    private KSISigningClient mockedSigningClient;
    private KSIExtenderClient mockedExtenderClient;
    private KSIPublicationsFileClient mockedPublicationsFileClient;
    private PKITrustStore mockedTrustStore;
    private Future mockedPublicationsFileResponse;

    private PduIdentifierProvider mockedIdentifierProvider;

    private KSI ksi;

    @BeforeMethod
    public void setUp() throws Exception {
        this.certSelector = new X509CertificateSubjectRdnSelector("E=publications@guardtime.com");
        mockedSigningClient = Mockito.mock(KSISigningClient.class);
        mockedExtenderClient = Mockito.mock(KSIExtenderClient.class);
        mockedPublicationsFileClient = Mockito.mock(KSIPublicationsFileClient.class);
        mockedTrustStore = Mockito.mock(PKITrustStore.class);
        mockedIdentifierProvider = Mockito.mock(PduIdentifierProvider.class);

        Mockito.when(mockedSigningClient.getPduVersion()).thenReturn(PduVersion.V2);
        Mockito.when(mockedExtenderClient.getPduVersion()).thenReturn(PduVersion.V2);
        Mockito.when(mockedIdentifierProvider.getInstanceId()).thenReturn(42L);
        Mockito.when(mockedIdentifierProvider.nextMessageId()).thenReturn(42L);
        Mockito.when(mockedIdentifierProvider.nextRequestId()).thenReturn(42275443333883166L);

        Mockito.when(mockedTrustStore.isTrusted(Mockito.any(X509Certificate.class), Mockito.any(Store.class))).thenReturn(true);

        mockedPublicationsFileResponse = Mockito.mock(Future.class);
        Mockito.when(mockedPublicationsFileResponse.getResult()).thenReturn(ByteBuffer.wrap(Util.toByteArray(load(PUBLICATIONS_FILE))));
        Mockito.when(mockedPublicationsFileClient.getPublicationsFile()).thenReturn(mockedPublicationsFileResponse);

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(TestUtil.load(KSI_TRUSTSTORE), KSI_TRUSTSTORE_PASSWORD.toCharArray());

        this.ksi = new KSIBuilder().
                setKsiProtocolExtenderClient(mockedExtenderClient).
                setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient).
                setPublicationsFileTrustedCertSelector(certSelector).
                setKsiProtocolSignerClient(mockedSigningClient).
                setPublicationsFilePkiTrustStore(keyStore).
                setDefaultVerificationPolicy(new AlwaysSuccessfulPolicy()).
                setPduIdentifierProvider(mockedIdentifierProvider).build();
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "KSI signing service can not be null")
    public void testCreateKsiInstanceWithoutSigningClient_ThrowsKsiException() throws Exception {
        new KSIBuilder().
                setKsiProtocolExtenderClient(mockedExtenderClient).
                setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient).
                setPublicationsFileTrustedCertSelector(certSelector).build();
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "KSI publications file can not be null")
    public void testCreateKsiInstanceWithoutPublicationsFileClient_ThrowsKsiException() throws Exception {
        new KSIBuilder().
                setKsiProtocolSignerClient(mockedSigningClient).
                setKsiProtocolExtenderClient(mockedExtenderClient).
                setPublicationsFileTrustedCertSelector(certSelector).build();
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "KSI extending service can not be null")
    public void testCreateKsiInstanceWithoutExtenderClient_ThrowsKsiException() throws Exception {
        new KSIBuilder().
                setKsiProtocolSignerClient(mockedSigningClient).
                setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient).
                setPublicationsFileTrustedCertSelector(certSelector).build();
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "KSI publications file trusted certificate selector can not be null")
    public void testCreateKsiInstanceWithoutPublicationsFileTrustedCertSelector_ThrowsKsiException() throws Exception {
        new KSIBuilder().
                setKsiProtocolSignerClient(mockedSigningClient).
                setKsiProtocolExtenderClient(mockedExtenderClient).
                setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient).build();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "File not-present-signature.ksig not found")
    public void testReadUniSignatureUsingFileNotPresent_ThrowsKSIException() throws Exception {
        ksi.read(new File("not-present-signature.ksig"));
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "File can not be null")
    public void testReadUniSignatureUsingInvalidFileInput_ThrowsKSIException() throws Exception {
        ksi.read((File) null);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Byte array can not be null")
    public void testReadUniSignatureUsingInvalidByteArrayInput_ThrowsKSIException() throws Exception {
        ksi.read((byte[]) null);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Input stream can not be null")
    public void testReadUniSignatureUsingInvalidInputStream_ThrowsKSIException() throws Exception {
        ksi.read((InputStream) null);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "Data hash can not be null")
    public void testSignMissingDataHash_ThrowsKSIException() throws Exception {
        ksi.sign((DataHash) null);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "File can not be null")
    public void testSignMissingFile_ThrowsKSIException() throws Exception {
        ksi.sign((File) null);
    }

}
