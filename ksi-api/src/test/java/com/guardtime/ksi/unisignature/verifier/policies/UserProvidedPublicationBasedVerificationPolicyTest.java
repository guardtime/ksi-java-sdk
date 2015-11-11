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

package com.guardtime.ksi.unisignature.verifier.policies;

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.KSIBuilder;
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.util.Base16;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.nio.ByteBuffer;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.util.Date;

public class UserProvidedPublicationBasedVerificationPolicyTest {

    private KSIPublicationsFileClient mockedPublicationsFileClient;
    private KSI ksi;
    private KSIExtenderClient mockedExtenderClient;

    @BeforeMethod
    public void setUp() throws Exception {
        mockedExtenderClient = Mockito.mock(KSIExtenderClient.class);
        mockedPublicationsFileClient = Mockito.mock(KSIPublicationsFileClient.class);
        CertSelector mockedCertificateSelector = Mockito.mock(CertSelector.class);
        Mockito.when(mockedCertificateSelector.match(Mockito.any(Certificate.class))).thenReturn(Boolean.TRUE);
        KSISigningClient mockerSigningClient = Mockito.mock(KSISigningClient.class);
        ksi = new KSIBuilder().
                setKsiProtocolExtenderClient(mockedExtenderClient).
                setKsiProtocolPublicationsFileClient(mockedPublicationsFileClient).
                setKsiProtocolSignerClient(mockerSigningClient).
                setPublicationsFileTrustedCertSelector(mockedCertificateSelector).
                setPublicationsFilePkiTrustStore(TestUtil.loadFile("truststore.jks"), "changeit").
                build();
    }

    @Test
    public void testCreateNewUserProvidedPublicationBasedVerificationPolicy_Ok() throws Exception {
        UserProvidedPublicationBasedVerificationPolicy policy = new UserProvidedPublicationBasedVerificationPolicy();
        Assert.assertNotNull(policy.getRules());
        Assert.assertNotNull(policy.getName());
        Assert.assertFalse(policy.getRules().isEmpty());
    }

    @Test
    public void testVerifySignatureThatDoesNotContainPublication() throws Exception {
        PublicationsFile mockedTrustProvider = Mockito.mock(PublicationsFile.class);
        Mockito.when(mockedTrustProvider.getName()).thenReturn("MockProvider");
        Future<ByteBuffer> future = Mockito.mock(Future.class);
        Mockito.when(future.getResult()).thenReturn(ByteBuffer.wrap(TestUtil.loadBytes("publications.tlv")));
        Mockito.when(mockedPublicationsFileClient.getPublicationsFile()).thenReturn(future);

        KSISignature signature = TestUtil.loadSignature("ok-sig-2014-04-30.1.ksig");
        DataHash dataHash = new DataHash(HashAlgorithm.SHA2_256, new byte[32]);
        VerificationContext context = TestUtil.buildContext(signature, ksi, mockedExtenderClient, new PublicationData(new Date(53610150000L), dataHash), false);
        VerificationResult result = ksi.verify(context, new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_2);
    }

    @Test
    public void testVerifySignatureWithDifferentPublicationData_ThrowsVerificationException() throws Exception {
        PublicationsFile mockedTrustProvider = Mockito.mock(PublicationsFile.class);
        Mockito.when(mockedTrustProvider.getName()).thenReturn("MockProvider");
        Future<ByteBuffer> future = Mockito.mock(Future.class);
        Mockito.when(future.getResult()).thenReturn(ByteBuffer.wrap(TestUtil.loadBytes("publications.tlv")));
        Mockito.when(mockedPublicationsFileClient.getPublicationsFile()).thenReturn(future);

        KSISignature signature = TestUtil.loadSignature("ok-sig-2014-04-30.1-extended.ksig");
        DataHash dataHash = new DataHash(HashAlgorithm.SHA2_256, Base16.decode("11A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D"));
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, mockedExtenderClient, new PublicationData(new Date(53610150000L), dataHash), false), new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_2);
    }


}