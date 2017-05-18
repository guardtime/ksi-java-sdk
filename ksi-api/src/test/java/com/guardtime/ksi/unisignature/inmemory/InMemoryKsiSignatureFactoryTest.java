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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.adapter.PublicationsFileClientAdapter;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.SignaturePublicationRecord;
import com.guardtime.ksi.unisignature.verifier.policies.InternalVerificationPolicy;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static java.util.Arrays.asList;

public class InMemoryKsiSignatureFactoryTest {

    private static final String PUBLICATION_STRING = "AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA";
    private InMemoryKsiSignatureComponentFactory signatureComponentFactory = new InMemoryKsiSignatureComponentFactory();
    private InMemoryKsiSignatureFactory signatureFactory;
    private PublicationsFileClientAdapter mockedPublicationsFileAdapter;

    @BeforeMethod
    public void setUp() throws Exception {
        this.mockedPublicationsFileAdapter = Mockito.mock(PublicationsFileClientAdapter.class);
        Mockito.when(mockedPublicationsFileAdapter.getPublicationsFile()).thenReturn(TestUtil.loadPublicationsFile(PUBLICATIONS_FILE));
        this.signatureFactory = new InMemoryKsiSignatureFactory(new InternalVerificationPolicy(),
                mockedPublicationsFileAdapter, Mockito.mock(KSIExtenderClient.class), false,
                new InMemoryKsiSignatureComponentFactory());
    }

    @Test
    public void testCreateValidKsiSignature_Ok() throws Exception {
        KSISignature signature = signatureFactory.createSignature(TestUtil.loadTlv(SIGNATURE_2017_03_14), null);
        Assert.assertNotNull(signature);
    }

    @Test(expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = "Signature .* is invalid: GEN_1.*Wrong document.*")
    public void testCreateSignatureWithInvalidInputHash_ThrowsInvalidSignatureContentException() throws Exception {
        signatureFactory.createSignature(TestUtil.loadTlv(SIGNATURE_2017_03_14), new DataHash(HashAlgorithm.SHA1, new byte[20]));
    }

    @Test(expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = "Signature .* is invalid: INT_09.*")
    public void testCreateSignatureFromInvalidComponents_ThrowsInvalidSignatureContentException() throws Exception {
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2017_03_14);
        SignaturePublicationRecord publicationRecord = signatureComponentFactory.createPublicationRecord(new PublicationData(PUBLICATION_STRING), null, null);
        signatureFactory.createSignature(asList(signature.getAggregationHashChains()), signature.getCalendarHashChain(), signature.getCalendarAuthenticationRecord(), publicationRecord, null);
    }
}
