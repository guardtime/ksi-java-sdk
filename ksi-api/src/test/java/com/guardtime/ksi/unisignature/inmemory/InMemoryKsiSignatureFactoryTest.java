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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.adapter.PublicationsFileClientAdapter;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.SignaturePublicationRecord;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.util.Base16;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.SIGNATURE_AGGREGATION_HASH_CHAIN_OK;
import static com.guardtime.ksi.Resources.SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_HEIGHT_2;
import static com.guardtime.ksi.Resources.SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_HEIGHT_3;
import static com.guardtime.ksi.Resources.SIGNATURE_WITH_LEVEL_CORRECTION_3;
import static com.guardtime.ksi.pdu.PduVersion.V2;
import static java.util.Arrays.asList;

public class InMemoryKsiSignatureFactoryTest {

    private static final String PUBLICATION_STRING = "AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA";
    private InMemoryKsiSignatureComponentFactory signatureComponentFactory = new InMemoryKsiSignatureComponentFactory();
    private InMemoryKsiSignatureFactory signatureFactory;

    @BeforeMethod
    public void setUp() throws Exception {
        PublicationsFileClientAdapter mockedPublicationsFileAdapter = Mockito.mock(PublicationsFileClientAdapter.class);
        Mockito.when(mockedPublicationsFileAdapter.getPublicationsFile()).thenReturn(TestUtil.loadPublicationsFile(PUBLICATIONS_FILE));

        KSIExtenderClient extenderClient = Mockito.mock(KSIExtenderClient.class);
        Mockito.when(extenderClient.getPduVersion()).thenReturn(V2);
        this.signatureFactory = new InMemoryKsiSignatureFactory(ContextAwarePolicyAdapter.createInternalPolicy(),
                new InMemoryKsiSignatureComponentFactory());
    }

    @Test
    public void testCreateValidKsiSignature_Ok() throws Exception {
        KSISignature signature = signatureFactory.createSignature(TestUtil.loadTlv(SIGNATURE_2017_03_14), null);
        Assert.assertNotNull(signature);
    }

    @Test
    public void testCreateSignatureWithAggregationHashChain_Ok() throws Exception {
        AggregationHashChain chain = new InMemoryAggregationHashChain(loadTlv(SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_HEIGHT_3));
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_WITH_LEVEL_CORRECTION_3);
        signatureFactory.createSignature(signature, chain,
                new DataHash(Base16.decode("01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2")));
    }

    @Test(expectedExceptions = KSIException.class,
            expectedExceptionsMessageRegExp = "The aggregation hash chain cannot be added as lowest level chain. " +
                    "Its output level .* is bigger than level correction of the first link of the first aggregation hash chain of the base signature .*")
    public void testCreateSignatureWithInvalidChainHeight_throwsKSIException() throws Exception {
        AggregationHashChain chain = new InMemoryAggregationHashChain(loadTlv(SIGNATURE_AGGREGATION_HASH_CHAIN_OK)
                .getFirstChildElement(InMemoryAggregationHashChain.ELEMENT_TYPE));
        signatureFactory.createSignature(TestUtil.loadSignature(SIGNATURE_2017_03_14), chain, null);
    }

    @Test(expectedExceptions = KSIException.class,
            expectedExceptionsMessageRegExp = "The aggregation hash chain cannot be added as lowest level chain. " +
                    "Its output hash .* does not match base signature input hash .*")
    public void testCreateSignatureWithInvalidOutputHash_throwsKSIException() throws Exception {
        AggregationHashChain chain = new InMemoryAggregationHashChain(loadTlv(SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_HEIGHT_2));
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_WITH_LEVEL_CORRECTION_3);
        signatureFactory.createSignature(signature, chain, null);
    }

    @Test(expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = "Signature .* is invalid: GEN_04.*Wrong input hash algorithm.*")
    public void testCreateSignatureWithInvalidInputHashAlgorithm_ThrowsInvalidSignatureContentException() throws Exception {
        signatureFactory.createSignature(TestUtil.loadTlv(SIGNATURE_2017_03_14), new DataHash(HashAlgorithm.SHA1, new byte[20]));
    }

    @Test(expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = "Signature .* is invalid: GEN_01.*Wrong document.*")
    public void testCreateSignatureWithInvalidInputHash_ThrowsInvalidSignatureContentException() throws Exception {
        signatureFactory.createSignature(TestUtil.loadTlv(SIGNATURE_2017_03_14), new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
    }

    @Test(expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = "Signature .* is invalid: INT_07.*")
    public void testCreateSignatureFromInvalidComponents_ThrowsInvalidSignatureContentException() throws Exception {
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2017_03_14);
        SignaturePublicationRecord publicationRecord = signatureComponentFactory.createPublicationRecord(new PublicationData(PUBLICATION_STRING), null, null);
        signatureFactory.createSignature(asList(signature.getAggregationHashChains()), signature.getCalendarHashChain(), signature.getCalendarAuthenticationRecord(), publicationRecord, null);
    }
}
