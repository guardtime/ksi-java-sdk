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

import com.guardtime.ksi.SignatureVerifier;
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.adapter.PublicationsFileClientAdapter;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.ChainResult;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.SignaturePublicationRecord;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.util.Base16;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.util.Date;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.SIGNATURE_AGGREGATION_HASH_CHAIN_OK;
import static com.guardtime.ksi.Resources.SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_HEIGHT_2;
import static com.guardtime.ksi.Resources.SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_HEIGHT_3;
import static com.guardtime.ksi.Resources.SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_LEFT_AND_RIGHT_LINKS_AND_HEIGHT_3;
import static com.guardtime.ksi.Resources.SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_LEFT_LINKS_AND_HEIGHT_5;
import static com.guardtime.ksi.Resources.SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_LEFT_LINK_AND_HEIGHT_1;
import static com.guardtime.ksi.Resources.SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_RIGHT_LINKS_AND_HEIGHT_3;
import static com.guardtime.ksi.Resources.SIGNATURE_WITH_LEVEL_CORRECTION_14;
import static com.guardtime.ksi.Resources.SIGNATURE_WITH_LEVEL_CORRECTION_3;
import static com.guardtime.ksi.Resources.SIGNATURE_WITH_LEVEL_CORRECTION_5;
import static com.guardtime.ksi.pdu.PduVersion.V2;
import static java.util.Arrays.asList;

public class InMemoryKsiSignatureFactoryTest {

    private static final String PUBLICATION_STRING = "AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA";
    private InMemoryKsiSignatureComponentFactory signatureComponentFactory = new InMemoryKsiSignatureComponentFactory();
    private InMemoryKsiSignatureFactory signatureFactory;
    private ContextAwarePolicy policy = ContextAwarePolicyAdapter.createInternalPolicy();
    private SignatureVerifier verifier = new SignatureVerifier();

    @BeforeMethod
    public void setUp() throws Exception {
        PublicationsFileClientAdapter mockedPublicationsFileAdapter = Mockito.mock(PublicationsFileClientAdapter.class);
        Mockito.when(mockedPublicationsFileAdapter.getPublicationsFile()).thenReturn(TestUtil.loadPublicationsFile(PUBLICATIONS_FILE));

        KSIExtenderClient extenderClient = Mockito.mock(KSIExtenderClient.class);
        Mockito.when(extenderClient.getPduVersion()).thenReturn(V2);
        this.signatureFactory = new InMemoryKsiSignatureFactory(policy, new InMemoryKsiSignatureComponentFactory());
    }

    @Test
    public void testCreateValidKsiSignature_Ok() throws Exception {
        KSISignature signature = signatureFactory.createSignature(TestUtil.loadTlv(SIGNATURE_2017_03_14), null);
        Assert.assertNotNull(signature);
    }

    @Test
    public void testCreateSignatureWithAggregationHashChainWithLeftLinksOnly_Ok() throws Exception {
        createSignatureWithAggregationChainAndVerify(
                SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_HEIGHT_3,
                SIGNATURE_WITH_LEVEL_CORRECTION_3,
                "01580192B0D06E48884432DFFC26A67C6C685BEAF0252B9DD2A0B4B05D1724C5F2");
    }

    @Test
    public void testCreateSignatureWithAggregationHashChainWithLeftAndRightLinks_Ok() throws Exception {
        createSignatureWithAggregationChainAndVerify(
                SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_LEFT_AND_RIGHT_LINKS_AND_HEIGHT_3,
                SIGNATURE_WITH_LEVEL_CORRECTION_3,
                "018D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E34");
    }

    @Test
    public void testCreateSignatureWithAggregationHashChainWithRightLinksOnly_Ok() throws Exception {
        createSignatureWithAggregationChainAndVerify(
                SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_RIGHT_LINKS_AND_HEIGHT_3,
                SIGNATURE_WITH_LEVEL_CORRECTION_3,
                "019D982C6911831201C5CF15E937514686A2169E2AD57BA36FD92CBEBD99A67E32");
    }

    @Test
    public void testCreateSignatureWithAggregationHashChainWithLeftLinksAndMetadata_Ok() throws Exception {
        createSignatureWithAggregationChainAndVerify(
                SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_LEFT_LINKS_AND_HEIGHT_5,
                SIGNATURE_WITH_LEVEL_CORRECTION_5,
                "04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    }

    @Test
    public void testCreateSignatureWithAggregationHashChainWithHeightLessThanLevelCorrection_Ok() throws Exception {
        createSignatureWithAggregationChainAndVerify(
                SIGNATURE_AGGREGATION_HASH_CHAIN_WITH_LEFT_LINK_AND_HEIGHT_1,
                SIGNATURE_WITH_LEVEL_CORRECTION_14,
                "0111A700B0C8066C47ECBA05ED37BC14DCADB238552D86C659342D1D7E87B8772D");
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

    @Test(expectedExceptions = KSIException.class,
            expectedExceptionsMessageRegExp = "The aggregation hash chain cannot be added as lowest level chain. " +
                    "Its aggregation time .* does not match base signature aggregation time .*")
    public void testCreateSignatureWithWrongAggregationTime_throwsKSIException() throws Exception {
        AggregationHashChain chain = Mockito.mock(AggregationHashChain.class);
        ChainResult cr = Mockito.mock(ChainResult.class);
        Mockito.when(cr.getLevel()).thenReturn(0L);
        Mockito.when(chain.calculateOutputHash(0L)).thenReturn(cr);
        Mockito.when(chain.getOutputHash()).thenReturn(new DataHash(Base16.decode("015A848EE304CBE6B858ABCCFA0E8397920C226FD18B9E5A34D0048F749B2DA0EC")));

        Mockito.when(chain.getAggregationTime()).thenReturn(new Date(1515660418000L));
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

    private void createSignatureWithAggregationChainAndVerify(String chainFilename, String signatureFilename, String inputHashImprint) throws Exception {
        AggregationHashChain chain = new InMemoryAggregationHashChain(loadTlv(chainFilename));
        KSISignature signature = TestUtil.loadSignature(signatureFilename);
        DataHash inputHash = new DataHash(Base16.decode(inputHashImprint));
        ByteArrayOutputStream signatureBytes = new ByteArrayOutputStream();
        ByteArrayOutputStream signatureBytesAfterSignatureCreation = new ByteArrayOutputStream();
        signature.writeTo(signatureBytes);

        KSISignature newSignature = signatureFactory.createSignature(signature, chain, inputHash);
        signature.writeTo(signatureBytesAfterSignatureCreation);

        Assert.assertEquals(signatureBytesAfterSignatureCreation.toByteArray(), signatureBytes.toByteArray());
        VerificationResult result = verifier.verify(newSignature, inputHash, this.policy);
        Assert.assertTrue(result.isOk());
    }
}
