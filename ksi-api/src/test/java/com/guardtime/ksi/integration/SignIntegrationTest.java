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
package com.guardtime.ksi.integration;

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.KSIBuilder;
import com.guardtime.ksi.Signer;
import com.guardtime.ksi.SignerBuilder;
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.AggregationResponseFuture;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.RequestContextFactory;
import com.guardtime.ksi.pdu.v2.PduV2Factory;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.service.http.simple.SimpleHttpExtenderClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpPublicationsFileClient;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import com.guardtime.ksi.util.Util;

import org.apache.commons.io.IOUtils;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.CommonTestUtil.loadFile;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_LEGACY_ID;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_LEGADY_ID_AND_LEVEL;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_METADATA;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_METADATA_AND_LEVEL;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_SIBLING_HASH;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_SIBLING_HASH_AND_LEVEL;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_LEGACY_ID;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_LEGACY_ID_AND_LEVEL;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_METADATA;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_METADATA_AND_LEVEL;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_SIBLING_HASH;
import static com.guardtime.ksi.Resources.AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_SIBLING_HASH_AND_LEVEL;
import static com.guardtime.ksi.Resources.INPUT_FILE;
import static com.guardtime.ksi.Resources.INPUT_FILE_REVERSED;
import static com.guardtime.ksi.TestUtil.calculateHash;

public class SignIntegrationTest extends AbstractCommonIntegrationTest {

    @Test
    public void testSigningWithSignerClient_Ok() throws Exception {
        Signer signer = new SignerBuilder().setSigningService(ksi.getSigningService()).build();
        KSISignature sig = signer.sign(loadFile(INPUT_FILE));
        signer.close();
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, extenderClient, getFileHash(INPUT_FILE)), new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testSignFile_Ok(KSI ksi) throws Exception {
        KSISignature sig = ksi.sign(loadFile(INPUT_FILE));
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, ksi.getExtendingService(), getFileHash(INPUT_FILE)), new KeyBasedVerificationPolicy());
        ksi.close();
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testSignHash_Ok(KSI ksi) throws Exception {
        KSISignature sig = ksi.sign(getFileHash(INPUT_FILE));
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, ksi.getExtendingService(), getFileHash(INPUT_FILE)), new KeyBasedVerificationPolicy());
        ksi.close();
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testSignHashWithLevel_Ok(KSI ksi) throws Exception {
        KSISignature sig = ksi.sign(getFileHash(INPUT_FILE), 3L);
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, ksi.getExtendingService(), getFileHash(INPUT_FILE), 3L), new KeyBasedVerificationPolicy());
        ksi.close();
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testSignFileAndUseInvalidHashForVerification_VerificationFailsWithErrorGen1(KSI ksi) throws Exception {
        KSISignature sig = ksi.sign(loadFile(INPUT_FILE));
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, ksi.getExtendingService(), getFileHash(INPUT_FILE_REVERSED)), new KeyBasedVerificationPolicy());
        ksi.close();
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_01);
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testSignWithLevel_Ok(KSI ksi) throws Exception {
        DataHash dataHash = new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]);
        KSISignature sig = ksi.sign(dataHash, 2L);
        Assert.assertTrue(sig.getAggregationHashChains()[0].getChainLinks().get(0).getLevelCorrection() >= 2L,
                "Signature's first link's level correction is smaller than used for sining.");
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, ksi.getExtendingService(), dataHash), new KeyBasedVerificationPolicy());
        ksi.close();
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION, expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Level must be between 0 and 255")
    public void testSignWithTooLargeLevel_Ok(KSI ksi) throws Exception {
        try {
            ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 257L);
        } finally {
            ksi.close();
        }
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION, expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Level must be between 0 and 255")
    public void testSignWithLessThanZeroLevel_Ok(KSI ksi) throws Exception {
        try {
            ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), -1L);
        } finally {
            ksi.close();
        }
    }

    /** Response with first right link that has sibling data */
    @Test
    public void testSigningWithLevelRightLinkSiblingData() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_SIBLING_HASH);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 5);
        ksi.close();
        checkSignatureFirstLink(signature, 5L, false, 2);
    }

    /** Response with first right link that has legacy id */
    @Test
    public void testSigningWithLevelRightLinkLegacyId() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_LEGACY_ID);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 5);
        ksi.close();
        checkSignatureFirstLink(signature, 5L, false, 3);
    }

    /** Response with first right link that has metadata */
    @Test
    public void testSigningWithLevelRightLinkMetadata() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_METADATA);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 5);
        ksi.close();
        checkSignatureFirstLink(signature, 5L, false, 4);
    }

    /** Response with first right link that has sibling data and level correction */
    @Test
    public void testSigningWithLevelRightLinkSiblingDataAndLevel() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_SIBLING_HASH_AND_LEVEL);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 2);
        ksi.close();
        checkSignatureFirstLink(signature, 7L, false, 2);
    }

    /** Response with first right link that has legacy id and level correction */
    @Test
    public void testSigningWithLevelRightLinkLegacyIdAndLevel() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_LEGACY_ID_AND_LEVEL);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 2);
        ksi.close();
        checkSignatureFirstLink(signature, 7L, false, 3);
    }

    /** Response with first right link that has metadata and level correction */
    @Test
    public void testSigningWithLevelRightLinkMetadataAndLevel() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_METADATA_AND_LEVEL);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 2);
        ksi.close();
        checkSignatureFirstLink(signature, 7L, false, 4);
    }

    /** Response with first left link that has sibling data */
    @Test
    public void testSigningWithLevelLeftLinkSiblingData() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_SIBLING_HASH);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 5);
        ksi.close();
        checkSignatureFirstLink(signature, 5L, true, 2);
    }

    /** Response with first left link that has legacy id */
    @Test
    public void testSigningWithLevelLeftLinkLegacyId() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_LEGACY_ID);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 5);
        checkSignatureFirstLink(signature, 5L, true, 3);
    }

    /** Response with first left link that has metadata */
    @Test
    public void testSigningWithLevelLeftLinkMetadata() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_METADATA);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 5);
        ksi.close();
        checkSignatureFirstLink(signature, 5L, true, 4);
    }

    /** Response with first left link that has sibling data and level correction */
    @Test
    public void testSigningWithLevelLeftLinkSiblingDataAndLevel() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_SIBLING_HASH_AND_LEVEL);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 2);
        ksi.close();
        checkSignatureFirstLink(signature, 7L, true, 2);
    }

    /** Response with first left link that has legacy id and level correction */
    @Test
    public void testSigningWithLevelLeftLinkLegacyIdAndLevel() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_LEGADY_ID_AND_LEVEL);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 2);
        checkSignatureFirstLink(signature, 7L, true, 3);
    }

    /** Response with first left link that has metadata and level correction */
    @Test
    public void testSigningWithLevelLeftLinkMetadataAndLevel() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_METADATA_AND_LEVEL);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 2);
        ksi.close();
        checkSignatureFirstLink(signature, 7L, true, 4);
    }

    /**
     * Mocks PDU V2 aggregation response by changing request ID and updating HMAC.
     * @param responseFile Aggregation response file.
     * @return KSI with mocked aggregation response.
     */
    private KSI mockSigning(final String responseFile) throws Exception {
        final ServiceCredentials signerCredentials =  loadSignerSettings().getCredentials();

        KSISigningService mockedSigningService = Mockito.mock(KSISigningService.class);
        final Future<TLVElement> mockedFuture = Mockito.mock(Future.class);
        Mockito.when(mockedFuture.isFinished()).thenReturn(Boolean.TRUE);
        final TLVElement responseTLV = TLVElement.create(IOUtils.toByteArray(load(responseFile)));
        Mockito.when(mockedFuture.getResult()).thenReturn(responseTLV);

        Mockito.when(mockedSigningService.sign(Mockito.any(DataHash.class), Mockito.any
            (long.class))).then(new Answer<Future>() {
                public Future<AggregationResponse> answer(InvocationOnMock invocationOnMock) throws Throwable {
                    DataHash dataHash = (DataHash) invocationOnMock.getArguments()[0];
                    long level = (long) invocationOnMock.getArguments()[1];

                    PduFactory factory = new PduV2Factory();
                    KSIRequestContext context = RequestContextFactory.DEFAULT_FACTORY.createContext();
                    AggregationRequest request = factory.createAggregationRequest(context, signerCredentials, dataHash, level);
                    ByteArrayInputStream bais = new ByteArrayInputStream(request.toByteArray());
                    TLVElement requestElement = TLVElement.create(Util.toByteArray(bais));
                    //Set header
                    responseTLV.getFirstChildElement(0x1).setContent(requestElement.getFirstChildElement(0x1).getEncoded());
                    //Set Request ID
                    responseTLV.getFirstChildElement(0x2).getFirstChildElement(0x1).setLongContent(requestElement.getFirstChildElement(0x2).getFirstChildElement(0x1).getDecodedLong());
                    //Set Input hash
                    responseTLV.getFirstChildElement(0x2).getFirstChildElement(0x801).getFirstChildElement(0x5).setDataHashContent(dataHash);
                    //Update HMAC
                    responseTLV.getFirstChildElement(0x1F).setDataHashContent(calculateHash(responseTLV, responseTLV.getFirstChildElement(0x1F).getDecodedDataHash().getAlgorithm(), signerCredentials.getLoginKey()));
                    return new AggregationResponseFuture(mockedFuture, context, signerCredentials, factory);
                }
            });

        return new KSIBuilder().setKsiProtocolExtenderClient(new SimpleHttpExtenderClient(loadExtenderSettings())).
                setKsiProtocolPublicationsFileClient(new SimpleHttpPublicationsFileClient(loadPublicationsFileSettings())).
                setKsiProtocolSigningService(mockedSigningService).
                setPublicationsFilePkiTrustStore(createKeyStore()).
                setPublicationsFileTrustedCertSelector(createCertSelector()).
                build();
    }

    private void checkSignatureFirstLink(KSISignature signature, Long expectedLevel, boolean isLeft, int expectedSiblingType) {
        long level = signature.getAggregationHashChains()[0].getChainLinks().get(0).getLevelCorrection();
        Assert.assertTrue(level == expectedLevel,
                "Expected link level " + expectedLevel + " but found " + level);

        Assert.assertEquals(signature.getAggregationHashChains()[0].getChainLinks().get(0).isLeft(), isLeft,
                "Expected link direction was not found.");

        Assert.assertNotNull(((TLVStructure)signature.getAggregationHashChains()[0].getChainLinks().get(0)).getRootElement().getFirstChildElement(expectedSiblingType),
                "Expected sibling data type of " + expectedSiblingType + " was not found.");
    }
}
