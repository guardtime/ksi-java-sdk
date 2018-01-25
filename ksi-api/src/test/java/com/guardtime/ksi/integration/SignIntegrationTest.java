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
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.service.client.http.HttpClientSettings;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;

import org.testng.Assert;
import org.testng.annotations.Test;

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

public class SignIntegrationTest extends AbstractCommonIntegrationTest {

    @Test
    public void testSigningWithSignerClient_Ok() throws Exception {
        Signer s = new SignerBuilder().setSigningService(ksi.getSigningService()).build();
        KSISignature sig = s.sign(loadFile(INPUT_FILE));
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, simpleHttpClient, getFileHash(INPUT_FILE)), new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testSignFile_Ok(KSI ksi) throws Exception {
        KSISignature sig = ksi.sign(loadFile(INPUT_FILE));
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, ksi.getExtendingService(), getFileHash(INPUT_FILE)), new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testSignHash_Ok(KSI ksi) throws Exception {
        KSISignature sig = ksi.sign(getFileHash(INPUT_FILE));
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, ksi.getExtendingService(), getFileHash(INPUT_FILE)), new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testSignHashWithLevel_Ok(KSI ksi) throws Exception {
        KSISignature sig = ksi.sign(getFileHash(INPUT_FILE), 3L);
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, ksi.getExtendingService(), getFileHash(INPUT_FILE), 3L), new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testSignFileAndUseInvalidHashForVerification_VerificationFailsWithErrorGen1(KSI ksi) throws Exception {
        KSISignature sig = ksi.sign(loadFile(INPUT_FILE));
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, ksi.getExtendingService(), getFileHash(INPUT_FILE_REVERSED)), new KeyBasedVerificationPolicy());
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
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION, expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Level must be between 0 and 255")
    public void testSignWithTooLargeLevel_Ok(KSI ksi) throws Exception {
        ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 257L);
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION, expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Level must be between 0 and 255")
    public void testSignWithLessThanZeroLevel_Ok(KSI ksi) throws Exception {
        ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), -1L);
    }

    /** Response with first right link that has sibling data */
    @Test
    public void testSigningWithLevelRightLinkSiblingData() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_SIBLING_HASH);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 5);
        checkSignatureFirstLink(signature, 5L, false, 2);
    }

    /** Response with first right link that has legacy id */
    @Test
    public void testSigningWithLevelRightLinkLegacyId() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_LEGACY_ID);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 5);
        checkSignatureFirstLink(signature, 5L, false, 3);
    }

    /** Response with first right link that has metadata */
    @Test
    public void testSigningWithLevelRightLinkMetadata() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_METADATA);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 5);
        checkSignatureFirstLink(signature, 5L, false, 4);
    }

    /** Response with first right link that has sibling data and level correction */
    @Test
    public void testSigningWithLevelRightLinkSiblingDataAndLevel() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_SIBLING_HASH_AND_LEVEL);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 2);
        checkSignatureFirstLink(signature, 7L, false, 2);
    }

    /** Response with first right link that has legacy id and level correction */
    @Test
    public void testSigningWithLevelRightLinkLegacyIdAndLevel() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_LEGACY_ID_AND_LEVEL);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 2);
        checkSignatureFirstLink(signature, 7L, false, 3);
    }

    /** Response with first right link that has metadata and level correction */
    @Test
    public void testSigningWithLevelRightLinkMetadataAndLevel() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_RIGHT_WITH_METADATA_AND_LEVEL);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 2);
        checkSignatureFirstLink(signature, 7L, false, 4);
    }

    /** Response with first left link that has sibling data */
    @Test
    public void testSigningWithLevelLeftLinkSiblingData() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_SIBLING_HASH);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 5);
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
        checkSignatureFirstLink(signature, 5L, true, 4);
    }

    /** Response with first left link that has sibling data and level correction */
    @Test
    public void testSigningWithLevelLeftLinkSiblingDataAndLevel() throws Exception {
        KSI ksi = mockSigning(AGGREGATION_RESPONSE_FIRST_LINK_LEFT_WITH_SIBLING_HASH_AND_LEVEL);
        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[HashAlgorithm.SHA2_256.getLength()]), 2);
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
        checkSignatureFirstLink(signature, 7L, true, 4);
    }

    /**
     * Mocks PDU V2 aggregation response by changing request ID and updating HMAC.
     * @param responseFile Aggregation response file.
     * @return KSI with mocked aggregation response.
     */
    protected static KSI mockSigning(String responseFile) throws Exception {
        HttpClientSettings settings = loadHTTPSettings();
        KSISigningService mockedSigningService = mockSigningService(responseFile, settings.getCredentials());

        return new KSIBuilder().setKsiProtocolExtenderClient(new SimpleHttpClient(settings)).
                setKsiProtocolPublicationsFileClient(new SimpleHttpClient(settings)).
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
