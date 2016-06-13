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

package com.guardtime.ksi.integration;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.publication.inmemory.InMemoryPublicationsFileFactory;
import com.guardtime.ksi.publication.inmemory.InvalidPublicationsFileException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.trust.CryptoException;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy;
import org.bouncycastle.util.Store;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

import static com.guardtime.ksi.CommonTestUtil.load;

public class PublicationsFileBasedVerificationPolicyIntegrationTest extends AbstractCommonIntegrationTest {

    private final PublicationsFileBasedVerificationPolicy policy = new PublicationsFileBasedVerificationPolicy();

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureWithCorrectDataAndSuitablePublicationInPublicationFile_VerificationReturnsOK() throws Exception {
        VerificationResult results = publicationFileBasedVerification("ok-sig-2014-06-2-extended.ksig", "publications.tlv", false, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyUnextendedSignatureWithCorrectDataExtendingAllowed_VerificationReturnsOk() throws Exception {
        KSISignature signature = TestUtil.loadSignature("ok-sig-2014-06-2.ksig");
        VerificationResult result = verify(ksi, simpleHttpClient, signature, policy, true);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyUnextendedSignatureWithCorrectDataExtendingNotAllowed_VerificationReturnsGen2() throws Exception {
        KSISignature signature = TestUtil.loadSignature("ok-sig-2014-06-2.ksig");
        VerificationResult result = verify(ksi, simpleHttpClient, signature, policy, false);
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_2);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureWithCorrectDataExtendingAllowed_VerificationReturnsGen2() throws Exception {
        KSISignature signature = TestUtil.loadSignature("ok-sig-2014-04-30.1-extended.ksig");
        VerificationResult result = verify(ksi, simpleHttpClient, signature, policy, true);
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_2);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyNewerSignatureWithOlderPublicationFile_VerificationReturnsGen2() throws Exception {
        VerificationResult results = publicationFileBasedVerification("signature_2015-09-13_21-34-00.ksig", "publication-based-verification/old-publications.tlv", true, simpleHttpClient);
        Assert.assertFalse(results.isOk());
        Assert.assertEquals(results.getErrorCode(), VerificationErrorCode.GEN_2);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureWithWrongResponseMissMatchInInputHash_VerificationReturnsPub1() throws Exception {
        KSIExtenderClient mockedExtenderClient = Mockito.mock(KSIExtenderClient.class);

        String responseFile = "publication-based-verification/extension-response-for-ok-sig-2014-06-2-wrong-input-hash.tlv";
        mockExtenderResponseCalendarHashCain(responseFile, mockedExtenderClient);

        VerificationResult result = publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publication-2015-09-15.tlv", true, mockedExtenderClient);
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.PUB_01);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureWithWrongResponseMissMatchInPublicationTime_VerificationReturnsPub2() throws Exception {
        KSIExtenderClient mockedExtenderClient = Mockito.mock(KSIExtenderClient.class);

        String responseFile = "publication-based-verification/extension-response-for-ok-sig-2014-06-2-wrong-publication-time.tlv";
        mockExtenderResponseCalendarHashCain(responseFile, mockedExtenderClient);

        VerificationResult result = publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publication-2015-09-15.tlv", true, mockedExtenderClient);
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.PUB_02);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithWrongHashChain_VerificationReturnsPub3() throws Exception {
        VerificationResult results = publicationFileBasedVerification("publication-based-verification/all-wrong-hash-chains-in-signature.ksig", "publication-2015-09-15.tlv", true, simpleHttpClient);
        Assert.assertFalse(results.isOk());
        Assert.assertEquals(results.getErrorCode(), VerificationErrorCode.PUB_03);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown critical TLV element with tag=0x1 encountered")
    public void testVerifySignatureWithPublicationWithExtraCriticalElementInPublicationRecordLvl1() throws Exception {
        publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publicartions-new-critical-element-in-publication-record-lvl1.tlv", true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown critical TLV element with tag=0x5 encountered")
    public void testVerifySignatureWithPublicationWithExtraCriticalElementInPublicationRecordLvl2() throws Exception {
        publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publicartions-new-critical-element-in-publication-record-lvl2.tlv", true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x708")
    public void testVerifySignatureWithPublicationWithNewCriticalTlvBlock() throws Exception {
        publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publicartions-new-critical-nested-tlv-in-main.tlv", true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x708")
    public void testVerifySignatureWithPublicationWithNewCriticalTlbBlockWithNonCriticalChild() throws Exception {
        publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publicartions-new-critical-nested-tlv-in-main-with-non-critical-tlvs.tlv", true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInPublicationRecordLvl1() throws Exception {
        VerificationResult results = publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publicartions-new-non-critical-element-in-publication-record-lvl1.tlv", true, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInPublicationRecordLvl2() throws Exception {
        VerificationResult results = publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publicartions-new-non-critical-element-in-publication-record-lvl2.tlv", true, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x708")
    public void testVerifySignatureWithPublicationWithNewNonCriticalTlvBlock() throws Exception {
        publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publicartions-new-non-critical-nested-tlv-in-main.tlv", true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x708")
    public void testVerifySignatureWithPublicationWithNewNonCriticalTlvBlockWithCriticalChild() throws Exception {
        publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publicartions-new-non-critical-nested-tlv-in-main-with-critical-tlvs.tlv", true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown critical TLV element with tag=0x5 encountered")
    public void testVerifySignatureWithPublicationWithNewCriticalElementInCertificateRecord() throws Exception {
        publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publicartions-new-critical-element-in-certificate-record-lvl1.tlv", true, simpleHttpClient);

    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown critical TLV element with tag=0x5 encountered")
    public void testVerifySignatureWithPublicationWithNewCriticalElementInPublicationHeader() throws Exception {
        publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publicartions-new-critical-element-in-publication-header-lvl1.tlv", true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInCertificateRecord() throws Exception {
        VerificationResult results = publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publicartions-new-non-critical-element-in-certificate-record-lvl1.tlv", true, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInPublicationHeader() throws Exception {
        VerificationResult results = publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publicartions-new-non-critical-element-in-publication-header-lvl1.tlv", true, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithWrongPublicationHash() throws Exception {
        VerificationResult results = publicationFileBasedVerification("ok-sig-2014-06-2.ksig", "publications-file/publications-one-cert-one-publication-record-with-wrong-hash.tlv", true, simpleHttpClient);
        Assert.assertFalse(results.isOk());
        Assert.assertEquals(results.getErrorCode(), VerificationErrorCode.PUB_01);
    }

    private VerificationResult publicationFileBasedVerification(String signatureFile, String publicationFile, boolean extendingAllowed, KSIExtenderClient extenderClient) throws Exception {
        VerificationContextBuilder build = new VerificationContextBuilder();
        build.setPublicationsFile(new InMemoryPublicationsFileFactory(new PKITrustStore() {
            public boolean isTrusted(X509Certificate certificate, Store certStore) throws CryptoException {
                return true;
            }
        }).create(load(publicationFile)));
        KSISignature signature = TestUtil.loadSignature(signatureFile);
        build.setSignature(signature).setExtenderClient(extenderClient);
        build.setExtendingAllowed(extendingAllowed);
        return ksi.verify(build.createVerificationContext(), policy);
    }
}
