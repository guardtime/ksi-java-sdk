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
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.PolicyVerificationResult;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.verifier.policies.*;
import org.testng.Assert;
import org.testng.annotations.Test;

import static com.guardtime.ksi.TestUtil.loadSignature;

public class VerifyIntegrationTest extends AbstractCommonIntegrationTest {
    //TODO: Are all of the following tests covered by new tests?

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingKeyBasedPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2014_06_02);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingCalendarBasedPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2014_06_02);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new CalendarBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithUsingPublicationsFileBasedVerificationPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2014_06_02);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new PublicationsFileBasedVerificationPolicy(), true);
        Assert.assertTrue(result.isOk());
    }

    //TODO: Covered by new tests?
    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingUserPublicationBasedPolicy_VerificationFailsWrongPublication() throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2014_06_02);
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, simpleHttpClient, new PublicationData(PUIBLICATION_STRING_2014_05_15)), new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_2);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void verifyExtendedSignatureWithUserProvidedPublicationString_OK() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2014_04_30);
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, simpleHttpClient, new PublicationData(PUIBLICATION_STRING_2014_05_15)), new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    //TODO: Covered by new tests?
    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingKeyBasedPolicy_FailInconclusive() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2014_06_02);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new KeyBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        PolicyVerificationResult policyVerificationResult = result.getPolicyVerificationResults().get(0);
        Assert.assertEquals(policyVerificationResult.getPolicyStatus(), VerificationResultCode.NA);
        Assert.assertEquals(policyVerificationResult.getErrorCode(), VerificationErrorCode.GEN_2);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingCalendarBasedPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2014_06_02);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new CalendarBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingPublicationsFileBasedPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2014_06_02);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new PublicationsFileBasedVerificationPolicy(), true);
        Assert.assertTrue(result.isOk());
    }

    //TODO: Covered by new tests?
    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingUserProvidedPublicationsBasedPolicy_FailInconclusive() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2014_06_02);
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, simpleHttpClient, new PublicationData(PUIBLICATION_STRING_2014_05_15)), new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_2);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingUserProvidedPublicationsBasedPolicyAllowExtending_Ok() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2014_06_02);
        PublicationRecord publication = ksi.getPublicationsFile().getPublicationRecord(sig.getAggregationTime());
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, simpleHttpClient, publication.getPublicationData(), true), new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    //TODO: Covered by new tests?
    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithInvalidRfc3161RecordUsingKeyBasedPolicy_VerificationFailInconsistentChain() throws Exception {
        KSISignature sig = loadSignature("signature/signature-with-invalid-rfc3161-output-hash.ksig");
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new KeyBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        PolicyVerificationResult policyResult = result.getPolicyVerificationResults().get(0);
        Assert.assertEquals(policyResult.getPolicyStatus(), VerificationResultCode.FAIL);
        Assert.assertEquals(policyResult.getErrorCode(), VerificationErrorCode.INT_01);
    }

    //TODO: Covered by new tests?
    @Test(groups = TEST_GROUP_INTEGRATION)
    public void verifySignatureWithLocalPubFile_TestFailInconclusive() throws Exception {
        PublicationsFile pub = TestUtil.loadPublicationsFile("publications-file/publications.15042014.tlv");
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2014_06_02);
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, simpleHttpClient, null, pub), new PublicationsFileBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_2);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOfflineKSIRfc3161SignatureUsingKeyBasedPolicy() throws Exception {
        KSISignature signature = loadSignature("testdata.txt.2015-01.tlv");
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, simpleHttpClient, getFileHash("testdata.txt", "SHA2-256")), new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOnlineKSIRfc3161SignatureUsingCalendarBasedVerificationPolicy() throws Exception {
        KSISignature signature = loadSignature("testdata.txt.2015-01.tlv");
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, simpleHttpClient, getFileHash("testdata.txt", "SHA2-256")), new CalendarBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOnlineExtendedKSIRfc3161SignatureWithPublicationString() throws Exception {
        KSISignature signature = loadSignature("testdata-extended.txt.2015-01.tlv");
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, simpleHttpClient, new PublicationData("AAAAAA-CUW4BQ-AAM6GY-ZSTYCJ-KTXF2M-AJB5RV-WEXTTH-3EWTQQ-XRUN6I-K7TXUN-X6PDV5-OIFY6C")), new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOfflineExtendedKSIRfc3161Signature() throws Exception {
        KSISignature signature = loadSignature("testdata-extended.txt.2015-01.tlv");
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, simpleHttpClient, getFileHash("testdata.txt", "SHA2-256")), new PublicationsFileBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }
}