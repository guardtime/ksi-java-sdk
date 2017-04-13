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
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.PolicyVerificationResult;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.verifier.policies.*;
import org.testng.Assert;
import org.testng.annotations.Test;

import static com.guardtime.ksi.Resources.EXTENDED_SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.INPUT_FILE;
import static com.guardtime.ksi.Resources.RFC3161_EXTENDED_FOR_PUBLICATIONS_FILE_VERIFICATION;
import static com.guardtime.ksi.Resources.RFC3161_SIGNATURE;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static com.guardtime.ksi.TestUtil.loadSignature;

public class VerifyIntegrationTest extends AbstractCommonIntegrationTest {

    @Test(groups = TEST_GROUP_INTEGRATION, dataProvider = VALID_SIGNATURES)
    public void testValidSignatures(DataHolderForIntegrationTests testData) throws Exception {
        testExecution(testData);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, dataProvider = INVALID_SIGNATURES)
    public void testInvalidSignatures(DataHolderForIntegrationTests testData) throws Exception {
        testExecution(testData);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, dataProvider = POLICY_VERIFICATION_SIGNATURES)
    public void testPolicyVerificationSignatures(DataHolderForIntegrationTests testData) throws Exception {
        testExecution(testData);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingKeyBasedPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingCalendarBasedPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new CalendarBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithUsingPublicationsFileBasedVerificationPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new PublicationsFileBasedVerificationPolicy(), true);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureWithUserProvidedPublicationString_OK() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, simpleHttpClient, sig.getPublicationRecord().getPublicationData()), new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingKeyBasedPolicy_FailInconclusive() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new KeyBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        PolicyVerificationResult policyVerificationResult = result.getPolicyVerificationResults().get(0);
        Assert.assertEquals(policyVerificationResult.getPolicyStatus(), VerificationResultCode.NA);
        Assert.assertEquals(policyVerificationResult.getErrorCode(), VerificationErrorCode.GEN_2);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingCalendarBasedPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new CalendarBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingPublicationsFileBasedPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new PublicationsFileBasedVerificationPolicy(), true);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingUserProvidedPublicationsBasedPolicyAllowExtending_Ok() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        PublicationRecord publication = ksi.getPublicationsFile().getPublicationRecord(sig.getAggregationTime());
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, simpleHttpClient, publication.getPublicationData(), true), new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOfflineKSIRfc3161SignatureUsingKeyBasedPolicy() throws Exception {
        KSISignature signature = loadSignature(RFC3161_SIGNATURE);
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, simpleHttpClient, getFileHash(INPUT_FILE, "SHA2-256")), new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOnlineKSIRfc3161SignatureUsingCalendarBasedVerificationPolicy() throws Exception {
        KSISignature signature = loadSignature(RFC3161_SIGNATURE);
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, simpleHttpClient, getFileHash(INPUT_FILE, "SHA2-256")), new CalendarBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOnlineExtendedKSIRfc3161SignatureWithPublicationString() throws Exception {
        KSISignature signature = loadSignature(RFC3161_EXTENDED_FOR_PUBLICATIONS_FILE_VERIFICATION);
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, simpleHttpClient, signature.getPublicationRecord().getPublicationData()), new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOfflineExtendedKSIRfc3161Signature() throws Exception {
        KSISignature signature = loadSignature(RFC3161_EXTENDED_FOR_PUBLICATIONS_FILE_VERIFICATION);
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, simpleHttpClient, signature.getInputHash()), new PublicationsFileBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }
}