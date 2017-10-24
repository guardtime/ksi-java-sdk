/*
 * Copyright 2013-2017 Guardtime, Inc.
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

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.service.KSIExtendingClientServiceAdapter;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.PolicyVerificationResult;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.verifier.policies.CalendarBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.UserProvidedPublicationBasedVerificationPolicy;
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
    public void testValidSignatures(IntegrationTestDataHolder testData) throws Exception {
        testExecution(testData);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, dataProvider = INVALID_SIGNATURES)
    public void testInvalidSignatures(IntegrationTestDataHolder testData) throws Exception {
        testExecution(testData);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, dataProvider = POLICY_VERIFICATION_SIGNATURES)
    public void testPolicyVerificationSignatures(IntegrationTestDataHolder testData) throws Exception {
        testExecution(testData);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingKeyBasedPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, new KSIExtendingClientServiceAdapter(simpleHttpClient), sig, new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingCalendarBasedPolicy_Ok(KSI ksi) throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, new KSIExtendingClientServiceAdapter(simpleHttpClient), sig, new CalendarBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithUsingPublicationsFileBasedVerificationPolicy_Ok(KSI ksi) throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new PublicationsFileBasedVerificationPolicy(), true);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureWithUserProvidedPublicationString_OK() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, simpleHttpClient, sig.getPublicationRecord()
                .getPublicationData()), new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingKeyBasedPolicy_FailInconclusive() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, new KSIExtendingClientServiceAdapter(simpleHttpClient), sig, new KeyBasedVerificationPolicy());
        Assert.assertFalse(result.isOk());
        PolicyVerificationResult policyVerificationResult = result.getPolicyVerificationResults().get(0);
        Assert.assertEquals(policyVerificationResult.getPolicyStatus(), VerificationResultCode.NA);
        Assert.assertEquals(policyVerificationResult.getErrorCode(), VerificationErrorCode.GEN_02);
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingCalendarBasedPolicy_Ok(KSI ksi) throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, new KSIExtendingClientServiceAdapter(simpleHttpClient), sig, new CalendarBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingPublicationsFileBasedPolicy_Ok(KSI ksi) throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, simpleHttpClient, sig, new PublicationsFileBasedVerificationPolicy(), true);
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureUsingUserProvidedPublicationsBasedPolicyAllowExtending_Ok(KSI ksi) throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        PublicationRecord publication = ksi.getPublicationsFile().getPublicationRecord(sig.getAggregationTime());
        VerificationResult result = ksi.verify(TestUtil.buildContext(sig, ksi, simpleHttpClient, publication.getPublicationData
                (), true), new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOfflineKSIRfc3161SignatureUsingKeyBasedPolicy() throws Exception {
        KSISignature signature = loadSignature(RFC3161_SIGNATURE);
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, simpleHttpClient, getFileHash(INPUT_FILE,
                "SHA2-256")), new KeyBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOnlineKSIRfc3161SignatureUsingCalendarBasedVerificationPolicy(KSI ksi) throws Exception {
        KSISignature signature = loadSignature(RFC3161_SIGNATURE);
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, simpleHttpClient, getFileHash(INPUT_FILE,
                "SHA2-256")), new CalendarBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOnlineExtendedKSIRfc3161SignatureWithPublicationString() throws Exception {
        KSISignature signature = loadSignature(RFC3161_EXTENDED_FOR_PUBLICATIONS_FILE_VERIFICATION);
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, simpleHttpClient, signature
                .getPublicationRecord().getPublicationData()), new UserProvidedPublicationBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOfflineExtendedKSIRfc3161Signature() throws Exception {
        KSISignature signature = loadSignature(RFC3161_EXTENDED_FOR_PUBLICATIONS_FILE_VERIFICATION);
        VerificationResult result = ksi.verify(TestUtil.buildContext(signature, ksi, simpleHttpClient, signature.getInputHash()
        ), new PublicationsFileBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingContextKeyBasedPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result =
                ksi.verify(sig, ContextAwarePolicyAdapter.createKeyPolicy(getPublicationsHandler(simpleHttpClient)));
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingContextCalendarBasedPolicy_Ok(KSI ksi)
            throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result =
                ksi.verify(sig, ContextAwarePolicyAdapter.createCalendarPolicy(getExtender(ksi.getExtendingService(), simpleHttpClient)));
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingContextPublicationsFilePolicy_Ok(KSI ksi)
            throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result =
                ksi.verify(sig, ContextAwarePolicyAdapter.createPublicationsFilePolicy(getPublicationsHandler(simpleHttpClient),
                        getExtender(ksi.getExtendingService(), simpleHttpClient)));
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingContextPublicationsFilePolicyExtendingNotAllowed_NA(KSI ksi)
            throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result =
                ksi.verify(sig, ContextAwarePolicyAdapter.createPublicationsFilePolicy(getPublicationsHandler(simpleHttpClient)));
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_02);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOfflineExtendedKSIRfc3161SignatureUsingContextPublicationsFilePolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(RFC3161_EXTENDED_FOR_PUBLICATIONS_FILE_VERIFICATION);
        VerificationResult result =
                ksi.verify(sig, ContextAwarePolicyAdapter.createPublicationsFilePolicy(getPublicationsHandler(simpleHttpClient)));
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureWithContextUserProvidedPublicationString_OK(KSI ksi)
            throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        VerificationResult result =
                ksi.verify(sig, ContextAwarePolicyAdapter.createUserProvidedPublicationPolicy(
                        sig.getPublicationRecord().getPublicationData(),
                        getExtender(ksi.getExtendingService(), simpleHttpClient)));
        Assert.assertTrue(result.isOk());
    }
}
