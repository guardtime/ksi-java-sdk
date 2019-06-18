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

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.service.client.http.CredentialsAwareHttpSettings;
import com.guardtime.ksi.service.http.simple.SimpleHttpExtenderClient;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.PolicyVerificationResult;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.CalendarBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.UserProvidedPublicationBasedVerificationPolicy;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.List;

import static com.guardtime.ksi.Resources.EXTENDED_SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.EXTENDER_RESPONSE_WITH_ERROR_AND_CALENDAR;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_WRONG_HASH;
import static com.guardtime.ksi.Resources.SIGNATURE_2014_06_02;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.SIGNATURE_ONLY_AGGREGATION_HASH_CHAINS;
import static com.guardtime.ksi.TestUtil.loadSignature;


public class FallbackPolicyIntegrationTest extends AbstractCommonIntegrationTest {

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallbackFromKeyBasedVerificationToCalendarBasedVerification_Ok() throws Exception {
        KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy();
        policy.setFallbackPolicy(new CalendarBasedVerificationPolicy());

        verification(TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14), policy, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallbackFromKeyBasedVerificationToPublicationFileBasedVerification_Ok() throws Exception {
        KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy();
        policy.setFallbackPolicy(new PublicationsFileBasedVerificationPolicy());

        verification(TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14), policy, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallbackFromKeyBasedVerificationToUserProvidedPublicationVerification_Ok() throws Exception {
        KeyBasedVerificationPolicy policy = new KeyBasedVerificationPolicy();
        policy.setFallbackPolicy(new UserProvidedPublicationBasedVerificationPolicy());

        KSISignature signature = TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        PublicationData publicationData = signature.getPublicationRecord().getPublicationData();
        verificationWithPublicationData(signature, policy, publicationData, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallbackFromPublicationFileBasedVerificationToCalendarBasedVerification_Ok() throws Exception {
        PublicationsFileBasedVerificationPolicy policy = new PublicationsFileBasedVerificationPolicy();
        policy.setFallbackPolicy(new CalendarBasedVerificationPolicy());

        verification(TestUtil.loadSignature(SIGNATURE_2017_03_14), policy, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallbackFromPublicationFileBasedVerificationToUserProvidedPublicationVerification_Ok() throws Exception {
        PublicationsFileBasedVerificationPolicy policy = new PublicationsFileBasedVerificationPolicy();
        policy.setFallbackPolicy(new UserProvidedPublicationBasedVerificationPolicy());

        PublicationsFile publicationFile = TestUtil.loadPublicationsFile(PUBLICATIONS_FILE_WRONG_HASH);
        KSISignature signature = TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        PublicationData publicationData = signature.getPublicationRecord().getPublicationData();

        VerificationContextBuilder builder = new VerificationContextBuilder();
        builder.setSignature(signature).setExtenderClient(extenderClient).setPublicationsFile(publicationFile);
        builder.setUserPublication(publicationData);
        builder.setExtendingAllowed(false);
        Assert.assertTrue(ksi.verify(builder.build(), policy).isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallbackFromPublicationFileBasedVerificationToKeyBasedVerification_Ok() throws Exception {
        PublicationsFileBasedVerificationPolicy policy = new PublicationsFileBasedVerificationPolicy();
        policy.setFallbackPolicy(new KeyBasedVerificationPolicy());

        verification(TestUtil.loadSignature(SIGNATURE_2017_03_14), policy, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallbackFromUserProvidedPublicationVerificationToCalendarBasedVerification_Ok() throws Exception {
        UserProvidedPublicationBasedVerificationPolicy policy = new UserProvidedPublicationBasedVerificationPolicy();
        policy.setFallbackPolicy(new CalendarBasedVerificationPolicy());

        PublicationData publicationData = TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14).getPublicationRecord().getPublicationData();
        verificationWithPublicationData(TestUtil.loadSignature(SIGNATURE_2017_03_14), policy, publicationData, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallbackFromUserProvidedPublicationVerificationToPublicationFileBasedVerification_Ok() throws Exception {
        UserProvidedPublicationBasedVerificationPolicy policy = new UserProvidedPublicationBasedVerificationPolicy();
        policy.setFallbackPolicy(new PublicationsFileBasedVerificationPolicy());

        PublicationData publicationData = new PublicationData("AAAAAA-CS2XHY-AAJCBE-DDAFMR-R3RKMY-GMAQDZ-FSAE7B-ZO64CT-QPNC3B-RQ6UGY-67QORK-6STDTS");
        verificationWithPublicationData(TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14), policy, publicationData, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallbackFromUserProvidedPublicationVerificationToKeyBasedVerification_Ok() throws Exception {
        UserProvidedPublicationBasedVerificationPolicy policy = new UserProvidedPublicationBasedVerificationPolicy();
        policy.setFallbackPolicy(new KeyBasedVerificationPolicy());

        PublicationData publicationData = TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14).getPublicationRecord().getPublicationData();
        verificationWithPublicationData(TestUtil.loadSignature(SIGNATURE_2017_03_14), policy, publicationData, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallBackFromUserPublicationAndPublicationFileToKeyBasedPolicy_Ok() throws Exception {
        UserProvidedPublicationBasedVerificationPolicy policy = new UserProvidedPublicationBasedVerificationPolicy();
        PublicationsFileBasedVerificationPolicy fallback_policy = new PublicationsFileBasedVerificationPolicy();
        fallback_policy.setFallbackPolicy(new KeyBasedVerificationPolicy());
        policy.setFallbackPolicy(fallback_policy);

        PublicationData publicationData = TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14).getPublicationRecord().getPublicationData();
        verificationWithPublicationData(TestUtil.loadSignature(SIGNATURE_2017_03_14), policy, publicationData, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallBackFromPublicationFileAndKeyBasedToCalendarPolicy_Ok() throws Exception {
        PublicationsFileBasedVerificationPolicy policy = new PublicationsFileBasedVerificationPolicy();
        KeyBasedVerificationPolicy fallback_policy = new KeyBasedVerificationPolicy();
        fallback_policy.setFallbackPolicy(new CalendarBasedVerificationPolicy());
        policy.setFallbackPolicy(fallback_policy);

        PublicationData publicationData = TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14).getPublicationRecord().getPublicationData();
        verificationWithPublicationData(TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14), policy, publicationData, false);
    }


    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallBackFromCalendarBasedPolicyToKeyBasedPolicyWithInvalidExtenderCredentials_Ok() throws Exception {
        CalendarBasedVerificationPolicy policy = new CalendarBasedVerificationPolicy();
        KeyBasedVerificationPolicy fallbackPolicy = new KeyBasedVerificationPolicy();
        policy.setFallbackPolicy(fallbackPolicy);

        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2017_03_14);
        SimpleHttpExtenderClient extClient = new SimpleHttpExtenderClient(new CredentialsAwareHttpSettings(
                loadExtenderSettings().getUrl().toString(), new KSIServiceCredentials("rand", "omnom")));
        VerificationResult result = verify(ksi, extClient, signature, policy, null, true);
        checkFallBackVerificationResultWithException(result, true, 2, KSIProtocolException.class);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallBackFromCalendarBasedPolicyToKeyBasedPolicyWithInvalidExtenderUrl_Ok() throws Exception {
        CalendarBasedVerificationPolicy policy = new CalendarBasedVerificationPolicy();
        KeyBasedVerificationPolicy fallbackPolicy = new KeyBasedVerificationPolicy();
        policy.setFallbackPolicy(fallbackPolicy);

        KSISignature signature = ksi.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        SimpleHttpExtenderClient randomClient = new SimpleHttpExtenderClient(new CredentialsAwareHttpSettings(
                "http://some.random.url.abc", new KSIServiceCredentials("rand", "omnom")));
        VerificationResult result = verify(ksi, randomClient, signature, policy, null, true);
        checkFallBackVerificationResultWithException(result, true, 2, KSIClientException.class);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testFallBackFromCalendarBasedPolicyToKeyBasedPolicyWithErrorResponseFromExtender_Ok() throws Exception {
        CalendarBasedVerificationPolicy policy = new CalendarBasedVerificationPolicy();
        KeyBasedVerificationPolicy fallbackPolicy = new KeyBasedVerificationPolicy();
        policy.setFallbackPolicy(fallbackPolicy);

        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2014_06_02);
        KSIExtendingService mockedExtenderService = mockExtenderResponseCalendarHashCain(EXTENDER_RESPONSE_WITH_ERROR_AND_CALENDAR);

        VerificationResult result = verify(ksi, mockedExtenderService, signature, policy, true);
        checkFallBackVerificationResultWithException(result, true, 2, KSIProtocolException.class);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifierCreatesNewContextInCaseOfUsesContextAwarePolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        ContextAwarePolicy policy = ContextAwarePolicyAdapter.createKeyPolicy(getPublicationsHandler(publicationsFileClient));
        policy.setFallbackPolicy(ContextAwarePolicyAdapter.createCalendarPolicy(getExtender(ksi.getExtendingService(), publicationsFileClient)));
        VerificationResult result = ksi.verify(sig, policy);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyContextAwarePolicyAndPolicyFallbackMix_Ok() throws Exception {
        //TODO: only agg chains is from test pack. should not?
        KSISignature sig = loadSignature(SIGNATURE_ONLY_AGGREGATION_HASH_CHAINS);

        Policy policy = new KeyBasedVerificationPolicy();
        PublicationsFile file = ksi.getPublicationsFile();
        PublicationData pubData = file.getPublicationRecord(sig.getAggregationTime()).getPublicationData();
        Policy fallbackPolicy = ContextAwarePolicyAdapter.createUserProvidedPublicationPolicy(pubData);
        fallbackPolicy.setFallbackPolicy(ContextAwarePolicyAdapter.createUserProvidedPublicationPolicy(
                pubData, getExtender(ksi.getExtendingService(), publicationsFileClient)
        ));
        policy.setFallbackPolicy(fallbackPolicy);

        ContextAwarePolicy contextAwarePolicy = ContextAwarePolicyAdapter.createPolicy(policy, getPublicationsHandler(publicationsFileClient), ksi.getExtendingService());
        VerificationResult result = ksi.verify(sig, contextAwarePolicy);
        Assert.assertEquals(result.getPolicyVerificationResults().size(), 3);
        Assert.assertTrue(result.isOk());
    }

    private void checkFallBackVerificationResultWithException(VerificationResult result, boolean resultIsOk, int policyResultsSize, Class expectedExceptionClass) {
        Assert.assertEquals(result.isOk(), resultIsOk);

        List<PolicyVerificationResult> policyResults = result.getPolicyVerificationResults();
        Assert.assertEquals(policyResults.size(), policyResultsSize);

        PolicyVerificationResult policyVerificationResult = getCalendarPolicyVerificationResult(policyResults);
        Assert.assertNotNull(policyVerificationResult);
        Assert.assertNotNull(policyVerificationResult.getException());
        Assert.assertEquals(policyVerificationResult.getException().getClass(), expectedExceptionClass);

    }

    private PolicyVerificationResult getCalendarPolicyVerificationResult(List<PolicyVerificationResult> policyResults) {
        for (PolicyVerificationResult policyResult : policyResults) {
            if(policyResult.getPolicy() instanceof CalendarBasedVerificationPolicy) {
                return policyResult;
            }
        }
        return null;
    }

    private void verification(KSISignature signature, Policy policy, boolean enableExtender) throws Exception {
        VerificationResult result = verify(ksi, extenderClient, signature, policy, enableExtender);
        Assert.assertTrue(result.isOk());
    }

    private void verificationWithPublicationData(KSISignature signature, Policy policy, PublicationData publicationData, boolean enableExtender) throws Exception {
        VerificationResult result = verify(ksi, extenderClient, signature, policy, publicationData, enableExtender);
        Assert.assertTrue(result.isOk());
    }
}
