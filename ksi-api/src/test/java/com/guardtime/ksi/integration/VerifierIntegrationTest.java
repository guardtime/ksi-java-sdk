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

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import org.testng.Assert;
import org.testng.annotations.Test;

import static com.guardtime.ksi.Resources.EXTENDED_SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.RFC3161_EXTENDED_FOR_PUBLICATIONS_FILE_VERIFICATION;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static com.guardtime.ksi.TestUtil.loadSignature;

public class VerifierIntegrationTest extends AbstractCommonIntegrationTest {

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingKeyBasedPolicy_Ok() throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result =
                ksi.verify(sig, ContextAwarePolicyAdapter.createKeyPolicy(getPublicationsHandler(simpleHttpClient)));
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingCalendarBasedPolicy_Ok(KSI ksi, KSIExtenderClient extenderClient) throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result =
                ksi.verify(sig, ContextAwarePolicyAdapter.createCalendarPolicy(getExtender(extenderClient, simpleHttpClient)));
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithUsingPublicationsFileBasedVerificationPolicy_Ok(KSI ksi, KSIExtenderClient extenderClient)
            throws Exception {
        KSISignature sig = loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result =
                ksi.verify(sig, ContextAwarePolicyAdapter.createPublicationsFilePolicy(getPublicationsHandler(simpleHttpClient),
                        getExtender(extenderClient, simpleHttpClient)));
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyOfflineExtendedKSIRfc3161Signature() throws Exception {
        KSISignature sig = loadSignature(RFC3161_EXTENDED_FOR_PUBLICATIONS_FILE_VERIFICATION);
        VerificationResult result =
                ksi.verify(sig, ContextAwarePolicyAdapter.createPublicationsFilePolicy(getPublicationsHandler(simpleHttpClient)));
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureWithUserProvidedPublicationString_OK(KSI ksi, KSIExtenderClient extenderClient)
            throws Exception {
        KSISignature sig = loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        VerificationResult result =
                ksi.verify(sig, ContextAwarePolicyAdapter.createUserPolicy(sig.getPublicationRecord().getPublicationData(),
                        getExtender(extenderClient, simpleHttpClient)));
        Assert.assertTrue(result.isOk());
    }
}
