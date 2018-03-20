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

import com.guardtime.ksi.Extender;
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;
import com.guardtime.ksi.unisignature.verifier.policies.UserProvidedPublicationBasedVerificationPolicy;
import org.testng.Assert;
import org.testng.annotations.Test;

import static com.guardtime.ksi.Resources.EXTENDED_SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;

public class UserProvidedPublicationPolicyIntegrationTest extends AbstractCommonIntegrationTest {

    private final UserProvidedPublicationBasedVerificationPolicy policy = new UserProvidedPublicationBasedVerificationPolicy();
    private static final String PUBLICATION_STRING_2017_03_15 = "AAAAAA-CYZBC2-QANONS-4PPSPX-M3UFZ2-ZD3MEV-YUG4LI-KNWRAU-TZHEB6-V7SCG6-J4QK56-OKW6FT";
    private static final String PUBLICATION_STRING_2017_03_18 = "AAAAAA-CYZTMY-QAPFTQ-SBXAY7-FNALRQ-HJ6QP4-U2CDTJ-OYLEND-DOHU47-QE7N27-OQHZPG-NVTZRV";

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithNoPublicationRecordinExtendingAllowed_VerificationReturnsOk() throws Exception {
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2017_03_14);
        PublicationData publicationData = new PublicationData(PUBLICATION_STRING_2017_03_15);
        VerificationResult result = verify(ksi, extenderClient, signature, policy, publicationData, true);
        Assert.assertTrue(result.isOk());
        result = verifyWithContext(signature, publicationData, true);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithCorrectData_VerificationReturnsOk() throws Exception {
        KSISignature signature = TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        VerificationResult result =
                verify(ksi, extenderClient, signature, policy, signature.getPublicationRecord().getPublicationData(), false);
        Assert.assertTrue(result.isOk());
        result = verifyWithContext(signature, signature.getPublicationRecord().getPublicationData(), false);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingDifferentPublication_VerificationReturnsOk() throws Exception {
        KSISignature signature = TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        PublicationData publicationData = new PublicationData(PUBLICATION_STRING_2017_03_18);
        VerificationResult result = verify(ksi, extenderClient, signature, policy, publicationData, true);
        Assert.assertTrue(result.isOk());
        result = verifyWithContext(signature, publicationData, true);
        Assert.assertTrue(result.isOk());
    }


    public VerificationResult verifyWithContext(KSISignature signature, PublicationData userPublication, boolean extendingAllowed)
            throws Exception {
        Extender extender = getExtender(ksi.getExtendingService(), publicationsFileClient);
        return ksi.verify(signature,
                ContextAwarePolicyAdapter.createUserProvidedPublicationPolicy(userPublication, extendingAllowed ? extender : null));
    }
}
