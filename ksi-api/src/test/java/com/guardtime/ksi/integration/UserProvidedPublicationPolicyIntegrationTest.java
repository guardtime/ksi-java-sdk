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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.unisignature.*;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.UserProvidedPublicationBasedVerificationPolicy;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Date;

import static com.guardtime.ksi.TestUtil.loadSignature;

public class UserProvidedPublicationPolicyIntegrationTest extends AbstractCommonIntegrationTest {

    private final UserProvidedPublicationBasedVerificationPolicy policy = new UserProvidedPublicationBasedVerificationPolicy();
    private static final String PUBLICATION_STRING_2014_09_15 = "AAAAAA-CUCYWA-AAOBM6-PNYLRK-EPI3VG-2PJGCF-Y5QHV3-XURLI2-GRFBK4-VHBED2-Q37QIB-UE3ENA";
    //TODO: Covered by new tests?
    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithNoPublicationRecordinExtendingAllowed_VerificationReturnsOk() throws Exception {
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2014_06_02);
        PublicationData publicationData = new PublicationData(PUBLICATION_STRING_2014_09_15);
        VerificationResult result = verify(ksi, simpleHttpClient, signature, policy, publicationData, true);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithCorrectData_VerificationReturnsOk() throws Exception {
        KSISignature signature = TestUtil.loadSignature(EXTENDED_SIGNATURE_2014_06_02);
        PublicationData publicationData = signature.getPublicationRecord().getPublicationData();
        VerificationResult result = verify(ksi, simpleHttpClient, signature, policy, publicationData, true);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureUsingDifferentPublication_VerificationReturnsOk() throws Exception {
        KSISignature signature = TestUtil.loadSignature(EXTENDED_SIGNATURE_2014_06_02);
        PublicationData publicationData = new PublicationData("AAAAAA-CTRQ5E-QAISH7-QFMEEV-CYN3XW-FWO33A-PXL4PD-4KS3Y5-FY2SYO-LIRKZK-HS25IW-5FIBTP");
        VerificationResult result = verify(ksi, simpleHttpClient, signature, policy, publicationData, true);
        Assert.assertTrue(result.isOk());
    }
}
