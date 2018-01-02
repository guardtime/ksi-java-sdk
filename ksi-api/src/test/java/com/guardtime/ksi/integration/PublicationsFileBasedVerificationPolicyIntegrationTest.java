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
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.trust.CryptoException;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy;
import org.bouncycastle.util.Store;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.Resources.EXTENDED_SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;

public class PublicationsFileBasedVerificationPolicyIntegrationTest extends AbstractCommonIntegrationTest {

    private final PublicationsFileBasedVerificationPolicy policy = new PublicationsFileBasedVerificationPolicy();

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureWithCorrectDataAndSuitablePublicationInPublicationFile_VerificationReturnsOK() throws Exception {
        VerificationResult results = publicationFileBasedVerification(EXTENDED_SIGNATURE_2017_03_14, null, false, extenderClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyUnextendedSignatureWithCorrectDataExtendingAllowed_VerificationReturnsOk() throws Exception {
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, extenderClient, signature, policy, true);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyUnextendedSignatureWithCorrectDataExtendingNotAllowed_VerificationReturnsGen2() throws Exception {
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, extenderClient, signature, policy, false);
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_02);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureWithCorrectDataExtendingAllowed_OK() throws Exception {
        KSISignature signature = TestUtil.loadSignature(EXTENDED_SIGNATURE_2017_03_14);
        VerificationResult result = verify(ksi, extenderClient, signature, policy, true);
        Assert.assertTrue(result.isOk());
    }

    private VerificationResult publicationFileBasedVerification(String signatureFile, String publicationFile, boolean extendingAllowed, KSIExtenderClient extenderClient) throws Exception {
        KSISignature signature = TestUtil.loadSignature(signatureFile);
        VerificationContextBuilder build = new VerificationContextBuilder();
        if (publicationFile != null) {
            build.setPublicationsFile(new InMemoryPublicationsFileFactory(new PKITrustStore() {
                public boolean isTrusted(X509Certificate certificate, Store certStore) throws CryptoException {
                    return true;
                }
            }).create(load(publicationFile)));
        } else {
            build.setPublicationsFile(ksi.getPublicationsFile());
        }
        build.setSignature(signature).setExtenderClient(extenderClient);
        build.setExtendingAllowed(extendingAllowed);
        return ksi.verify(build.build(), policy);
    }
}
