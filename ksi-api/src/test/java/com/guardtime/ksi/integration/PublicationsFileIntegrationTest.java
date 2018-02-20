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
import com.guardtime.ksi.publication.inmemory.InMemoryPublicationsFileFactory;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.trust.CryptoException;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContextBuilder;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy;

import org.bouncycastle.util.Store;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_CERT;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_HEADER;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD2;
import static com.guardtime.ksi.Resources.SIGNATURE_2014_06_02;

public class PublicationsFileIntegrationTest extends AbstractCommonIntegrationTest {

    private final PublicationsFileBasedVerificationPolicy policy = new PublicationsFileBasedVerificationPolicy();

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInPublicationRecordLvl1() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD, true, extenderClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInPublicationRecordLvl2() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD2, true, extenderClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInCertificateRecord() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_CERT, true, extenderClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInPublicationHeader() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_HEADER, true, extenderClient);
        Assert.assertTrue(results.isOk());
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
        return ksi.verify(build.build(), policy);
    }
}
