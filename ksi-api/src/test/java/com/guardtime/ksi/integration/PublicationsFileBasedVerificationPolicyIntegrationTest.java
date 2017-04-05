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
import org.testng.Assert;
import org.testng.annotations.Test;

import java.security.cert.X509Certificate;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.Resources.EXTENDED_SIGNATURE_2014_04_30;
import static com.guardtime.ksi.Resources.EXTENDED_SIGNATURE_2014_06_02;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_CERT;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_HEADER;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_RECORD;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_RECORD2;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CRITICAL_NESTED_ELEMENT_IN_MAIN;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_CRITICAL_NESTED_ELEMENT_IN_MAIN_WITH_NON_CIRITCAL_ELEMENTS;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_CERT;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_HEADER;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_MAIN;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_MAIN_WITH_CIRITCAL_ELEMENTS;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD2;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_WRONG_HASH;
import static com.guardtime.ksi.Resources.SIGNATURE_2014_06_02;

public class PublicationsFileBasedVerificationPolicyIntegrationTest extends AbstractCommonIntegrationTest {

    private final PublicationsFileBasedVerificationPolicy policy = new PublicationsFileBasedVerificationPolicy();

    //TODO: Looks like there are several publiation file prasing tests included.
    //TODO: Most, if not all, tests should be covered with new tests?

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureWithCorrectDataAndSuitablePublicationInPublicationFile_VerificationReturnsOK() throws Exception {
        VerificationResult results = publicationFileBasedVerification(EXTENDED_SIGNATURE_2014_06_02, PUBLICATIONS_FILE, false, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyUnextendedSignatureWithCorrectDataExtendingAllowed_VerificationReturnsOk() throws Exception {
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2014_06_02);
        VerificationResult result = verify(ksi, simpleHttpClient, signature, policy, true);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyUnextendedSignatureWithCorrectDataExtendingNotAllowed_VerificationReturnsGen2() throws Exception {
        KSISignature signature = TestUtil.loadSignature(SIGNATURE_2014_06_02);
        VerificationResult result = verify(ksi, simpleHttpClient, signature, policy, false);
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_2);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureWithCorrectDataExtendingAllowed_OK() throws Exception {
        KSISignature signature = TestUtil.loadSignature(EXTENDED_SIGNATURE_2014_04_30);
        VerificationResult result = verify(ksi, simpleHttpClient, signature, policy, true);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown critical TLV element with tag=0x1 encountered")
    public void testVerifySignatureWithPublicationWithExtraCriticalElementInPublicationRecordLvl1() throws Exception {
        publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_RECORD, true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown critical TLV element with tag=0x5 encountered")
    public void testVerifySignatureWithPublicationWithExtraCriticalElementInPublicationRecordLvl2() throws Exception {
        publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_RECORD2, true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x708")
    public void testVerifySignatureWithPublicationWithNewCriticalTlvBlock() throws Exception {
        publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_CRITICAL_NESTED_ELEMENT_IN_MAIN, true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x708")
    public void testVerifySignatureWithPublicationWithNewCriticalTlbBlockWithNonCriticalChild() throws Exception {
        publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_CRITICAL_NESTED_ELEMENT_IN_MAIN_WITH_NON_CIRITCAL_ELEMENTS, true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInPublicationRecordLvl1() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD, true, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInPublicationRecordLvl2() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_RECORD2, true, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x708")
    public void testVerifySignatureWithPublicationWithNewNonCriticalTlvBlock() throws Exception {
        publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_MAIN, true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidPublicationsFileException.class, expectedExceptionsMessageRegExp = "Invalid publications file element type=0x708")
    public void testVerifySignatureWithPublicationWithNewNonCriticalTlvBlockWithCriticalChild() throws Exception {
        publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_MAIN_WITH_CIRITCAL_ELEMENTS, true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown critical TLV element with tag=0x5 encountered")
    public void testVerifySignatureWithPublicationWithNewCriticalElementInCertificateRecord() throws Exception {
        publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_CERT, true, simpleHttpClient);

    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = TLVParserException.class, expectedExceptionsMessageRegExp = "Unknown critical TLV element with tag=0x5 encountered")
    public void testVerifySignatureWithPublicationWithNewCriticalElementInPublicationHeader() throws Exception {
        publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_CRITICAL_ELEMENT_IN_HEADER, true, simpleHttpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInCertificateRecord() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_CERT, true, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithNewNonCriticalElementInPublicationHeader() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_NON_CRITICAL_ELEMENT_IN_HEADER, true, simpleHttpClient);
        Assert.assertTrue(results.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithPublicationWithWrongPublicationHash() throws Exception {
        VerificationResult results = publicationFileBasedVerification(SIGNATURE_2014_06_02, PUBLICATIONS_FILE_WRONG_HASH, true, simpleHttpClient);
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
