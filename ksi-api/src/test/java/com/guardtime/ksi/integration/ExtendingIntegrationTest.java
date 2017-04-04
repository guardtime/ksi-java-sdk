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
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.inmemory.PublicationsFilePublicationRecord;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.InvalidSignatureContentException;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.UserProvidedPublicationBasedVerificationPolicy;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import static com.guardtime.ksi.TestUtil.loadSignature;

public class ExtendingIntegrationTest extends AbstractCommonIntegrationTest {

    //TODO: Move used resources to new test resources where possible. If not all?

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testExtendToNearest_OK() throws Exception {
        KSISignature extendedSignature = ksi.extend(loadSignature(SIGNATURE_2014_06_02));
        Assert.assertTrue(extendedSignature.isExtended(), "Signature extension failed.");
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignature_OK() throws Exception {
        KSISignature signature = loadSignature(SIGNATURE_2014_06_02);
        signature = ksi.extend(signature);
        Assert.assertTrue(signature.isExtended(), "Signature extension failed.");

        VerificationResult verificationResult = ksi.verify(signature, new PublicationsFileBasedVerificationPolicy());
        Assert.assertTrue(verificationResult.isOk(), "Verification of extended signature failed with " + verificationResult.getErrorCode());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testExtendWithPublicationsFile_OK() throws Exception {
        KSISignature signature = loadSignature(SIGNATURE_2014_06_02);
        PublicationsFile publicationsFile = TestUtil.loadPublicationsFile("publication-2015-09-15.tlv");
        PublicationRecord publicationRecord = publicationsFile.getPublicationRecord(signature.getPublicationTime());
        KSISignature extendedSignature = ksi.extend(signature, publicationRecord);
        Assert.assertTrue(extendedSignature.isExtended());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testExtendToUserPublicationString_OK() throws Exception {
        PublicationData publicationData_2016_07_12 = new PublicationData("AAAAAA-CXQQZQ-AAPGJF-HGNMUN-DXEIQW-NJZZOE-J76OK4-BV3FKY-AEAWIP-KSPZPW-EJKVAI-JPOOR7");
        PublicationRecord publicationRecord = new PublicationsFilePublicationRecord(publicationData_2016_07_12);
        KSISignature extendedSignature = ksi.extend(loadSignature(SIGNATURE_2014_06_02), publicationRecord);
        Assert.assertTrue(extendedSignature.isExtended(), "Signature extension failed");
        VerificationResult result = ksi.verify(extendedSignature, new UserProvidedPublicationBasedVerificationPolicy(), publicationData_2016_07_12);
        Assert.assertTrue(result.isOk());
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifyExtendedSignatureAfterWrithingToAndReadingFromStream_OK() throws Exception {
        KSISignature signature = loadSignature(SIGNATURE_2014_06_02);
        signature = ksi.extend(signature);
        Assert.assertTrue(signature.isExtended(), "Signature extension failed.");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        signature.writeTo(baos);
        signature = ksi.read(new ByteArrayInputStream(baos.toByteArray()));

        VerificationResult verificationResult = ksi.verify(signature, new PublicationsFileBasedVerificationPolicy());
        Assert.assertTrue(verificationResult.isOk(), "Verification of extended signature failed with " + verificationResult.getErrorCode());
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Publication is before signature")
    public void testExtendPublicationBeforeSignature_NOK() throws Exception {
        PublicationRecord publicationRecord = new PublicationsFilePublicationRecord(new PublicationData(PUIBLICATION_STRING_2014_05_15));
        ksi.extend(loadSignature(SIGNATURE_2014_06_02), publicationRecord);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testExtendSignatureFromAnotherCore_NOK() throws Exception {
        String publicationStringFromAnotherCore = "AAAAAA-CXQQZQ-AAOSZH-ONCB4K-TFGPBW-R6S6TF-6EW4DU-4QMP7X-GI2VCO-TNGAZM-EV6AZR-464IOA";
        KSISignature signature = loadSignature(SIGNATURE_2014_06_02);
        PublicationRecord record = new PublicationsFilePublicationRecord(new PublicationData(publicationStringFromAnotherCore));
        try {
            ksi.extend(signature, record);
            Assert.assertTrue(false, "Extended signature internal verification had to fail.");
        }catch (InvalidSignatureContentException e){
            Assert.assertFalse(e.getVerificationResult().isOk());
            Assert.assertEquals(e.getVerificationResult().getErrorCode(), VerificationErrorCode.INT_09);
            Assert.assertTrue(e.getSignature().isExtended());
        }
    }
}
