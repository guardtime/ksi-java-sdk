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

import com.guardtime.ksi.CommonTestUtil;
import com.guardtime.ksi.KSI;
import com.guardtime.ksi.KSIBuilder;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.inmemory.PublicationsFilePublicationRecord;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.InvalidSignatureContentException;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.policies.*;
import com.guardtime.ksi.util.Util;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.InputStream;

import static com.guardtime.ksi.TestUtil.loadFile;

public class DefaultVerificationIntegrationTest extends AbstractCommonIntegrationTest {
    private static KSIBuilder ksiBuilder;
    private static InputStream signatureInputStream;

    @BeforeMethod
    public void setUp() throws Exception {
        SimpleHttpClient httpClient = new SimpleHttpClient(loadHTTPSettings());
        ksiBuilder = new KSIBuilder().setKsiProtocolExtenderClient(httpClient).
                setKsiProtocolPublicationsFileClient(httpClient).
                setKsiProtocolSignerClient(httpClient).
                setPublicationsFileTrustedCertSelector(createCertSelector());
        signatureInputStream = CommonTestUtil.load(SIGNATURE_2014_06_02);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testSigning_InvalidSignatureContentException() throws Exception {
        Policy policy = new PublicationsFileBasedVerificationPolicy();
        KSI ksiTest = ksiBuilder.setDefaultVerificationPolicy(policy).build();

        try{
            ksiTest.sign(new byte[32]);
        } catch (InvalidSignatureContentException e) {
            Assert.assertNotNull(e.getSignature(), "Signature in exception is NULL.");
            Assert.assertEquals(e.getVerificationResult().getErrorCode(), VerificationErrorCode.GEN_2);
        }
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testExtendSignature_InvalidSignatureContentException() throws Exception {
        KSI ksiTest = ksiBuilder.build();
        KSISignature signature = ksiTest.read(loadFile("calendar-based-verification/all-wrong-hash-chains-in-signature.ksig"));

        PublicationRecord publicationRecord = new PublicationsFilePublicationRecord(new PublicationData("AAAAAA-CX5TF7-IAOXTG-6N4TGI-AIGLHG-ZD2NOX-WHGLYG-HHOXAD-XJ3FIN-GXJSGS-72NPRL-3ECEBJ"));
        try {
            ksiTest.extend(signature, publicationRecord);
        } catch (InvalidSignatureContentException e) {
            Assert.assertTrue(e.getSignature().isExtended());
            Assert.assertEquals(e.getVerificationResult().getErrorCode(), VerificationErrorCode.INT_03);
        }
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testInternalVerificationAsDefaultVerificationPolicy_OK() throws Exception {
        InternalVerificationPolicy policy = new InternalVerificationPolicy();
        KSI ksiTest = ksiBuilder.setDefaultVerificationPolicy(policy).build();
        try{
            ksiTest.read(signatureInputStream);
        } catch (InvalidSignatureContentException e) {
            System.out.println("Verification failed with policy " + policy.getName());
            System.out.println(e.getVerificationResult().isOk());
            throw e;
        }

    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testInternalVerificationAsDefaultPolicy_InvalidSignatureContentException() throws Exception {
        Policy policy = new InternalVerificationPolicy();
        KSI ksiTest = ksiBuilder.setDefaultVerificationPolicy(policy).build();
        try{
            ksiTest.read(loadFile("aggregation-hash-chain-metadata/metadata-padding-too-long.ksig"));
        } catch (InvalidSignatureContentException e) {
            Assert.assertEquals(e.getVerificationResult().getErrorCode(), VerificationErrorCode.INT_11);
        }
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testKeyBasedVerificationAsDefaultVerificationPolicy_InvalidSignatureContentException() throws Exception {
        Policy policy = new KeyBasedVerificationPolicy();
        KSI ksiTest = ksiBuilder.setDefaultVerificationPolicy(policy).build();
        try {
            ksiTest.read(loadFile("internal-verification-authentication-records/NewSignature-CalAuth-WrongCertID.ksig"));
        } catch (InvalidSignatureContentException e) {
            Assert.assertEquals(e.getVerificationResult().getErrorCode(), VerificationErrorCode.KEY_01);
        }

    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testCalendarBasedVerificationAsDefaultVerificationPolicy_InvalidSignatureContentException() throws Exception {
        Policy policy = new CalendarBasedVerificationPolicy();
        KSI ksiTest = ksiBuilder.setDefaultVerificationPolicy(policy).build();
        try {
            ksiTest.read(loadFile("calendar-based-verification/all-wrong-hash-chains-in-signature.ksig"));
        } catch (InvalidSignatureContentException e) {
            Assert.assertEquals(e.getVerificationResult().getErrorCode(), VerificationErrorCode.CAL_02);
        }

    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testPublicationFileBasedVerificationAsDefaultVerificationPolicy_InvalidSignatureContentException() throws Exception {
        Policy policy = new PublicationsFileBasedVerificationPolicy();
        KSI ksiTest = ksiBuilder.setDefaultVerificationPolicy(policy).build();
        try {
            ksiTest.read(loadFile("calendar-based-verification/all-wrong-hash-chains-in-signature.ksig"));
        } catch (InvalidSignatureContentException e) {
            Assert.assertEquals(e.getVerificationResult().getErrorCode(), VerificationErrorCode.PUB_03);
        }
    }
}
