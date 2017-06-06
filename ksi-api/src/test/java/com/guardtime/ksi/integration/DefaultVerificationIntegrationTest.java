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
import com.guardtime.ksi.KSIBuilder;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.inmemory.PublicationsFilePublicationRecord;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.inmemory.InvalidSignatureContentException;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.policies.CalendarBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.InternalVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.UserProvidedPublicationBasedVerificationPolicy;
import com.guardtime.ksi.util.Util;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.guardtime.ksi.CommonTestUtil.loadFile;
import static com.guardtime.ksi.Resources.SIGNATURE_CHANGED_CHAINS;
import static com.guardtime.ksi.Resources.SIGNATURE_METADATA_PADDING_TOO_LONG;
import static com.guardtime.ksi.Resources.SIGNATURE_OTHER_CORE;
import static com.guardtime.ksi.Resources.SIGNATURE_OTHER_CORE_EXTENDED_CALENDAR;
import static com.guardtime.ksi.Resources.SIGNATURE_PUB_REC_WRONG_CERT_ID_VALUE;

public class DefaultVerificationIntegrationTest extends AbstractCommonIntegrationTest {
    private static KSIBuilder ksiBuilder;

    @BeforeMethod
    public void setUp() throws Exception {
        SimpleHttpClient httpClient = new SimpleHttpClient(loadHTTPSettings());
        ksiBuilder = initKsiBuilder(httpClient, httpClient, httpClient);
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = ".*Verification inconclusive.*")
    public void testSigningWithPublicationFileBasedVerification_InvalidSignatureContentException_GEN2() throws Exception {
        Policy policy = new PublicationsFileBasedVerificationPolicy();
        KSI ksiTest = ksiBuilder.setDefaultVerificationPolicy(policy).build();

        try{
            ksiTest.sign(new byte[32]);
        } catch (InvalidSignatureContentException e) {
            Assert.assertNotNull(e.getSignature(), "Signature is not provided with exception.");
            Assert.assertEquals(e.getVerificationResult().getErrorCode(), VerificationErrorCode.GEN_2);
            throw e;
        }
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = ".*Calendar hash chain input hash mismatch.*")
    public void testExtendInvalidSignature_InvalidSignatureContentException_INT3() throws Exception {
        KSI ksiTest = ksiBuilder.build();
        KSISignature signature = ksiTest.read(loadFile(SIGNATURE_CHANGED_CHAINS));

        PublicationRecord publicationRecord = new PublicationsFilePublicationRecord(new PublicationData("AAAAAA-CX5TF7-IAOXTG-6N4TGI-AIGLHG-ZD2NOX-WHGLYG-HHOXAD-XJ3FIN-GXJSGS-72NPRL-3ECEBJ"));
        try {
            ksiTest.extend(signature, publicationRecord);
        } catch (InvalidSignatureContentException e) {
            Util.notNull(e.getSignature(), "Signature is not provided with exception.");
            Assert.assertEquals(e.getVerificationResult().getErrorCode(), VerificationErrorCode.INT_03);
            throw e;
        }
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = ".*The metadata record in the aggregation hash chain may not be trusted.*")
    public void testInternalVerificationAsDefaultPolicy_InvalidSignatureContentException_INT11() throws Exception {
        Policy policy = new InternalVerificationPolicy();
        KSI ksiTest = ksiBuilder.setDefaultVerificationPolicy(policy).build();
        ksiTest.read(loadFile(SIGNATURE_METADATA_PADDING_TOO_LONG));
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = ".*Certificate not found.*")
    public void testKeyBasedVerificationAsDefaultVerificationPolicy_InvalidSignatureContentException_KEY1() throws Exception {
        Policy policy = new KeyBasedVerificationPolicy();
        KSI ksiTest = ksiBuilder.setDefaultVerificationPolicy(policy).build();
        ksiTest.read(loadFile(SIGNATURE_PUB_REC_WRONG_CERT_ID_VALUE));
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = ".*Unsupported default verification policy.*")
    public void testUserProvidedPublicationBasedVerificationAsDefaultVerificationPolicy() throws Exception {
        ksiBuilder.setDefaultVerificationPolicy(new UserProvidedPublicationBasedVerificationPolicy()).build();
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = ".*Aggregation hash chain root hash and calendar database hash chain input hash mismatch.*")
    public void testCalendarBasedVerificationAsDefaultVerificationPolicy_InvalidSignatureContentException_CAL2() throws Exception {
        Policy policy = new CalendarBasedVerificationPolicy();
        KSI ksiTest = ksiBuilder.setDefaultVerificationPolicy(policy).build();
        ksiTest.read(loadFile(SIGNATURE_OTHER_CORE));
    }

    @Test(groups = TEST_GROUP_INTEGRATION, expectedExceptions = InvalidSignatureContentException.class, expectedExceptionsMessageRegExp = ".*Extender response input hash mismatch.*")
    public void testPublicationFileBasedVerificationAsDefaultVerificationPolicy_InvalidSignatureContentException_PUB3() throws Exception {
        Policy policy = new PublicationsFileBasedVerificationPolicy();
        KSI ksiTest = ksiBuilder.setDefaultVerificationPolicy(policy).build();
        ksiTest.read(loadFile(SIGNATURE_OTHER_CORE_EXTENDED_CALENDAR));
    }
}
