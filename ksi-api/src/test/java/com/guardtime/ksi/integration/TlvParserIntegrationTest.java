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

import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.MultipleTLVElementException;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.PolicyVerificationResult;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.CalendarBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.List;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.Resources.EXTENDED_CALENDAR_WITH_CRITICAL_ELEMENT;
import static com.guardtime.ksi.Resources.EXTENDED_CALENDAR_WITH_EXTRA_CRITICAL_PDU_WITH_CRITICAL_ELEMENTS;
import static com.guardtime.ksi.Resources.EXTENDED_CALENDAR_WITH_EXTRA_CRITICAL_PDU_WITH_NON_CRITICAL_ELEMENTS;
import static com.guardtime.ksi.Resources.EXTENDED_CALENDAR_WITH_EXTRA_NON_CRITICAL_PDU_WITH_CRITICAL_ELEMENTS;
import static com.guardtime.ksi.Resources.EXTENDED_CALENDAR_WITH_EXTRA_NON_CRITICAL_PDU_WITH_NON_CRITICAL_ELEMENTS;
import static com.guardtime.ksi.Resources.EXTENDED_CALENDAR_WITH_NON_CRITICAL_ELEMENT;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;

public class TlvParserIntegrationTest extends AbstractCommonIntegrationTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(TlvParserIntegrationTest.class);
    private final Policy policy = new CalendarBasedVerificationPolicy();

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithNonCriticalElementInExtenderResponse() throws Exception {
        String testFile = EXTENDED_CALENDAR_WITH_NON_CRITICAL_ELEMENT;

        LOGGER.info("Used response file: " + testFile);
        KSIExtendingService mockedExtendingService = mockExtenderResponseCalendarHashCain(testFile);

        KSISignature signature = ksi.read(load(SIGNATURE_2017_03_14));
        VerificationResult result = verify(ksi, mockedExtendingService, signature, policy);
        Assert.assertFalse(result.isOk());
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.CAL_04);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithUnknownCriticalElementInExtenderResponse() throws Exception {
        String exceptionMessage = "parse response message";
        Class exceptionClass = KSIProtocolException.class;
        testExtenderResponses(EXTENDED_CALENDAR_WITH_CRITICAL_ELEMENT, exceptionClass, exceptionMessage, true);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithExtraCriticalPduInExtenderResponse() throws Exception {
        String exceptionMessage = "Message outermost layer consists of more than one TLV elements.";
        Class exceptionClass = MultipleTLVElementException.class;
        testExtenderResponses(EXTENDED_CALENDAR_WITH_EXTRA_CRITICAL_PDU_WITH_CRITICAL_ELEMENTS, exceptionClass, exceptionMessage, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithExtraCriticalPduWithNonCriticalElementsInExtenderResponse() throws Exception {
        String exceptionMessage = "Message outermost layer consists of more than one TLV elements.";
        Class exceptionClass = MultipleTLVElementException.class;
        testExtenderResponses(EXTENDED_CALENDAR_WITH_EXTRA_CRITICAL_PDU_WITH_NON_CRITICAL_ELEMENTS, exceptionClass, exceptionMessage, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithExtraNonCiriticalCriticalPduInExtenderResponse() throws Exception {
        String exceptionMessage = "Message outermost layer consists of more than one TLV elements.";
        Class exceptionClass = MultipleTLVElementException.class;
        testExtenderResponses(EXTENDED_CALENDAR_WITH_EXTRA_NON_CRITICAL_PDU_WITH_CRITICAL_ELEMENTS, exceptionClass, exceptionMessage, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithExtraNonCriticalPduWithNonCriticalElementsInExtenderResponse() throws Exception {
        String exceptionMessage = "Message outermost layer consists of more than one TLV elements.";
        Class exceptionClass = MultipleTLVElementException.class;
        testExtenderResponses(EXTENDED_CALENDAR_WITH_EXTRA_NON_CRITICAL_PDU_WITH_NON_CRITICAL_ELEMENTS, exceptionClass, exceptionMessage, false);
    }

    private void testExtenderResponses(String testFile, Class exceptionClass, String message, boolean checkVerificationError) throws Exception {
        try {
            LOGGER.info("Used response file: " + testFile);
            KSIExtendingService mockedExtenderClient = mockExtenderResponseCalendarHashCain(testFile);

            KSISignature signature = ksi.read(load(SIGNATURE_2017_03_14));
            VerificationResult result = verify(ksi, mockedExtenderClient, signature, policy);
            if (checkVerificationError) {
                List<PolicyVerificationResult> results = result.getPolicyVerificationResults();
                for (PolicyVerificationResult r : results) {
                    if (r.getException() != null) {
                        throw r.getException();
                    }
                }
            }
            throw new IntegrationTestFailureException("No exception was thrown when verifying " + SIGNATURE_2017_03_14 + " with extender response " + testFile);
        } catch (IntegrationTestFailureException e) {
            throw e;
        } catch (Exception e) {
            if (!(e.getClass().isAssignableFrom(exceptionClass))) {
                throw new IntegrationTestFailureException("Expected exception " + exceptionClass.toString() + " but received " + e.getClass().toString());
            } else if (!(e.getMessage().contains(message))) {
                throw new IntegrationTestFailureException("Expected exception message '" + message + "' was not found int " + e.getMessage());
            }
        }
    }
}
