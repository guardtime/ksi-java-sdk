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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.ExtensionRequest;
import com.guardtime.ksi.pdu.ExtensionResponseFuture;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.RequestContextFactory;
import com.guardtime.ksi.pdu.v1.PduV1Factory;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.MultipleTLVElementException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.PolicyVerificationResult;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.CalendarBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.util.Util;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Date;
import java.util.List;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.Resources.EXTENDER_RESPONSE_WITH_CRITICAL_ELEMENT;
import static com.guardtime.ksi.Resources.EXTENDER_RESPONSE_WITH_EXTRA_CRITICAL_PDU_WITH_CRITICAL_ELEMENTS;
import static com.guardtime.ksi.Resources.EXTENDER_RESPONSE_WITH_EXTRA_CRITICAL_PDU_WITH_NON_CRITICAL_ELEMENTS;
import static com.guardtime.ksi.Resources.EXTENDER_RESPONSE_WITH_EXTRA_NON_CRITICAL_PDU_WITH_CRITICAL_ELEMENTS;
import static com.guardtime.ksi.Resources.EXTENDER_RESPONSE_WITH_EXTRA_NON_CRITICAL_PDU_WITH_NON_CRITICAL_ELEMENTS;
import static com.guardtime.ksi.Resources.EXTENDER_RESPONSE_WITH_NON_CRITICAL_ELEMENT;
import static com.guardtime.ksi.Resources.EXTENSION_RESPONSE_DUMMY;
import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;

public class TlvParserIntegrationTest extends AbstractCommonIntegrationTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(TlvParserIntegrationTest.class);
    private final Policy policy = new CalendarBasedVerificationPolicy();

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithNonCriticalElementInExtenderResponse() throws Exception {
        String testFile = EXTENDER_RESPONSE_WITH_NON_CRITICAL_ELEMENT;

        LOGGER.info("Used response file: " + testFile);
        KSIExtendingService mockedExtendingService = mockExtenderResponseCalendarHashCain(testFile);

        KSISignature signature = ksi.read(load(SIGNATURE_2017_03_14));
        VerificationResult result = verify(ksi, mockedExtendingService, signature, policy);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithUnknownCriticalElementInExtenderResponse() throws Exception {
        String exceptionMessage = "parse response message";
        Class exceptionClass = KSIProtocolException.class;
        testExtenderResponses(EXTENDER_RESPONSE_WITH_CRITICAL_ELEMENT, exceptionClass, exceptionMessage, true);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithExtraCriticalPduInExtenderResponse() throws Exception {
        String exceptionMessage = "Message outermost layer consists of more than one TLV elements.";
        Class exceptionClass = MultipleTLVElementException.class;
        testExtenderResponses(EXTENDER_RESPONSE_WITH_EXTRA_CRITICAL_PDU_WITH_CRITICAL_ELEMENTS, exceptionClass, exceptionMessage, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithExtraCriticalPduWithNonCriticalElementsInExtenderResponse() throws Exception {
        String exceptionMessage = "Message outermost layer consists of more than one TLV elements.";
        Class exceptionClass = MultipleTLVElementException.class;
        testExtenderResponses(EXTENDER_RESPONSE_WITH_EXTRA_CRITICAL_PDU_WITH_NON_CRITICAL_ELEMENTS, exceptionClass, exceptionMessage, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithExtraNonCiriticalCriticalPduInExtenderResponse() throws Exception {
        String exceptionMessage = "Message outermost layer consists of more than one TLV elements.";
        Class exceptionClass = MultipleTLVElementException.class;
        testExtenderResponses(EXTENDER_RESPONSE_WITH_EXTRA_NON_CRITICAL_PDU_WITH_CRITICAL_ELEMENTS, exceptionClass, exceptionMessage, false);
    }

    @Test(groups = TEST_GROUP_INTEGRATION)
    public void testVerifySignatureWithExtraNonCriticalPduWithNonCriticalElementsInExtenderResponse() throws Exception {
        String exceptionMessage = "Message outermost layer consists of more than one TLV elements.";
        Class exceptionClass = MultipleTLVElementException.class;
        testExtenderResponses(EXTENDER_RESPONSE_WITH_EXTRA_NON_CRITICAL_PDU_WITH_NON_CRITICAL_ELEMENTS, exceptionClass, exceptionMessage, false);
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

    protected KSIExtendingService mockExtenderResponseCalendarHashCain(String responseCalendarChainFile) throws Exception {
        KSIExtendingService mockedExtenderService = Mockito.mock(KSIExtendingService.class);
        final Future<TLVElement> mockedFuture = Mockito.mock(Future.class);
        Mockito.when(mockedFuture.isFinished()).thenReturn(Boolean.TRUE);
        final TLVElement responseTLV = TLVElement.create(TestUtil.loadBytes(EXTENSION_RESPONSE_DUMMY));
        Mockito.when(mockedFuture.getResult()).thenReturn(responseTLV);
        final TLVElement calendarChain = TLVElement.create(TestUtil.loadBytes(responseCalendarChainFile));

        Mockito.when(mockedExtenderService.extend(Mockito.any(Date.class), Mockito.any
                (Date.class))).then(new Answer<Future>() {
            public Future answer(InvocationOnMock invocationOnMock) throws Throwable {
                ServiceCredentials credentials = loadExtenderSettings().getCredentials();
                KSIRequestContext requestContext = RequestContextFactory.DEFAULT_FACTORY.createContext();
                Date aggregationTime = (Date) invocationOnMock.getArguments()[0];
                Date publicationTime = (Date) invocationOnMock.getArguments()[1];
                PduFactory pduFactory = new PduV1Factory();
                ExtensionRequest requestMessage = pduFactory.createExtensionRequest(requestContext, credentials, aggregationTime,
                        publicationTime);
                ByteArrayInputStream requestStream = new ByteArrayInputStream(requestMessage.toByteArray());
                TLVElement tlvElement = TLVElement.create(Util.toByteArray(requestStream));
                TLVElement payload = responseTLV.getFirstChildElement(0x302);
                payload.getFirstChildElement(0x01).setLongContent(tlvElement.getFirstChildElement(0x301).getFirstChildElement
                        (0x01).getDecodedLong());

                payload.replace(payload.getFirstChildElement(CalendarHashChain.ELEMENT_TYPE), calendarChain);
                responseTLV.getFirstChildElement(0x1F).setDataHashContent(calculateHash(extenderClient.getServiceCredentials()
                        .getLoginKey(), responseTLV.getFirstChildElement(0x01), payload));
                return new ExtensionResponseFuture(mockedFuture, requestContext, credentials, pduFactory);
            }
        });
        return mockedExtenderService;
    }

    private DataHash calculateHash(byte[] key, TLVElement... elements) throws Exception {
        HashAlgorithm algorithm = HashAlgorithm.SHA2_256;
        return new DataHash(algorithm, Util.calculateHMAC(getContent(elements), key, algorithm.getName()));
    }

    private byte[] getContent(TLVElement[] elements) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (TLVElement element : elements) {
            out.write(element.getEncoded());
        }
        return out.toByteArray();
    }
}
