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
package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.exceptions.InvalidMessageAuthenticationCodeException;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;

public class PduV2FactoryTest {

    private static final long DEFAULT_LEVEL = 0L;
    public static final KSIServiceCredentials CREDENTIALS = new KSIServiceCredentials("anon", "anon");
    private PduV2Factory pduFactory = new PduV2Factory();
    private DataHash dataHash;
    private KSIRequestContext requestContext;
    private KSIRequestContext extensionContext;

    @BeforeMethod
    public void setUp() throws Exception {
        this.dataHash = new DataHash(HashAlgorithm.SHA2_256, new byte[32]);
        this.requestContext = new KSIRequestContext(CREDENTIALS, 42275443333883166L, 42L, 42L);
        this.extensionContext = new KSIRequestContext(CREDENTIALS, 5546551786909961666L, 42L, 42L);
    }

    @Test
    public void testCreateAggregationRequest_Ok() throws Exception {
        AggregationRequest request = pduFactory.createAggregationRequest(requestContext, dataHash, DEFAULT_LEVEL);
        Assert.assertNotNull(request);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "KsiRequestContext can not be null")
    public void testCreateAggregationRequestWithoutContext_ThrowsNullPointerException() throws Exception {
        pduFactory.createAggregationRequest(null, dataHash, DEFAULT_LEVEL);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "DataHash can not be null")
    public void testCreateAggregationRequestWithoutDataHash_ThrowsNullPointerException() throws Exception {
        pduFactory.createAggregationRequest(requestContext, null, DEFAULT_LEVEL);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Only non-negative integer values are allowed")
    public void testCreateAggregationRequestWithNegativeLevel_ThrowsNullPointerException() throws Exception {
        pduFactory.createAggregationRequest(requestContext, dataHash, -42L);
    }

    @Test(expectedExceptions = InvalidMessageAuthenticationCodeException.class, expectedExceptionsMessageRegExp = "Invalid MAC code. Expected.*")
    public void testAggregationResponseContainsInvalidMac_ThrowsInvalidMessageAuthenticationCodeException() throws Exception {
        pduFactory.readAggregationResponse(requestContext, loadTlv("pdu/aggregation/aggregation-response-v2-invalid-mac.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Aggregation response payload with requestId 1 wasn't found")
    public void testAggregationResponseContainsInvalidRequestId_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 1L, 42L, 42L), loadTlv("pdu/aggregation/aggregation-response-v2.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Invalid response message. Response message must contain at least one payload element")
    public void testAggregationResponseDoesNotContainResponseTlvTag_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(requestContext, loadTlv("pdu/aggregation/aggregation-response-v2-missing-payload.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Error was returned by server. Error status is .* Error message from server: 'The request could not be authenticated'")
    public void testAggregationResponseContains03ErrorMessage_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(requestContext, loadTlv("pdu/aggregation/aggregation-response-v2-invalid-login-key.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Error was returned by server. Error status is .* Error message from server: .*")
    public void testAggregationResponseContainsErrorMessageInside02Element_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 8530358545345979581L, 42L, 42L), loadTlv("pdu/aggregation/aggregation-response-v2-with-error.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Aggregator")
    public void testReadV2AggregationResponse() throws Exception {
        pduFactory.readAggregationResponse(extensionContext, loadTlv("aggregation-203-error.tlv"));
    }

    @Test(expectedExceptions = InvalidMessageAuthenticationCodeException.class, expectedExceptionsMessageRegExp = "Invalid MAC code. Expected.*")
    public void testExtensionResponseInvalidHMAC_ThrowsInvalidMessageAuthenticationCodeException() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v2-invalid-mac.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Extension response payload with requestId 5546551786909961666 wasn't found")
    public void testExtensionRequestIdsMismatch() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v2.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Error was returned by server. Error status is .* Error message from server: 'The request could not be authenticated'")
    public void testExtensionResponseContains03ErrorMessage_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readExtensionResponse(requestContext, loadTlv("pdu/extension/extension-response-v2-invalid-login-key.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Error was returned by server. Error status is .* Error message from server: 'The request contained invalid payload'")
    public void testExtensionResponseContains02ErrorMessage_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readExtensionResponse(new KSIRequestContext(CREDENTIALS, 98765L, 42L, 42L), loadTlv("pdu/extension/extension-response-v2-with-error.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Invalid KSI response. Missing MAC.")
    public void testExtensionResponseWithoutMac_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v2-missing-mac.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Extender")
    public void testReadV2ExtensionResponse() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v1-ok-request-id-4321.tlv"));
    }

    @Test
    public void testReadV2ExtensionResponseContainingUnknownNonCriticalElement() throws Exception {
        ExtensionResponse response = pduFactory.readExtensionResponse(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 8396215651691691389L, 42L, 42L), loadTlv("pdu/extension/extension-response-v2-unknown-non-critical-element.tlv"));
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getCalendarHashChain());
    }

}
