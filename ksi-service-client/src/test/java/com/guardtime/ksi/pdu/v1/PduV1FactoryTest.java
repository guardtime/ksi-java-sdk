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
package com.guardtime.ksi.pdu.v1;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.exceptions.InvalidMessageAuthenticationCodeException;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;

public class PduV1FactoryTest {

    private static final long DEFAULT_LEVEL = 0L;
    public static final KSIServiceCredentials CREDENTIALS = new KSIServiceCredentials("anon", "anon");
    private KSIRequestContext extensionContext;
    private PduV1Factory pduFactory = new PduV1Factory();
    private DataHash dataHash;
    private KSIRequestContext requestContext;

    @BeforeMethod
    public void setUp() throws Exception {
        this.dataHash = new DataHash(HashAlgorithm.SHA2_256, new byte[32]);
        this.requestContext = new KSIRequestContext(42275443333883166L, 42L, 42L).getWithCredentials(CREDENTIALS);
        this.extensionContext = new KSIRequestContext(5546551786909961666L, 42L, 42L).getWithCredentials(CREDENTIALS);
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
        pduFactory.readAggregationResponse(requestContext, loadTlv("pdu/aggregation/aggregation-response-v1-invalid-mac.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*request IDs do not match, sent .* received .*")
    public void testAggregationResponseContainsInvalidRequestId_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(new KSIRequestContext(1L, 42L, 42L).getWithCredentials(CREDENTIALS), loadTlv("pdu/aggregation/aggregation-response-v1.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*Response message does not contain response payload element")
    public void testAggregationResponseDoesNotContainResponseTlvTag_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(requestContext, loadTlv("pdu/aggregation/aggregation-response-v1-missing-response-tag.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(5\\):Response error 5: Invalid request format")
    public void testAggregationResponseContains203ErrorMessage_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(requestContext, loadTlv("pdu/aggregation/aggregation-response-v1-203-error.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(769\\):Server error")
    public void testAggregationResponseContainsErrorMessageInside202TLVMessage_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(requestContext, loadTlv("pdu/aggregation/aggregation-response-v1-202-error.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Received PDU v2 response to PDU v1 request. Configure the SDK to use PDU v2 format for the given Aggregator")
    public void testReadV2AggregationResponse() throws Exception {
        pduFactory.readAggregationResponse(extensionContext, loadTlv("pdu/aggregation/aggregation-response-v2-with-error.tlv"));
    }

    @Test(expectedExceptions = InvalidMessageAuthenticationCodeException.class, expectedExceptionsMessageRegExp = "Invalid MAC code. Expected.*")
    public void testExtensionResponseInvalidHMAC_ThrowsInvalidMessageAuthenticationCodeException() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v1-invalid-hmac.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*request IDs do not match, sent \\'[0-9]+\\' received \\'4321\\'")
    public void testExtensionRequestIdsMismatch() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v1-ok-request-id-4321.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*Response message does not contain response payload element")
    public void testExtensionResponseEmpty() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v1-missing-response-payload.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(404\\):Not found")
    public void testExtensionRequest404ErrorWithResponse() throws Exception {
        pduFactory.readExtensionResponse(new KSIRequestContext(4321L, 42L, 42L).getWithCredentials(CREDENTIALS), loadTlv("pdu/extension/extension-response-v1-with-error-payload.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(404\\):Response error 404: Not found")
    public void testExtensionResponseWithError() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v1-header-error.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Received PDU v2 response to PDU v1 request. Configure the SDK to use PDU v2 format for the given Extender")
    public void testReadV2ExtensionResponse() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v2-with-error.tlv"));
    }

}
