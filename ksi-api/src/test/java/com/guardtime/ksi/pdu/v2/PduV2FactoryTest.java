package com.guardtime.ksi.pdu.v2;

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

public class PduV2FactoryTest {

    private static final long DEFAULT_LEVEL = 0L;
    private PduV2Factory pduFactory = new PduV2Factory();
    private DataHash dataHash;
    private KSIRequestContext requestContext;
    private KSIRequestContext extensionContext;

    @BeforeMethod
    public void setUp() throws Exception {
        this.dataHash = new DataHash(HashAlgorithm.SHA2_256, new byte[32]);
        this.requestContext = new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 42275443333883166L, 42L, 42L);
        this.extensionContext = new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 5546551786909961666L, 42L, 42L);
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

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Aggregation response request ID do not match. Sent .* received .*")
    public void testAggregationResponseContainsInvalidRequestId_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 1L, 42L, 42L), loadTlv("pdu/aggregation/aggregation-response-v2.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Invalid response message. Response message must contain at least one payload element")
    public void testAggregationResponseDoesNotContainResponseTlvTag_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(requestContext, loadTlv("pdu/aggregation/aggregation-response-v2-missing-payload.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Invalid KSI response. Error payload element is .* Error message from server: 'The request could not be authenticated'")
    public void testAggregationResponseContains03ErrorMessage_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(requestContext, loadTlv("pdu/aggregation/aggregation-response-v2-invalid-login-key.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Invalid aggregation response. Error code:.*, message: .*")
    public void testAggregationResponseContainsErrorMessageInside02Element_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 8530358545345979581L, 42L, 42L), loadTlv("pdu/aggregation/aggregation-response-v2-with-error.tlv"));
    }

    @Test(expectedExceptions = InvalidMessageAuthenticationCodeException.class, expectedExceptionsMessageRegExp = "Invalid MAC code. Expected.*")
    public void testExtensionResponseInvalidHMAC_ThrowsInvalidMessageAuthenticationCodeException() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v2-invalid-mac.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Extension response request ID do not match. Sent '5546551786909961666' received '4846851148188931472'")
    public void testExtensionRequestIdsMismatch() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v2.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Invalid KSI response. Error payload element is .* Error message from server: 'The request could not be authenticated'")
    public void testExtensionResponseContains03ErrorMessage_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readExtensionResponse(requestContext, loadTlv("pdu/extension/extension-response-v2-invalid-login-key.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Invalid extension response. Error code:.*, message: 'The request contained invalid payload'")
    public void testExtensionResponseContains02ErrorMessage_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v2-with-error.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "Invalid KSI response. Missing MAC and error payload.")
    public void testExtensionResponseWithoutMac_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readExtensionResponse(extensionContext, loadTlv("pdu/extension/extension-response-v2-missing-mac.tlv"));
    }

}
