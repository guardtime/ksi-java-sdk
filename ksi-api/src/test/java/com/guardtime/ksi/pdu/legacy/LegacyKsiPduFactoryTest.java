package com.guardtime.ksi.pdu.legacy;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduIdentifiers;
import com.guardtime.ksi.pdu.exceptions.InvalidMessageAuthenticationCodeException;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.pdu.AggregationRequest;

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.InputStream;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.TestUtil.loadSignature;

public class LegacyKsiPduFactoryTest {

    private static final long DEFAULT_LEVEL = 0L;
    private LegacyKsiPduFactory pduFactory = new LegacyKsiPduFactory();
    private DataHash dataHash;
    private KSIRequestContext requestContext;

    @BeforeMethod
    public void setUp() throws Exception {
        this.dataHash = new DataHash(HashAlgorithm.SHA2_256, new byte[32]);
        this.requestContext = new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 42275443333883166L, 42L, 42L);
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
        pduFactory.readAggregationResponse(requestContext, loadTlv("aggregation-response-invalid-mac.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*request IDs do not match, sent .* received .*")
    public void testAggregationResponseContainsInvalidRequestId_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 1L, 42L, 42L), loadTlv("aggregation-response.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*Response message does not contain response payload element")
    public void testAggregationResponseDoesNotContainResponseTlvTag_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(requestContext, loadTlv("aggregation-response-missing-response-tag.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(5\\):Response error 5: Invalid request format")
    public void testAggregationResponseContains203ErrorMessage_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(requestContext, loadTlv("aggregation-203-error.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(769\\):Server error")
    public void testAggregationResponseContainsErrorMessageInside202TLVMessage_ThrowsKSIProtocolException() throws Exception {
        pduFactory.readAggregationResponse(requestContext, loadTlv("aggregation-202-error.tlv"));
    }

    // TODO move the message
    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*Can't parse response message")
    public void testExtensionResponseFormatException() throws Exception {
//        Mockito.when(mockedResponse.getResult()).thenReturn();
//        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
//        Mockito.when(mockedIdentifierProvider.nextRequestId()).thenReturn(5546551786909961666L);
//
//        ksi.extend(loadSignature("ok-sig-2014-04-30.1.ksig"));
        pduFactory.readExtensionResponse(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 5546551786909961666L, 42L, 42L), loadTlv("extension/extension-response-invalid.tlv"));
    }
    //TODO refactor context
    @Test(expectedExceptions = InvalidMessageAuthenticationCodeException.class, expectedExceptionsMessageRegExp = "Invalid MAC code. Expected.*")
    public void testExtensionResponseInvalidHMAC_ThrowsInvalidMessageAuthenticationCodeException() throws Exception {
        pduFactory.readExtensionResponse(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 5546551786909961666L, 42L, 42L), loadTlv("extension/extension-response-invalid-hmac.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*request IDs do not match, sent \\'[0-9]+\\' received \\'4321\\'")
    public void testExtensionRequestIdsMismatch() throws Exception {
        pduFactory.readExtensionResponse(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 5546551786909961666L, 42L, 42L), loadTlv("extension/extension-response-ok-request-id-4321.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*Response message does not contain response payload element")
    public void testExtensionResponseEmpty() throws Exception {
        pduFactory.readExtensionResponse(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 5546551786909961666L, 42L, 42L), loadTlv("extension/extension-response-missing-response-payload.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(404\\):Not found")
    public void testExtensionRequest404ErrorWithResponse() throws Exception {
        pduFactory.readExtensionResponse(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 4321L, 42L, 42L), loadTlv("extension/extension-response-with-error-payload.tlv"));
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(404\\):Response error 404: Not found")
    public void testExtensionResponseWithError() throws Exception {
        pduFactory.readExtensionResponse(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 5546551786909961666L, 42L, 42L), loadTlv("extension/extension-error-response-with-header.tlv"));
    }

}
