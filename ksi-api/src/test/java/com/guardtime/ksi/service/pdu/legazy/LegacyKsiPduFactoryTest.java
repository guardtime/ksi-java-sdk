package com.guardtime.ksi.service.pdu.legazy;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.service.pdu.KSIRequestContext;
import com.guardtime.ksi.service.pdu.PduIdentifiers;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.service.pdu.AggregationRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class LegacyKsiPduFactoryTest {

    private static final long DEFAULT_LEVEL = 0L;
    private LegacyKsiPduFactory pduFactory = new LegacyKsiPduFactory();
    private DataHash dataHash;
    private KSIRequestContext requestContext;

    @BeforeMethod
    public void setUp() throws Exception {
        this.dataHash = new DataHash(HashAlgorithm.SHA2_256, new byte[32]);
        this.requestContext = new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 42L, PduIdentifiers.getInstanceId(), PduIdentifiers.nextMessageId());
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "KsiRequestContext can not be null")
    public void testCreateAggregationRequestWithoutContext_ThrowsNullPointerException() throws Exception {
        pduFactory.createAggregationRequest(null, dataHash, DEFAULT_LEVEL);
    }

    @Test(expectedExceptions = NullPointerException.class, expectedExceptionsMessageRegExp = "DataHash can not be null")
    public void testCreateAggregationRequestWithoutDataHash_ThrowsNullPointerException() throws Exception {
        pduFactory.createAggregationRequest(requestContext, null, DEFAULT_LEVEL);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Level can not be negative")
    public void testCreateAggregationRequestWithNegativeLevel_ThrowsNullPointerException() throws Exception {
        pduFactory.createAggregationRequest(requestContext, dataHash, -42L);
    }

    @Test
    public void testCreateAggregationRequest_Ok() throws Exception {
        AggregationRequest request = pduFactory.createAggregationRequest(requestContext, dataHash, DEFAULT_LEVEL);
        Assert.assertNotNull(request);
    }

}
