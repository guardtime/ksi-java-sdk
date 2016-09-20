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
package com.guardtime.ksi.service.aggregation;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.service.KSIMessageHeader;

import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.util.Util;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;

public class AggregationRequestTest {

    public static final byte[] LOGIN_KEY = TestUtil.CREDENTIALS_ANONYMOUS.getLoginKey();
    private KSIMessageHeader header;

    @BeforeMethod
    public void setUp() throws Exception {
        this.header = new KSIMessageHeader(TestUtil.CREDENTIALS_ANONYMOUS.getLoginId());
    }

    @Test
    public void testCreateAggregationRequestInstance_Ok() throws Exception {
        AggregationRequest aggregationRequest = new AggregationRequest(header, null, LOGIN_KEY);
        Assert.assertNotNull(aggregationRequest.getHeader());
        Assert.assertEquals(aggregationRequest.getHeader().getLoginId(), TestUtil.CREDENTIALS_ANONYMOUS.getLoginId());
        Assert.assertNull(aggregationRequest.getHeader().getInstanceId());
        Assert.assertNull(aggregationRequest.getHeader().getMessageId());
        Assert.assertNotNull(aggregationRequest.getMac());
        Assert.assertNull(aggregationRequest.getRequestPayload());
    }

    @Test
    public void testEncodeAggregationRequestWithoutPayload_Ok() throws Exception {
        AggregationRequest aggregationRequest = new AggregationRequest(header, null, LOGIN_KEY);
        AggregationRequest request = load(encode(aggregationRequest));
        Assert.assertEquals(aggregationRequest.getRequestPayload(), request.getRequestPayload());
        Assert.assertEquals(aggregationRequest.getHeader(), request.getHeader());
    }

    @Test
    public void testEncodeAggregationRequestWithPayload_Ok() throws Exception {
        AggregationRequestPayload payload = new AggregationRequestPayload(new DataHash(HashAlgorithm.SHA2_256, new byte[32]), Util.nextLong());
        AggregationRequest aggregationRequest = new AggregationRequest(header, payload, LOGIN_KEY);
        AggregationRequest request = load(encode(aggregationRequest));
        Assert.assertEquals(aggregationRequest.getRequestPayload().getRequestHash(), request.getRequestPayload().getRequestHash());
    }

    @Test
    public void testEncodeAggregationRequestWithoutPayloadDataHash_Ok() throws Exception {
        AggregationRequestPayload payload = new AggregationRequestPayload(Util.nextLong());
        AggregationRequest aggregationRequest = new AggregationRequest(header, payload, LOGIN_KEY);
        AggregationRequest request = load(encode(aggregationRequest));
        Assert.assertEquals(aggregationRequest.getRequestPayload().getRequestHash(), request.getRequestPayload().getRequestHash());
        Assert.assertEquals(request.getRequestPayload().getRequestHash(), null);
    }

    private byte[] encode(TLVStructure element) throws KSIException {
        return element.getRootElement().getEncoded();
    }

    private AggregationRequest load(byte[] data) throws Exception {
        return new AggregationRequest(loadTlv(data), LOGIN_KEY);
    }

}
