/*
 * Copyright 2013-2015 Guardtime, Inc.
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
package com.guardtime.ksi.service.extension;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.KSIRequestContext;
import com.guardtime.ksi.tlv.TLVInputStream;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.util.Util;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.util.Date;

public class ExtensionRequestTest {

    private static final KSIRequestContext CONTEXT = new KSIRequestContext(TestUtil.CREDENTIALS_ANONYMOUS, 1234L);

    @Test
    public void testCreateExtensionRequestInstance_Ok() throws Exception {
        ExtensionRequest aggregationRequest = new ExtensionRequest((ExtensionRequestPayload) null, CONTEXT);
        Assert.assertNotNull(aggregationRequest.getHeader());
        Assert.assertEquals(aggregationRequest.getHeader().getLoginId(), TestUtil.CREDENTIALS_ANONYMOUS.getLoginId());
        Assert.assertNull(aggregationRequest.getHeader().getInstanceId());
        Assert.assertNull(aggregationRequest.getHeader().getMessageId());
        Assert.assertNotNull(aggregationRequest.getMac());
        Assert.assertNull(aggregationRequest.getRequestPayload());
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*Invalid KSI request. Extension request payload is missing")
    public void testEncodeExtensionRequestWithoutPayload_Ok() throws Exception {
        ExtensionRequest aggregationRequest = new ExtensionRequest((ExtensionRequestPayload) null, CONTEXT);
        byte[] bytes = encode(aggregationRequest);
        TLVInputStream tlvInput = new TLVInputStream(new ByteArrayInputStream(bytes));
        try {
            new ExtensionRequest(tlvInput.readElement(), CONTEXT);
        } finally {
            tlvInput.close();
        }
    }

    @Test
    public void testEncodeExtensionRequestWithAggregationTime_Ok() throws Exception {
        ExtensionRequestPayload payload = new ExtensionRequestPayload(new Date(), Util.nextLong());
        ExtensionRequest aggregationRequest = new ExtensionRequest(payload, CONTEXT);
        byte[] bytes = encode(aggregationRequest);
        TLVInputStream tlvInput = new TLVInputStream(new ByteArrayInputStream(bytes));
        ExtensionRequest request = new ExtensionRequest(tlvInput.readElement(), CONTEXT);
        tlvInput.close();
        Assert.assertEquals(aggregationRequest.getRequestPayload().getRequestId(), request.getRequestPayload().getRequestId());
    }

    @Test
    public void testEncodeExtensionRequestWithPublicationTime_Ok() throws Exception {
        ExtensionRequestPayload payload = new ExtensionRequestPayload(new Date(), new Date(), Util.nextLong());
        ExtensionRequest aggregationRequest = new ExtensionRequest(payload, CONTEXT);
        byte[] bytes = encode(aggregationRequest);
        TLVInputStream tlvInput = new TLVInputStream(new ByteArrayInputStream(bytes));
        ExtensionRequest request = new ExtensionRequest(tlvInput.readElement(), CONTEXT);
        tlvInput.close();
        Assert.assertEquals(aggregationRequest.getRequestPayload().getRequestId(), request.getRequestPayload().getRequestId());
        Assert.assertEquals(aggregationRequest.getRequestPayload().getAggregationTime().getTime() / 1000, request.getRequestPayload().getAggregationTime().getTime() / 1000);
        Assert.assertEquals(aggregationRequest.getRequestPayload().getPublicationTime().getTime() / 1000, request.getRequestPayload().getPublicationTime().getTime() / 1000);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. AggregationTime is null.")
    public void testEncodeExtensionRequestWithoutAggregationTime_ThrowsIllegalArgumentException() throws Exception {
        ExtensionRequestPayload payload = new ExtensionRequestPayload((Date) null, Util.nextLong());
        ExtensionRequest aggregationRequest = new ExtensionRequest(payload, CONTEXT);
        byte[] bytes = encode(aggregationRequest);
        TLVInputStream tlvInput = new TLVInputStream(new ByteArrayInputStream(bytes));
        ExtensionRequest request = new ExtensionRequest(tlvInput.readElement(), CONTEXT);
        tlvInput.close();
        Assert.assertEquals(aggregationRequest.getRequestPayload().getRequestId(), request.getRequestPayload().getRequestId());
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = "There is no suitable publication yet")
    public void testEncodeExtensionRequestPublicationTimeAfterAggregationTime_Ok() throws Exception {
        Date currentDate = new Date();
        ExtensionRequestPayload payload = new ExtensionRequestPayload(currentDate, new Date(currentDate.getTime() - 1000), Util.nextLong());
        ExtensionRequest aggregationRequest = new ExtensionRequest(payload, CONTEXT);
        byte[] bytes = encode(aggregationRequest);
        TLVInputStream tlvInput = new TLVInputStream(new ByteArrayInputStream(bytes));
        ExtensionRequest request = new ExtensionRequest(tlvInput.readElement(), CONTEXT);
        tlvInput.close();
        Assert.assertEquals(aggregationRequest.getRequestPayload().getRequestId(), request.getRequestPayload().getRequestId());
    }

    private byte[] encode(TLVStructure element) throws KSIException {
        return element.getRootElement().getEncoded();
    }
}
