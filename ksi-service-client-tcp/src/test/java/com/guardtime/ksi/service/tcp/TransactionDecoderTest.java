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

package com.guardtime.ksi.service.tcp;

import com.guardtime.ksi.CommonTestUtil;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.mockito.Mockito.times;

public class TransactionDecoderTest {

    private static final String TCP_RESPONSE_MULTIPLE_RESPONSES = "tcp-response-multiple-responses";
    private static final String TCP_RESPONSE_MISSING_DATA = "tcp-response-missing-data";
    private static final String TCP_RESPONSE_MULTIPLE_RESPONSES_MISSING_LAST_TLV_LENGTH = "tcp-response-multiple-responses-missing-last-tlv-length";
    private static final String TCP_RESPONSE_MULTIPLE_WITH_INCOMPLETE_HEADER = "tcp-response-multiple-with-incomplete-header";
    private final TransactionDecoder decoder = new TransactionDecoder();
    @Mock
    private ProtocolDecoderOutput mockedOutput;


    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testDecodeResponseContainingEmptyArray() throws Exception {
        boolean result = decoder.doDecode(null, IoBuffer.wrap(new byte[0]), mockedOutput);
        Assert.assertFalse(result);
    }

    @Test
    public void testDecodeResponseContainingIncompleteTypeHeader() throws Exception {
        boolean result = decoder.doDecode(null, IoBuffer.wrap(new byte[]{(byte) 0x82}), mockedOutput);
        Assert.assertFalse(result);
    }

    @Test
    public void testDecodeResponseContainingIncompleteTlv16Length() throws Exception {
        boolean result = decoder.doDecode(null, IoBuffer.wrap(new byte[]{(byte) 0x82, 0x00, 0x07}), mockedOutput);
        Assert.assertFalse(result);
    }

    @Test
    public void testDecodeMultipleResponses() throws Exception {
        byte[] response = CommonTestUtil.loadBytes(TCP_RESPONSE_MULTIPLE_RESPONSES);
        boolean result = decoder.doDecode(null, IoBuffer.wrap(response), mockedOutput);
        Assert.assertTrue(result);
        Mockito.verify(mockedOutput, times(16)).write(Mockito.any());
    }

    @Test
    public void testDecodeResponseWithMissingData() throws Exception {
        byte[] response = CommonTestUtil.loadBytes(TCP_RESPONSE_MISSING_DATA);
        boolean result = decoder.doDecode(null, IoBuffer.wrap(response), mockedOutput);
        Assert.assertFalse(result);
    }

    @Test
    public void testDecodeMultipleResponsesWithMissingTlvLength() throws Exception {
        byte[] response = CommonTestUtil.loadBytes(TCP_RESPONSE_MULTIPLE_RESPONSES_MISSING_LAST_TLV_LENGTH);
        boolean result = decoder.doDecode(null, IoBuffer.wrap(response), mockedOutput);
        Assert.assertFalse(result);
        Mockito.verify(mockedOutput, times(16)).write(Mockito.any());
    }

    @Test
    public void testDecodeMultipleResponsesWithIncompleteHeader() throws Exception {
        byte[] response = CommonTestUtil.loadBytes(TCP_RESPONSE_MULTIPLE_WITH_INCOMPLETE_HEADER);
        boolean result = decoder.doDecode(null, IoBuffer.wrap(response), mockedOutput);
        Assert.assertFalse(result);
        Mockito.verify(mockedOutput, times(16)).write(Mockito.any());
    }
    
}
