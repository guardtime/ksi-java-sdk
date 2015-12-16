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
package com.guardtime.ksi.service;

import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.util.Util;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.InputStream;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;
import static com.guardtime.ksi.TestUtil.load;
import static com.guardtime.ksi.TestUtil.loadSignature;

public class ExtensionServiceRequestTest extends AbstractCommonServiceTest {

    @Test
    public void testNormalOperations_Ok() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension-response-sig-2014-04-30.1.ksig"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(ksiService.generateRandomId()).thenReturn(5546551786909961666L);

        ExtensionRequestFuture response = ksiService.extend(loadSignature("ok-sig-2014-04-30.1.ksig").getAggregationTime(), null);
        CalendarHashChain result = response.getResult();
        Assert.assertNotNull(result);
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*Can't parse response message")
    public void testResponseFormatException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension/extension-response-invalid.tlv"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(ksiService.generateRandomId()).thenReturn(5546551786909961666L);

        ExtensionRequestFuture response = ksiService.extend(loadSignature("ok-sig-2014-04-30.1.ksig").getAggregationTime(), null);
        response.getResult();
    }

    @Test(expectedExceptions = InvalidMessageAuthenticationCodeException.class, expectedExceptionsMessageRegExp = "Invalid MAC code. Expected.*")
    public void testResponseInvalidHMAC_ThrowsInvalidMessageAuthenticationCodeException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension/extension-response-invalid-hmac.tlv"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(ksiService.generateRandomId()).thenReturn(5546551786909961666L);

        ExtensionRequestFuture response = ksiService.extend(loadSignature("ok-sig-2014-04-30.1.ksig").getAggregationTime(), null);
        response.getResult();
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*request IDs do not match, sent \\'[0-9]+\\' received \\'4321\\'")
    public void testRequestIdsMismatch() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension/extension-response-ok-request-id-4321.tlv"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(ksiService.generateRandomId()).thenReturn(5546551786909961666L);

        ExtensionRequestFuture response = ksiService.extend(loadSignature("ok-sig-2014-04-30.1.ksig").getAggregationTime(), null);
        response.getResult();
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*Response message does not contain response payload element")
    public void testRequestResponseEmpty() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension/extension-response-missing-response-payload.tlv"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(ksiService.generateRandomId()).thenReturn(5546551786909961666L);

        ExtensionRequestFuture response = ksiService.extend(loadSignature("ok-sig-2014-04-30.1.ksig").getAggregationTime(), null);
        response.getResult();
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(404\\):Not found")
    public void testRequest404ErrorWithResponse() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension/extension-response-with-error-payload.tlv"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(ksiService.generateRandomId()).thenReturn(4321L);

        ExtensionRequestFuture response = ksiService.extend(loadSignature("ok-sig-2014-04-30.1.ksig").getAggregationTime(), null);
        response.getResult();
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(404\\):Response error 404: Not found")
    public void testResponseWithError() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("extension/extension-error-response-with-header.tlv"));
        Mockito.when(mockedExtenderClient.extend(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(ksiService.generateRandomId()).thenReturn(5546551786909961666L);

        ExtensionRequestFuture response = ksiService.extend(loadSignature("ok-sig-2014-04-30.1.ksig").getAggregationTime(), null);
        response.getResult();
    }

}
