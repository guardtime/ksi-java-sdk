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
package com.guardtime.ksi.service;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.InputStream;

import static com.guardtime.ksi.CommonTestUtil.loadTlv;

public class AggregationServiceTest extends AbstractCommonServiceTest {

    @Test
    public void testCreateSignature_Ok() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("aggregation-response.tlv"));
        Mockito.when(mockedSigningClient.sign(Mockito.any(InputStream.class))).thenReturn(mockedResponse);

        CreateSignatureFuture response = ksiService.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getResult());
    }

    @Test(expectedExceptions = InvalidMessageAuthenticationCodeException.class, expectedExceptionsMessageRegExp = "Invalid MAC code. Expected.*")
    public void testResponseContainsInvalidMac_ThrowsInvalidMessageAuthenticationCodeException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("aggregation-response-invalid-mac.tlv"));
        Mockito.when(mockedSigningClient.sign(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        CreateSignatureFuture future = ksiService.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        future.getResult();
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*request IDs do not match, sent .* received .*")
    public void testResponseContainsInvalidRequestId_ThrowsKSIProtocolException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("aggregation-response.tlv"));
        Mockito.when(mockedSigningClient.sign(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        Mockito.when(ksiService.generateRequestId()).thenReturn(42275443333883167L);
        CreateSignatureFuture future = ksiService.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        future.getResult();
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*Response message does not contain response payload element")
    public void testResponseDoesNotContainResponseTlvTag_ThrowsKSIProtocolException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("aggregation-response-missing-response-tag.tlv"));
        Mockito.when(mockedSigningClient.sign(Mockito.any(InputStream.class))).thenReturn(mockedResponse);

        CreateSignatureFuture future = ksiService.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        future.getResult();
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(5\\):Response error 5: Invalid request format")
    public void testResponseContains203ErrorMessage_ThrowsKSIProtocolException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("aggregation-203-error.tlv"));
        Mockito.when(mockedSigningClient.sign(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        CreateSignatureFuture future = ksiService.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        future.getResult();
    }

    @Test(expectedExceptions = KSIProtocolException.class, expectedExceptionsMessageRegExp = ".*\\(769\\):Server error")
    public void testResponseContainsErrorMessageInside202TLVMessage_ThrowsKSIProtocolException() throws Exception {
        Mockito.when(mockedResponse.getResult()).thenReturn(loadTlv("aggregation-202-error.tlv"));
        Mockito.when(mockedSigningClient.sign(Mockito.any(InputStream.class))).thenReturn(mockedResponse);
        CreateSignatureFuture future = ksiService.sign(new DataHash(HashAlgorithm.SHA2_256, new byte[32]));
        future.getResult();
    }

}
