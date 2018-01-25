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
package com.guardtime.ksi.service.http.simple;

import com.guardtime.ksi.service.client.http.HttpProtocolException;
import com.guardtime.ksi.tlv.TLVElement;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;

import static org.mockito.Mockito.when;

public class SimpleHttpPostRequestFutureTest {

    @Test
    public void createSimpleHttpPostRequestFuture200() throws Exception {
        SimpleHttpPostRequestFuture future =
                new SimpleHttpPostRequestFuture(getHttpUrlConnection(200, "OK", new ByteArrayInputStream(new byte[] {0x0f, 33,
                        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})));

        TLVElement element = future.getResult();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        element.writeTo(out);
        Assert.assertEquals(out.toByteArray(), new byte[] {0x0f, 33, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});

    }

    @Test(expectedExceptions = HttpProtocolException.class, expectedExceptionsMessageRegExp = "\\(400\\):BAD REQUEST")
    public void createSimpleHttpPostRequestFuture400() throws Exception {
        SimpleHttpPostRequestFuture future =
                new SimpleHttpPostRequestFuture(
                        getHttpUrlConnection(400, "BAD REQUEST", new ByteArrayInputStream(new byte[] {1})));

        future.getResult();
    }

    @Test(expectedExceptions = HttpProtocolException.class, expectedExceptionsMessageRegExp = "\\(500\\):INTERNAL SERVER ERROR")
    public void createSimpleHttpPostRequestFuture500() throws Exception {
        SimpleHttpPostRequestFuture future =
                new SimpleHttpPostRequestFuture(getHttpUrlConnection(500, "INTERNAL SERVER ERROR", null));

        future.getResult();
    }

    private HttpURLConnection getHttpUrlConnection(int responseCode, String responseMessage, InputStream in) throws IOException {
        HttpURLConnection connection = Mockito.mock(HttpURLConnection.class);
        when(connection.getResponseCode()).thenReturn(responseCode);
        when(connection.getResponseMessage()).thenReturn(responseMessage);
        if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
            when(connection.getInputStream()).thenReturn(in);
        } else {
            when(connection.getErrorStream()).thenReturn(in);
        }
        return connection;
    }
}
