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
package com.guardtime.ksi.service.http.simple;

import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.http.HttpGetRequestFuture;
import com.guardtime.ksi.util.Util;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.nio.ByteBuffer;

/**
 * JDK specific class for all HTTP GET based requests.
 */
public class SimpleHttpGetRequestFuture extends HttpGetRequestFuture {

    private int responseCode;
    private String responseMessage;
    private byte[] response;

    public SimpleHttpGetRequestFuture(HttpURLConnection connection) throws IOException {
        this.responseCode = connection.getResponseCode();
        this.responseMessage = connection.getResponseMessage();
        if (connection.getResponseCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
            InputStream inputStream = null;
            try {
                inputStream = connection.getInputStream();
                this.response = Util.toByteArray(inputStream);
            } finally {
                Util.closeQuietly(inputStream);
            }
        }
    }

    public boolean isFinished() {
        return true;
    }

    public ByteBuffer getResult() throws KSIClientException, KSIProtocolException {
        validateHttpResponse(responseCode, responseMessage);
        return ByteBuffer.wrap(response);
    }

}
