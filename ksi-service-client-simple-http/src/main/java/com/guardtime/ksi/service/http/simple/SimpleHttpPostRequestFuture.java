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
package com.guardtime.ksi.service.http.simple;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.client.http.AbstractHttpClient;
import com.guardtime.ksi.service.client.http.HttpPostRequestFuture;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;

/**
 * Simple HTTP response future.
 */
public class SimpleHttpPostRequestFuture extends HttpPostRequestFuture {

    private int responseCode;
    private String responseContentType;
    private String responseMessage;
    private byte[] response;

    public SimpleHttpPostRequestFuture(HttpURLConnection connection) throws IOException {
        this.responseCode = connection.getResponseCode();
        this.responseContentType = connection.getHeaderField(AbstractHttpClient.HEADER_NAME_CONTENT_TYPE);
        this.responseMessage = connection.getResponseMessage();
        InputStream input = null;
        try {
            if (connection.getResponseCode() >= HttpURLConnection.HTTP_BAD_REQUEST) {
                input = connection.getErrorStream();
                if (input != null) {
                    this.response = Util.toByteArray(input);
                }
            } else {
                input = connection.getInputStream();
                this.response = Util.toByteArray(input);
            }
        } finally {
            Util.closeQuietly(input);
        }
    }

    public boolean isFinished() {
        return true;
    }

    public TLVElement getResult() throws KSIException {
        return parse(responseCode, responseMessage, new ByteArrayInputStream(response), responseContentType);
    }

}
