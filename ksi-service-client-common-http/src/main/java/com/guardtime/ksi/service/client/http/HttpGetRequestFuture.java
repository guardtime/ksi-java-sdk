/*
 * Copyright 2013-2017 Guardtime, Inc.
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
package com.guardtime.ksi.service.client.http;

import com.guardtime.ksi.service.Future;

import java.net.HttpURLConnection;
import java.nio.ByteBuffer;

/**
 * Common HTTP request future class for all HTTP GET based requests.
 */
public abstract class HttpGetRequestFuture implements Future<ByteBuffer> {

    /**
     * Validates HTTP response message.
     *
     * @param statusCode
     *         HTTP status code.
     * @param responseMessage
     *         HTTP header response message.
     * @throws HttpProtocolException
     *         will be thrown when HTTP status code is not 200 and response doesn't include data,
     *         or HTTP status code is not 200 and response content type isn't
     *         "application/ksi-response".
     */
    protected void validateHttpResponse(int statusCode, String responseMessage) throws HttpProtocolException {
        if (statusCode != HttpURLConnection.HTTP_OK) {
            throw new HttpProtocolException(statusCode, responseMessage);
        }
    }

}
