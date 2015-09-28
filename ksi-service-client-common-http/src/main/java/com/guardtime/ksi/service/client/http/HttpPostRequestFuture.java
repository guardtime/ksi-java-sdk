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
package com.guardtime.ksi.service.client.http;

import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.tlv.TLVElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;

import static com.guardtime.ksi.service.client.http.AbstractHttpClient.HEADER_APPLICATION_KSI_RESPONSE;

/**
 * Common HTTP request future class for all HTTP POST based requests.
 */
public abstract class HttpPostRequestFuture implements Future<TLVElement> {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpPostRequestFuture.class);

    /**
     * Validates HTTP response message.
     *
     * @param statusCode
     *         - HTTP status code
     * @param responseMessage
     *         - HTTP header response message
     * @param responseInputStream
     *         - response input stream
     * @param contentType
     *         - response content type header
     * @throws IOException
     *         - will be thrown when I/O exception occurs
     * @throws HTTPServiceException
     *         will be thrown when HTTP status code is not 200 and response doesn't include data or HTTP status code is
     *         not 200 and response content type isn't "application/ksi-response"
     */
    protected void validateHttpResponse(int statusCode, String responseMessage, InputStream responseInputStream, String contentType) throws IOException,
            HTTPServiceException {
        if (statusCode != HttpURLConnection.HTTP_OK && (responseInputStream.available() == 0 || !HEADER_APPLICATION_KSI_RESPONSE.equals(contentType))) {
            LOGGER.error("KSI Protocol request failed. HTTP status code is {}, HTTP response message is {} and content type is {}", statusCode, responseMessage, contentType);
            throw new HTTPServiceException(statusCode, responseMessage);
        }
    }

}
