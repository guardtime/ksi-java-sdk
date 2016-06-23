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
package com.guardtime.ksi.service.client.http;

import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;

/**
 * Common HTTP request future class for all HTTP POST based requests.
 */
public abstract class HttpPostRequestFuture implements Future<TLVElement> {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpPostRequestFuture.class);

    private static final int AGGREGATION_PDU_TYPE = 0x200;
    private static final int EXTENSION_PDU_TYPE = 0x300;

    private static final int[] SUPPORTED_TLV_TYPES = new int[]{AGGREGATION_PDU_TYPE, EXTENSION_PDU_TYPE};

    /**
     * Validates HTTP response message.
     *
     * @param statusCode
     *         - HTTP status code
     * @param responseMessage
     *         - HTTP header response message
     * @param response
     *         - response input stream
     * @param contentType
     *         - response content type header
     * @throws HttpProtocolException
     *         will be thrown when KSI HTTP response is not valid
     */
    protected TLVElement parse(int statusCode, String responseMessage, InputStream response, String contentType) throws HttpProtocolException {
        try {
            TLVElement tlv = TLVElement.createFromBytes(Util.toByteArray(response));
            int tlvType = tlv.getType();
            for (int type : SUPPORTED_TLV_TYPES) {
                if (tlvType == type) {
                    return tlv;
                }
            }
        } catch (Exception e) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Invalid TLV response.", e);
            }
            throw new HttpProtocolException(statusCode, responseMessage);
        }
        LOGGER.error("Invalid KSI Protocol response. HTTP status code is {}, HTTP response message is {} and content type is {}", statusCode, responseMessage, contentType);
        throw new HttpProtocolException(statusCode, responseMessage);
    }

}
