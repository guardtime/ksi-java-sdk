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
package com.guardtime.ksi.service.aggregation;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.KSIResponsePayload;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.AggregationAuthenticationRecord;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.CalendarAuthenticationRecord;
import com.guardtime.ksi.unisignature.CalendarHashChain;

import java.util.List;

/**
 * Aggregation response payload.
 */
public class AggregationResponsePayload extends KSIResponsePayload {

    public static final int ELEMENT_TYPE = 0x0202;
    private static final int ELEMENT_TYPE_REQUEST_ID = 0x1;
    private static final int ELEMENT_TYPE_ERROR = 0x4;
    private static final int ELEMENT_TYPE_ERROR_MESSAGE = 0x5;

    private Long requestId;
    private Long error;
    private String errorMsg;

    /**
     * Create aggregation response from TLVTag.
     *
     * @param element
     *         TLV element
     */
    public AggregationResponsePayload(TLVElement element) throws KSIException {
        super(element);
        List<TLVElement> children = element.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_REQUEST_ID:
                    this.requestId = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_ERROR:
                    this.error = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_ERROR_MESSAGE:
                    this.errorMsg = readOnce(child).getDecodedString();
                    continue;
                case AggregationHashChain.ELEMENT_TYPE:
                case AggregationAuthenticationRecord.ELEMENT_TYPE:
                case CalendarHashChain.ELEMENT_TYPE:
                case CalendarAuthenticationRecord.ELEMENT_TYPE:
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (requestId == null) {
            throw new KSIProtocolException("Invalid KSI response. Aggregation response payload does not contain request id.");
        }
    }

    /**
     * @return error number
     */
    public Long getError() {
        return error;
    }

    /**
     * @return error message
     */
    public String getErrorMessage() {
        return errorMsg;
    }

    /**
     * @return request id
     */
    public final Long getRequestId() {
        return requestId;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }
}
