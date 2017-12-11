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
package com.guardtime.ksi.pdu.v1;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.GlobalTlvTypes;
import com.guardtime.ksi.tlv.TLVElement;

import java.util.List;

/**
 * Aggregation response payload.
 */
class AggregationResponsePayloadV1 extends PduResponsePayloadV1 implements AggregationResponse {

    public static final int ELEMENT_TYPE = 0x0202;
    private static final int ELEMENT_TYPE_REQUEST_ID = 0x1;
    private static final int ELEMENT_TYPE_ERROR = 0x4;
    private static final int ELEMENT_TYPE_ERROR_MESSAGE = 0x5;

    private Long requestId;
    private Long error;
    private String errorMsg;

    /**
     * Creates aggregation response from TLVTag.
     *
     * @param element
     *         TLV element.
     */
    public AggregationResponsePayloadV1(TLVElement element) throws KSIException {
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
                case GlobalTlvTypes.ELEMENT_TYPE_AGGREGATION_HASH_CHAIN:
                case GlobalTlvTypes.ELEMENT_TYPE_AGGREGATION_AUTHENTICATION_RECORD:
                case GlobalTlvTypes.ELEMENT_TYPE_CALENDAR_HASH_CHAIN:
                case GlobalTlvTypes.ELEMENT_TYPE_CALENDAR_AUTHENTICATION_RECORD:
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
     * @return Error code.
     */
    public Long getError() {
        return error;
    }

    /**
     * @return Error message.
     */
    public String getErrorMessage() {
        return errorMsg;
    }

    /**
     * @return Request ID.
     */
    public final Long getRequestId() {
        return requestId;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

    public TLVElement getPayload() {
        return getRootElement();
    }
}
