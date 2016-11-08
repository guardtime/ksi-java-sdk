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
package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.GlobalTlvTypes;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.List;

class AggregationResponsePayloadV2 extends TLVStructure implements AggregationResponse {

    static final int ELEMENT_TYPE = 0x02;

    private static final int ELEMENT_TYPE_REQUEST_ID = 0x01;
    private static final int ELEMENT_TYPE_ERROR = 0x04;
    private static final int ELEMENT_TYPE_ERROR_MESSAGE = 0x05;

    private Long requestId;
    private Long status;
    private String errorMessage;

    public AggregationResponsePayloadV2(TLVElement element) throws KSIException {
        super(element);
        List<TLVElement> children = element.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_REQUEST_ID:
                    this.requestId = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_ERROR:
                    this.status = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_ERROR_MESSAGE:
                    this.errorMessage = readOnce(child).getDecodedString();
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
        if (status != 0) {
            throw new KSIProtocolException("Error was returned by server. Error status is 0x" + Long.toHexString(status)+ ". Error message from server: '" + errorMessage + "'");
        }
    }

    /**
     * @return error number
     */
    public Long getStatus() {
        return status;
    }

    /**
     * returns an error message
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Returns the request identifier
     */
    public final Long getRequestId() {
        return requestId;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

    public TLVElement getPayload() {
        return this.getRootElement();
    }
}
