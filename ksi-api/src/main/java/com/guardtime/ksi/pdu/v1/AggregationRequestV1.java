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
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduMessageHeader;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;

/**
 * Outgoing aggregation message TLV object.
 */
class AggregationRequestV1 extends AbstractKSIRequest<AggregationRequestPayloadV1> implements AggregationRequest {

    private static final int ELEMENT_TYPE = 0x200;

    public AggregationRequestV1(PduMessageHeader header, AggregationRequestPayloadV1 payload, KSIRequestContext requestContext) throws KSIException {
        super(header, payload, requestContext.getLoginKey());
    }

    public AggregationRequestV1(TLVElement element, KSIRequestContext requestContext) throws KSIException {
        super(element, requestContext.getLoginKey());
    }

    @Override
    protected AggregationRequestPayloadV1 readPayload(TLVElement element) throws KSIException {
        return new AggregationRequestPayloadV1(element);
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

    public byte[] toByteArray() {
        try {
            return getRootElement().getEncoded();
        } catch (TLVParserException e) {
            throw new IllegalArgumentException("Invalid aggregation request state");
        }
    }

}
