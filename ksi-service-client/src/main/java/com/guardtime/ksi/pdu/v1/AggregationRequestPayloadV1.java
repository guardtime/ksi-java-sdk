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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.List;

/**
 * Aggregation request payload.
 */
class AggregationRequestPayloadV1 extends TLVStructure {

    public static final int ELEMENT_TYPE = 0x0201;

    public static final int ELEMENT_TYPE_REQUEST_ID = 0x01;
    public static final int ELEMENT_TYPE_REQUEST_HASH = 0x02;
    public static final int ELEMENT_TYPE_LEVEL = 0x03;
    public static final int ELEMENT_TYPE_CONFIG = 0x10;

    private long level = 0L;
    private Long requestId;
    private DataHash requestHash;

    public AggregationRequestPayloadV1(Long requestId) throws KSIException {
        this.requestId = requestId;
        this.rootElement = new TLVElement(false, false, ELEMENT_TYPE);
        TLVElement requestIdElement = new TLVElement(false, false, ELEMENT_TYPE_REQUEST_ID);
        requestIdElement.setLongContent(requestId);
        this.rootElement.addChildElement(requestIdElement);
    }

    public AggregationRequestPayloadV1(DataHash dataHash, Long requestId, long level) throws KSIException {
        this(dataHash, requestId);
        this.level = level;

        TLVElement levelElement = new TLVElement(false, false, ELEMENT_TYPE_LEVEL);
        levelElement.setLongContent(level);

        this.rootElement.addChildElement(levelElement);
    }

    /**
     * Create new aggregation request.
     *
     * @param dataHash
     *         request hash value.
     * @param requestId
     *         request id
     */
    public AggregationRequestPayloadV1(DataHash dataHash, Long requestId) throws KSIException {
        this(requestId);
        this.requestHash = dataHash;
        TLVElement requestHashElement = new TLVElement(false, false, ELEMENT_TYPE_REQUEST_HASH);
        requestHashElement.setDataHashContent(dataHash);
        this.rootElement.addChildElement(requestHashElement);
    }

    /**
     * Create new aggregation request from base TLVTag.
     *
     * @param element
     *         TLV element
     */
    public AggregationRequestPayloadV1(TLVElement element) throws KSIException {
        super(element);
        List<TLVElement> children = element.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_REQUEST_ID:
                    this.requestId = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_REQUEST_HASH:
                    this.requestHash = readOnce(child).getDecodedDataHash();
                    continue;
                case ELEMENT_TYPE_LEVEL:
                    this.level = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_CONFIG:
                    readOnce(child);
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (requestId == null) {
            throw new KSIProtocolException("Invalid KSI request. Aggregation request does not contain request id.");
        }
    }

    /**
     * Get request hash.
     *
     * @return request hash
     */
    public final DataHash getRequestHash() {
        return requestHash;
    }

    /**
     * Get request Id.
     *
     * @return Request Id
     */
    public final Long getRequestId() {
        return requestId;
    }

    public Long getLevel() {
        return level;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

}
