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
package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;

class AggregationRequestPayloadV2 extends TLVStructure {

    static final int ELEMENT_TYPE = 0x02;

    private static final int ELEMENT_TYPE_REQUEST_ID = 0x01;
    private static final int ELEMENT_TYPE_REQUEST_HASH = 0x02;
    private static final int ELEMENT_TYPE_LEVEL = 0x03;

    private long level = 0L;
    private Long requestId;
    private DataHash requestHash;

    public AggregationRequestPayloadV2(DataHash dataHash, Long requestId, long level) throws KSIException {
        this.requestId = requestId;
        this.level = level;
        this.requestHash = dataHash;
        this.rootElement = new TLVElement(false, false, ELEMENT_TYPE);

        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_REQUEST_ID, requestId));
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_REQUEST_HASH, dataHash));
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_LEVEL, level));
    }

    public long getLevel() {
        return level;
    }

    public Long getRequestId() {
        return requestId;
    }

    public DataHash getRequestHash() {
        return requestHash;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

    @Override
    public String toString() {
        return "AggregationRequestPayloadV2{" +
                "level=" + level +
                ", requestId=" + requestId +
                ", requestHash=" + requestHash +
                '}';
    }

}
