/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */
package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.Date;

/**
 * Signature extension request TLV object.
 */
class ExtensionRequestPayloadV2 extends TLVStructure {

    public static final int ELEMENT_TYPE = 0x2;

    private static final int ELEMENT_TYPE_REQUEST_ID = 0x1;
    private static final int ELEMENT_TYPE_AGGREGATION_TIME = 0x2;
    private static final int ELEMENT_TYPE_PUBLICATION_TIME = 0x3;

    private Long requestId;
    private Date aggregationTime;
    private Date publicationTime;

    /**
     * Creates a new instance of extension request payload.
     */
    public ExtensionRequestPayloadV2(Date aggregationTime, Date publicationTime, Long requestId) throws KSIException {
        this.requestId = requestId;
        this.aggregationTime = aggregationTime;
        this.publicationTime = publicationTime;

        this.rootElement = new TLVElement(false, false, ELEMENT_TYPE);

        rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_REQUEST_ID, requestId));
        rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_AGGREGATION_TIME, aggregationTime));
        if (publicationTime != null) {
            rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_PUBLICATION_TIME, publicationTime));
        }
    }

    public Long getRequestId() {
        return requestId;
    }

    public Date getAggregationTime() {
        return aggregationTime;
    }

    public Date getPublicationTime() {
        return publicationTime;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }
}
