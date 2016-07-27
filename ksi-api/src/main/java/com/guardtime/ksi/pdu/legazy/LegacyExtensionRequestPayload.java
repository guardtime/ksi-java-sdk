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
package com.guardtime.ksi.pdu.legazy;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.Date;
import java.util.List;

/**
 * Signature extension request TLV object.
 */
class LegacyExtensionRequestPayload extends TLVStructure {

    public static final int ELEMENT_TYPE = 0x301;
    private static final int ELEMENT_TYPE_REQUEST_ID = 0x1;
    private static final int ELEMENT_TYPE_AGGREGATION_TIME = 0x2;
    private static final int ELEMENT_TYPE_PUBLICATION_TIME = 0x3;

    private Long requestId;
    private Date aggregationTime;
    private Date publicationTime;

    /**
     * Create extension request with aggregation time.
     *
     * @param aggregationTime
     *         aggregation time
     * @param requestId
     *         request identifier
     */
    public LegacyExtensionRequestPayload(Date aggregationTime, Long requestId) throws KSIException {
        if (aggregationTime == null) {
            throw new IllegalArgumentException("Invalid input parameter. AggregationTime is null.");
        }

        this.requestId = requestId;
        this.aggregationTime = aggregationTime;
        this.rootElement = new TLVElement(false, false, ELEMENT_TYPE);

        //requestID
        TLVElement requestIdElement = new TLVElement(false, false, ELEMENT_TYPE_REQUEST_ID);
        requestIdElement.setLongContent(requestId);
        rootElement.addChildElement(requestIdElement);

        //aggregationTime
        TLVElement aggregationTimeElement = new TLVElement(false, false, ELEMENT_TYPE_AGGREGATION_TIME);
        aggregationTimeElement.setLongContent(aggregationTime.getTime() / 1000);
        rootElement.addChildElement(aggregationTimeElement);
    }

    /**
     * Create extension request with aggregation and publication time.
     *
     * @param aggregationTime
     *         aggregation time
     * @param publicationTime
     *         publication time
     * @param requestId
     *         request identifier
     * @throws KSIProtocolException
     *         if request requires hash chain going backwards in time
     */
    public LegacyExtensionRequestPayload(Date aggregationTime, Date publicationTime, Long requestId) throws KSIException {
        this(aggregationTime, requestId);
        if (publicationTime != null) {
            if (aggregationTime.after(publicationTime)) {
                throw new KSIProtocolException("There is no suitable publication yet");
            }

            this.publicationTime = publicationTime;
            TLVElement publicationTimeElement = new TLVElement(false, false, ELEMENT_TYPE_PUBLICATION_TIME);
            publicationTimeElement.setLongContent(publicationTime.getTime() / 1000);
            rootElement.addChildElement(publicationTimeElement);
        }
    }

    public LegacyExtensionRequestPayload(TLVElement element) throws KSIException {
        super(element);
        List<TLVElement> children = element.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_REQUEST_ID:
                    this.requestId = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_AGGREGATION_TIME:
                    this.aggregationTime = readOnce(child).getDecodedDate();
                    continue;
                case ELEMENT_TYPE_PUBLICATION_TIME:
                    this.publicationTime = readOnce(child).getDecodedDate();
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (requestId == null) {
            throw new KSIProtocolException("Invalid extension request. Request id is missing");
        }
        if (aggregationTime == null) {
            throw new KSIProtocolException("Invalid extension request. Aggregation time is missing");
        }
    }


    /**
     * @return request id
     */
    public final Long getRequestId() {
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
