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
import com.guardtime.ksi.service.AbstractKSIResponse;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.KSIRequestContext;
import com.guardtime.ksi.tlv.TLVElement;

/**
 * <p> This class is used to describe an aggregation response protocol data unit (PDU).</p>
 */
public class AggregationResponse extends AbstractKSIResponse<AggregationResponsePayload> {


    public static final int ELEMENT_TYPE_AGGREGATION_RESPONSE = 0x0200;

    /**
     * This constructor is used to parse response messages. Also does the basic validation.
     *
     * @param rootElement
     *         instance of{@link TLVElement}
     * @param context
     *         instance of {@link KSIRequestContext}. may not be null
     * @throws KSIProtocolException
     *         will be thrown when TLV message parsing fails
     */
    public AggregationResponse(TLVElement rootElement, KSIRequestContext context) throws KSIException {
        super(rootElement, context);
    }

    @Override
    protected AggregationResponsePayload parse(TLVElement element) throws KSIException {
        return new AggregationResponsePayload(element);
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE_AGGREGATION_RESPONSE;
    }
}
