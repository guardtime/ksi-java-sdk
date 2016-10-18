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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.ExtensionRequest;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;

import java.util.Arrays;
import java.util.Date;

public class PduV2Factory implements PduFactory {

    public AggregationRequest createAggregationRequest(KSIRequestContext context, DataHash imprint, Long level) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(imprint, "DataHash");
        AggregationRequestPayloadV2 payload = new AggregationRequestPayloadV2(imprint, context.getRequestId(), level);
        return new AggregationRequestPduV2(Arrays.asList(payload), HashAlgorithm.SHA2_256, context);
    }

    public AggregationResponse readAggregationResponse(KSIRequestContext context, TLVElement input) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(input, "Input TLV");
        if (input.getType() == 0x0200) {
            throw new KSIProtocolException("Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Aggregator");
        }
        AggregationResponsePduV2 aggregationResponsePdu = new AggregationResponsePduV2(input, context);
        TLVElement payload = aggregationResponsePdu.getPayload(AggregationResponsePayloadV2.ELEMENT_TYPE);
        return new AggregationResponsePayloadV2(payload, context);
    }

    public ExtensionRequest createExtensionRequest(KSIRequestContext context, Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(aggregationTime, "Aggregation time");
        if (publicationTime != null && aggregationTime.after(publicationTime)) {
            throw new KSIProtocolException("There is no suitable publication yet");
        }
        ExtensionRequestPayloadV2 payload = new ExtensionRequestPayloadV2(aggregationTime, publicationTime, context.getRequestId());
        return new ExtensionRequestPduV2(Arrays.asList(payload), HashAlgorithm.SHA2_256, context);
    }

    public ExtensionResponse readExtensionResponse(KSIRequestContext context, TLVElement input) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(input, "Input TLV");
        if (input.getType() == 0x0300) {
            throw new KSIProtocolException("Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Extender");
        }
        ExtensionResponsePduV2 responsePdu = new ExtensionResponsePduV2(input, context);
        return new ExtensionResponsePayloadV2(responsePdu.getPayload(ExtensionResponsePayloadV2.ELEMENT_TYPE), context);
    }

}
