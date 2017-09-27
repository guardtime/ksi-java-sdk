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
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionRequest;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.GlobalTlvTypes;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Date;
import java.util.List;

public class PduV2Factory implements PduFactory {

    private static final Logger logger = LoggerFactory.getLogger(PduV2Factory.class);

    public static final int ELEMENT_TYPE_CONFIGURATION = 0x04;

    public AggregationRequest createAggregationRequest(KSIRequestContext context, ServiceCredentials credentials, DataHash imprint, Long level) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(imprint, "DataHash");
        Util.notNull(credentials,"ServiceCredentials");
        AggregationRequestPayloadV2 payload = new AggregationRequestPayloadV2(imprint, context.getRequestId(), level);
        return new AggregationRequestPduV2(Collections.singletonList(payload.getRootElement()), HashAlgorithm.SHA2_256, context, credentials);
    }

    public AggregationRequest createAggregatorConfigurationRequest(KSIRequestContext context, ServiceCredentials credentials) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(credentials,"ServiceCredentials");
        TLVElement payload = new TLVElement(false, false, false, ELEMENT_TYPE_CONFIGURATION);
        return new AggregationRequestPduV2(Collections.singletonList(payload), HashAlgorithm.SHA2_256, context, credentials);
    }

    public AggregatorConfiguration readAggregatorConfigurationResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException {
        List<TLVElement> payloads = getAggregatorPayloadElements(credentials, input, ELEMENT_TYPE_CONFIGURATION);
        return new AggregatorConfigurationPayload(payloads.get(0));
    }

    public AggregationResponse readAggregationResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException {
        List<TLVElement> payloads = getAggregatorPayloadElements(credentials, input, AggregationResponsePayloadV2.ELEMENT_TYPE);

        TLVElement responsePayload = getPayload(payloads, context.getRequestId());
        if (responsePayload == null) {
            throw new KSIProtocolException("Aggregation response payload with requestId " + context.getRequestId() + " wasn't found");
        }
        return new AggregationResponsePayloadV2(responsePayload);
    }

    public ExtensionRequest createExtensionRequest(KSIRequestContext context, ServiceCredentials credentials, Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(credentials,"ServiceCredentials");
        Util.notNull(aggregationTime, "Aggregation time");
        if (publicationTime != null && aggregationTime.after(publicationTime)) {
            throw new KSIProtocolException("There is no suitable publication yet");
        }
        ExtensionRequestPayloadV2 payload = new ExtensionRequestPayloadV2(aggregationTime, publicationTime, context.getRequestId());
        return new ExtensionRequestPduV2(Collections.singletonList(payload.getRootElement()), HashAlgorithm.SHA2_256, context, credentials);
    }

    public ExtensionRequest createExtensionConfigurationRequest(KSIRequestContext context, ServiceCredentials credentials) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(credentials,"ServiceCredentials");
        TLVElement payload = new TLVElement(false, false, false, ELEMENT_TYPE_CONFIGURATION);
        return new ExtensionRequestPduV2(Collections.singletonList(payload), HashAlgorithm.SHA2_256, context, credentials);
    }

    public ExtensionResponse readExtensionResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException {
        List<TLVElement> payloads = getExtenderPayloadElements(credentials, input, ExtensionResponsePayloadV2.ELEMENT_TYPE);

        TLVElement responsePayload = getPayload(payloads, context.getRequestId());
        if (responsePayload == null) {
            throw new KSIProtocolException("Extension response payload with requestId " + context.getRequestId() + " wasn't found");
        }

        return new ExtensionResponsePayloadV2(responsePayload);
    }

    public ExtenderConfiguration readExtenderConfigurationResponse(ServiceCredentials credentials, TLVElement input) throws KSIException {
        List<TLVElement> payloads = getExtenderPayloadElements(credentials, input, ELEMENT_TYPE_CONFIGURATION);
        return new ExtenderConfigurationPayload(payloads.get(0));
    }

    private TLVElement getPayload(List<TLVElement> payloads, Long requestId) throws TLVParserException {
        TLVElement responsePayload = null;
        for (TLVElement payload : payloads) {
            TLVElement requestIdElement = payload.getFirstChildElement(0x01);

            if (requestIdElement != null) {
                Long id = requestIdElement.getDecodedLong();
                if (requestId.equals(id)) {
                    if (responsePayload == null) {
                        responsePayload = payload;
                    } else {
                        logger.warn("Duplicate response payload received");
                    }
                } else {
                    logger.warn("Response payload with requestId={} encountered, expected requestId={}", id, requestId);
                }
            }
        }
        return responsePayload;
    }

    private List<TLVElement> getAggregatorPayloadElements(ServiceCredentials credentials, TLVElement input, int payloadType) throws KSIException {
        Util.notNull(credentials, "ServiceCredentials");
        Util.notNull(input, "Input TLV");
        if (input.getType() == GlobalTlvTypes.ELEMENT_TYPE_AGGREGATION_PDU_V1) {
            throw new KSIProtocolException("Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Aggregator");
        }
        AggregationResponsePduV2 aggregationResponsePdu = new AggregationResponsePduV2(input, credentials);
        List<TLVElement> payloads = aggregationResponsePdu.getPayloads(payloadType);

        if (payloads.isEmpty()) {
            throw new IllegalStateException("Payload with TLV type 0x" + Integer.toHexString(payloadType) + " not found");
        }
        return payloads;
    }

    private List<TLVElement> getExtenderPayloadElements(ServiceCredentials credentials, TLVElement input, int payloadType) throws KSIException {
        Util.notNull(credentials, "ServiceCredentials");
        Util.notNull(input, "Input TLV");
        if (input.getType() == GlobalTlvTypes.ELEMENT_TYPE_EXTENSION_PDU_V1) {
            throw new KSIProtocolException("Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Extender");
        }
        ExtensionResponsePduV2 pdu = new ExtensionResponsePduV2(input, credentials);
        List<TLVElement> payloads = pdu.getPayloads(payloadType);

        if (payloads.isEmpty()) {
            throw new IllegalStateException("Payload with TLV type 0x" + Integer.toHexString(payloadType) + " not found");
        }
        return payloads;
    }

}
