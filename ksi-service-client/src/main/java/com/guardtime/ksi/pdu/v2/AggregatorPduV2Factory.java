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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.AggregatorPduFactory;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.ConfigurationListener;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.GlobalTlvTypes;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.util.Util;

import java.util.Collections;
import java.util.List;

import static com.guardtime.ksi.tlv.GlobalTlvTypes.ELEMENT_TYPE_CONFIGURATION_PAYLOAD;

/**
 * Implementation of the {@link AggregatorPduFactory}.
 */
public class AggregatorPduV2Factory extends AbstractPduV2Factory<AggregatorConfiguration> implements AggregatorPduFactory {

    public AggregatorPduV2Factory() {
    }

    public AggregatorPduV2Factory(ConfigurationListener<AggregatorConfiguration> aggregatorConfigurationListener) {
        super(aggregatorConfigurationListener);
    }

    public AggregationRequest createAggregationRequest(KSIRequestContext context, ServiceCredentials credentials, DataHash imprint, Long level) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(imprint, "DataHash");
        Util.notNull(credentials, "ServiceCredentials");
        AggregationRequestPayloadV2 payload = new AggregationRequestPayloadV2(imprint, context.getRequestId(), level);
        return new AggregationRequestPduV2(Collections.singletonList(payload.getRootElement()), context, credentials);
    }

    public AggregationResponse readAggregationResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException {
        updateConfiguration(credentials, input);

        List<TLVElement> payloads = getMandatoryPayloadElements(credentials, input, AggregationResponsePayloadV2.ELEMENT_TYPE);
        TLVElement responsePayload = getPayload(payloads, context.getRequestId());
        if (responsePayload == null) {
            throw new KSIProtocolException("Aggregation response payload with requestId " + context.getRequestId() + " wasn't found");
        }
        return new AggregationResponsePayloadV2(responsePayload);
    }

    public AggregationRequest createAggregatorConfigurationRequest(KSIRequestContext context, ServiceCredentials credentials) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(credentials, "ServiceCredentials");
        TLVElement payload = new TLVElement(false, false, false, ELEMENT_TYPE_CONFIGURATION_PAYLOAD);
        return new AggregationRequestPduV2(Collections.singletonList(payload), context, credentials);
    }

    public AggregatorConfiguration readAggregatorConfigurationResponse(KSIRequestContext requestContext, ServiceCredentials credentials, TLVElement input) throws KSIException {
        return getConfiguration(getMandatoryPayloadElements(credentials, input, ELEMENT_TYPE_CONFIGURATION_PAYLOAD));
    }

    AggregatorConfiguration getConfiguration(List<TLVElement> confPayload) throws TLVParserException {
        return new AggregatorConfigurationPayload(confPayload.get(0));
    }

    List<TLVElement> getPayloadElements(ServiceCredentials credentials, TLVElement input, int payloadType) throws KSIException {
        Util.notNull(credentials, "ServiceCredentials");
        Util.notNull(input, "Input TLV");
        if (input.getType() != GlobalTlvTypes.ELEMENT_TYPE_AGGREGATION_RESPONSE_PDU_V2) {
            throw new KSIProtocolException("Received unknown response to PDU v2 aggregation request.");
        }
        AggregationResponsePduV2 aggregationResponsePdu = new AggregationResponsePduV2(input, credentials);
        return aggregationResponsePdu.getPayloads(payloadType);
    }
}
