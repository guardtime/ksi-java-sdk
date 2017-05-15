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
import com.guardtime.ksi.pdu.*;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.GlobalTlvTypes;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;

import java.util.Date;

/**
 * Legacy implementation of {@link PduFactory}.
 */
public class PduV1Factory implements PduFactory {

    public AggregationRequest createAggregationRequest(KSIRequestContext context, ServiceCredentials credentials, DataHash imprint, Long level) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(imprint, "DataHash");
        Util.notNull(credentials, "ServiceCredentials");
        PduMessageHeader header = new PduMessageHeader(credentials.getLoginId(), context.getInstanceId(), context.getMessageId());
        AggregationRequestPayloadV1 request = new AggregationRequestPayloadV1(imprint, context.getRequestId(), level);
        return new AggregationRequestV1(header, request, credentials.getLoginKey());
    }

    public AggregationResponse readAggregationResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(input, "Input TLV");
        if (input.getType() == GlobalTlvTypes.ELEMENT_TYPE_AGGREGATION_RESPONSE_PDU_V2) {
            throw new KSIProtocolException("Received PDU v2 response to PDU v1 request. Configure the SDK to use PDU v2 format for the given Aggregator");
        }
        return new AggregationResponseV1(input, context, credentials).getResponsePayload();
    }

    public ExtensionRequest createExtensionRequest(KSIRequestContext context, ServiceCredentials credentials, Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(aggregationTime, "AggregationTime");
        Util.notNull(credentials, "ServiceCredentials");
        PduMessageHeader header = new PduMessageHeader(credentials.getLoginId(), context.getInstanceId(), context.getMessageId());
        ExtensionRequestPayloadV1 extensionRequest = new ExtensionRequestPayloadV1(aggregationTime, publicationTime, context.getRequestId());
        return new ExtensionRequestV1(header, extensionRequest, credentials.getLoginKey());
    }

    public ExtensionResponse readExtensionResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(input, "Input TLV");
        if (input.getType() == GlobalTlvTypes.ELEMENT_TYPE_EXTENSION_RESPONSE_PDU_V2) {
            throw new KSIProtocolException("Received PDU v2 response to PDU v1 request. Configure the SDK to use PDU v2 format for the given Extender");
        }
        return new ExtensionResponseV1(input, context, credentials).getResponsePayload();
    }

    public AggregationRequest createAggregatorConfigurationRequest(KSIRequestContext requestContext, ServiceCredentials credentials) throws KSIException {
        throw new KSIException("Not supported. Configure the SDK to use PDU v2 format.");
    }

    public AggregatorConfiguration readAggregatorConfigurationResponse(KSIRequestContext requestContext, ServiceCredentials credentials, TLVElement input) throws KSIException {
        throw new KSIException("Not supported. Configure the SDK to use PDU v2 format.");
    }

    public ExtensionRequest createExtensionConfigurationRequest(KSIRequestContext requestContext, ServiceCredentials credentials) throws KSIException {
        throw new KSIException("Not supported. Configure the SDK to use PDU v2 format.");
    }

    public ExtenderConfiguration readExtenderConfigurationResponse(ServiceCredentials credentials, TLVElement input) throws KSIException {
        throw new KSIException("Not supported. Configure the SDK to use PDU v2 format.");
    }

}
