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
import com.guardtime.ksi.pdu.*;
import com.guardtime.ksi.service.ConfigurationListener;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.GlobalTlvTypes;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.util.Util;

import java.util.Collections;
import java.util.Date;
import java.util.List;

import static com.guardtime.ksi.tlv.GlobalTlvTypes.ELEMENT_TYPE_CONFIGURATION;

/**
 * Implementation of the {@link ExtenderPduFactory}.
 */
public class ExtenderPduV2Factory extends AbstractPduV2Factory<ExtenderConfiguration> implements ExtenderPduFactory {

    public ExtenderPduV2Factory() {
    }

    public ExtenderPduV2Factory(ConfigurationListener<ExtenderConfiguration> extenderConfigurationListener) {
        super(extenderConfigurationListener);
    }

    public ExtensionRequest createExtensionRequest(KSIRequestContext context, ServiceCredentials credentials, Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(credentials, "ServiceCredentials");
        Util.notNull(aggregationTime, "Aggregation time");
        if (publicationTime != null && aggregationTime.after(publicationTime)) {
            throw new KSIProtocolException("There is no suitable publication yet");
        }
        ExtensionRequestPayloadV2 payload = new ExtensionRequestPayloadV2(aggregationTime, publicationTime, context.getRequestId());
        return new ExtensionRequestPduV2(Collections.singletonList(payload.getRootElement()), context, credentials);
    }


    public ExtensionResponse readExtensionResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException {
        updateConfiguration(credentials, input);

        List<TLVElement> payloads = getMandatoryPayloadElements(credentials, input, ExtensionResponsePayloadV2.ELEMENT_TYPE);
        TLVElement responsePayload = getPayload(payloads, context.getRequestId());
        if (responsePayload == null) {
            throw new KSIProtocolException("Extension response payload with requestId " + context.getRequestId() + " wasn't found");
        }

        return new ExtensionResponsePayloadV2(responsePayload);
    }

    public ExtensionRequest createExtensionConfigurationRequest(KSIRequestContext context, ServiceCredentials credentials) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(credentials, "ServiceCredentials");
        TLVElement payload = new TLVElement(false, false, false, ELEMENT_TYPE_CONFIGURATION);
        return new ExtensionRequestPduV2(Collections.singletonList(payload), context, credentials);
    }

    public ExtenderConfiguration readExtenderConfigurationResponse(ServiceCredentials credentials, TLVElement input) throws KSIException {
        return getConfiguration(getMandatoryPayloadElements(credentials, input, ELEMENT_TYPE_CONFIGURATION));
    }

    ExtenderConfiguration getConfiguration(List<TLVElement> confPayload) throws TLVParserException {
        return new ExtenderConfigurationPayload(confPayload.get(0));
    }

    List<TLVElement> getPayloadElements(ServiceCredentials credentials, TLVElement input, int payloadType) throws KSIException {
        Util.notNull(credentials, "ServiceCredentials");
        Util.notNull(input, "Input TLV");
        if (input.getType() == GlobalTlvTypes.ELEMENT_TYPE_EXTENSION_PDU_V1) {
            throw new KSIProtocolException("Received PDU v1 response to PDU v2 request. Configure the SDK to use PDU v1 format for the given Extender");
        }
        ExtensionResponsePduV2 pdu = new ExtensionResponsePduV2(input, credentials);
        return pdu.getPayloads(payloadType);
    }
}
