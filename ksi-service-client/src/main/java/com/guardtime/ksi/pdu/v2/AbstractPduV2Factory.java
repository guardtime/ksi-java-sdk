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
import com.guardtime.ksi.service.ConfigurationListener;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static com.guardtime.ksi.tlv.GlobalTlvTypes.ELEMENT_TYPE_CONFIGURATION;
import static com.guardtime.ksi.tlv.GlobalTlvTypes.ELEMENT_TYPE_REQUEST_ID;

abstract class AbstractPduV2Factory<T> {
    private static final Logger logger = LoggerFactory.getLogger(AbstractPduV2Factory.class);

    private ConfigurationListener<T> configurationListener;

    AbstractPduV2Factory() {
    }

    AbstractPduV2Factory(ConfigurationListener<T> configurationListener) {
        this.configurationListener = configurationListener;
    }

    void updateConfiguration(ServiceCredentials credentials, TLVElement input) {
        if (this.configurationListener != null) {
            try {
                List<TLVElement> confPayload = getPayloadElements(credentials, input, ELEMENT_TYPE_CONFIGURATION);
                if (!confPayload.isEmpty()) {
                    this.configurationListener.updated(getConfiguration(confPayload));
                }
            } catch (KSIException e) {
                this.configurationListener.updateFailed(e);
            }
        }
    }

    List<TLVElement> getMandatoryPayloadElements(ServiceCredentials credentials, TLVElement input, int payloadType) throws KSIException {
        List<TLVElement> payloads = getPayloadElements(credentials, input, payloadType);

        if (payloads.isEmpty()) {
            throw new IllegalStateException("Payload with TLV type 0x" + Integer.toHexString(payloadType) + " not found");
        }
        return payloads;
    }

    TLVElement getPayload(List<TLVElement> payloads, Long requestId) throws TLVParserException {
        TLVElement responsePayload = null;
        for (TLVElement payload : payloads) {
            TLVElement requestIdElement = payload.getFirstChildElement(ELEMENT_TYPE_REQUEST_ID);

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

    abstract T getConfiguration(List<TLVElement> confPayload) throws TLVParserException;

    abstract List<TLVElement> getPayloadElements(ServiceCredentials credentials, TLVElement input, int payloadType) throws KSIException;
}
