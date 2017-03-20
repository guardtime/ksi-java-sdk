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
package com.guardtime.ksi.pdu;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;

import java.util.Date;

/**
 * An abstract factory interface to support multiple ways to create KSI Protocol Data Unit (PDU) messages.
 */
public interface PduFactory {

    /**
     * Creates a new aggregation request PDU message.
     */
    AggregationRequest createAggregationRequest(KSIRequestContext context, DataHash imprint, Long level) throws KSIException;

    /**
     * Reads an aggregation response.
     */
    AggregationResponse readAggregationResponse(KSIRequestContext context, TLVElement input) throws KSIException;

    /**
     * Creates a new extension request.
     */
    ExtensionRequest createExtensionRequest(KSIRequestContext context, Date aggregationTime, Date publicationTime) throws KSIException;

    /**
     * Reads an extension response.
     */
    ExtensionResponse readExtensionResponse(KSIRequestContext context, TLVElement input) throws KSIException;

    AggregationRequest createAggregatorConfigurationRequest(KSIRequestContext requestContext) throws KSIException;

    AggregatorConfiguration readAggregatorConfigurationResponse(KSIRequestContext requestContext, TLVElement input) throws KSIException;

    /**
     * This method can be used to create an extension configuration request
     */
    ExtensionRequest createExtensionConfigurationRequest(KSIRequestContext requestContext) throws KSIException;

    ExtenderConfiguration readExtensionConfigurationResponse(KSIRequestContext context, TLVElement input) throws KSIException;
}
