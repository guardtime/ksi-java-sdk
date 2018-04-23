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
package com.guardtime.ksi.pdu;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;

public interface AggregatorPduFactory {

    /**
     * Creates a new aggregation request.
     */
    AggregationRequest createAggregationRequest(KSIRequestContext context, ServiceCredentials credentials, DataHash imprint, Long level) throws KSIException;

    /**
     * Reads an aggregation response.
     */
    AggregationResponse readAggregationResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException;

    /**
     * Creates an aggregation configuration request.
     */
    AggregationRequest createAggregatorConfigurationRequest(KSIRequestContext context, ServiceCredentials credentials) throws KSIException;

    /**
     * Reads an aggregation configuration response.
     */
    AggregatorConfiguration readAggregatorConfigurationResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException;

}
