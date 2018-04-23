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
import com.guardtime.ksi.pdu.*;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;

import java.util.Date;

/**
 * Implementation of the {@link PduFactory}.
 */
public class PduV2Factory implements PduFactory {

    private AggregatorPduV2Factory aggregatorPduV2Factory;
    private ExtenderPduV2Factory extenderPduV2Factory;

    public PduV2Factory() {
        this.aggregatorPduV2Factory = new AggregatorPduV2Factory();
        this.extenderPduV2Factory = new ExtenderPduV2Factory();
    }

    public PduV2Factory(AggregatorPduV2Factory aggregatorPduV2Factory, ExtenderPduV2Factory extenderPduV2Factory) {
        this.aggregatorPduV2Factory = aggregatorPduV2Factory;
        this.extenderPduV2Factory = extenderPduV2Factory;
    }

    public PduV2Factory(AggregatorPduV2Factory aggregatorPduV2Factory) {
        this.aggregatorPduV2Factory = aggregatorPduV2Factory;
        this.extenderPduV2Factory = new ExtenderPduV2Factory();
    }

    public PduV2Factory(ExtenderPduV2Factory extenderPduV2Factory) {
        this.aggregatorPduV2Factory = new AggregatorPduV2Factory();
        this.extenderPduV2Factory = extenderPduV2Factory;
    }

    public AggregationRequest createAggregationRequest(KSIRequestContext context, ServiceCredentials credentials, DataHash imprint, Long level) throws KSIException {
        return this.aggregatorPduV2Factory.createAggregationRequest(context, credentials, imprint, level);
    }

    public AggregationResponse readAggregationResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException {
        return this.aggregatorPduV2Factory.readAggregationResponse(context, credentials, input);
    }

    public AggregationRequest createAggregatorConfigurationRequest(KSIRequestContext context, ServiceCredentials credentials) throws KSIException {
        return this.aggregatorPduV2Factory.createAggregatorConfigurationRequest(context, credentials);
    }

    public AggregatorConfiguration readAggregatorConfigurationResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException {
        return this.aggregatorPduV2Factory.readAggregatorConfigurationResponse(context, credentials, input);
    }

    public ExtensionRequest createExtensionRequest(KSIRequestContext context, ServiceCredentials credentials, Date aggregationTime, Date publicationTime) throws KSIException {
        return this.extenderPduV2Factory.createExtensionRequest(context, credentials, aggregationTime, publicationTime);
    }

    public ExtensionResponse readExtensionResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException {
        return this.extenderPduV2Factory.readExtensionResponse(context, credentials, input);
    }

    public ExtensionRequest createExtensionConfigurationRequest(KSIRequestContext context, ServiceCredentials credentials) throws KSIException {
        return this.extenderPduV2Factory.createExtensionConfigurationRequest(context, credentials);
    }

    public ExtenderConfiguration readExtenderConfigurationResponse(ServiceCredentials credentials, TLVElement input) throws KSIException {
        return this.extenderPduV2Factory.readExtenderConfigurationResponse(credentials, input);
    }
}
