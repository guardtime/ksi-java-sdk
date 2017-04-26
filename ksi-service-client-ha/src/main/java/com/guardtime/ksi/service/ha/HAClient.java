/*
 * Copyright 2013-2017 Guardtime, Inc.
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
package com.guardtime.ksi.service.ha;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSISigningClient;

import java.util.Date;
import java.util.List;

/**
 * Combines {@link SigningHAClient} and {@link ExtenderHAClient}
 */
public class HAClient implements KSISigningClient, KSIExtenderClient {

    private final SigningHAClient signingHAClient;
    private final ExtenderHAClient extenderHAClient;

    /**
     * Used to initialize HAClient.
     *
     * @param signingClients
     *          List of {@link KSISigningClient}s HAClient can use.
     * @param extenderClients
     *          List of {@link KSIExtenderClient}s HAClient can use.
     *
     * @see SigningHAClient#SigningHAClient(List)
     * @see ExtenderHAClient#ExtenderHAClient(List)
     */
    public HAClient(List<KSISigningClient> signingClients, List<KSIExtenderClient> extenderClients) {
        this.signingHAClient = new SigningHAClient(signingClients);
        this.extenderHAClient = new ExtenderHAClient(extenderClients);
    }

    /**
     * @see SigningHAClient#sign(KSIRequestContext, DataHash, Long)
     */
    public Future<AggregationResponse> sign(KSIRequestContext requestContext, DataHash dataHash, Long level) throws KSIException {
        return signingHAClient.sign(requestContext, dataHash, level);
    }

    /**
     * @see ExtenderHAClient#extend(KSIRequestContext, Date, Date)
     */
    public Future<ExtensionResponse> extend(KSIRequestContext requestContext, Date aggregationTime, Date publicationTime)
            throws KSIException {
        return extenderHAClient.extend(requestContext, aggregationTime, publicationTime);
    }

    /**
     * @see SigningHAClient#getAggregatorConfiguration(KSIRequestContext)
     */
    public AggregatorConfiguration getAggregatorConfiguration(KSIRequestContext requestContext) throws KSIException {
        return signingHAClient.getAggregatorConfiguration(requestContext);
    }

    /**
     * @see ExtenderHAClient#getExtenderConfiguration(KSIRequestContext)
     */
    public ExtenderConfiguration getExtenderConfiguration(KSIRequestContext requestContext) throws KSIException {
        return extenderHAClient.getExtenderConfiguration(requestContext);
    }

    /**
     * Closes signingHaClient and extenderHaClient
     *
     * @see AbstractHAClient#close()
     */
    public void close() {
        signingHAClient.close();
        extenderHAClient.close();
    }

    @Override
    public String toString() {
        return "HAClient{SigningHAClient='" + signingHAClient + "', 'ExtenderHAClient" + extenderHAClient + "'}";
    }

}
