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
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.ConfigurationListener;

import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;

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
     * Used to initialize HAClient with custom {@link ExecutorService}.
     *
     * @param signingClients
     *          List of {@link KSISigningClient}s HAClient can use.
     * @param extenderClients
     *          List of {@link KSIExtenderClient}s HAClient can use.
     * @param executorService
     *          {@link ExecutorService} used for signing and extension requests.
     *
     * @see SigningHAClient#SigningHAClient(List, ExecutorService)
     * @see ExtenderHAClient#ExtenderHAClient(List, ExecutorService)
     */
    public HAClient(List<KSISigningClient> signingClients, List<KSIExtenderClient> extenderClients, ExecutorService executorService) {
        this.signingHAClient = new SigningHAClient(signingClients, executorService);
        this.extenderHAClient = new ExtenderHAClient(extenderClients, executorService);
    }

    /**
     * @see SigningHAClient#sign(DataHash, Long)
     */
    public Future<AggregationResponse> sign(DataHash dataHash, Long level) throws KSIException {
        return signingHAClient.sign(dataHash, level);
    }

    /**
     * @see ExtenderHAClient#extend(Date, Date)
     */
    public Future<ExtensionResponse> extend(Date aggregationTime, Date publicationTime) throws KSIException {
        return extenderHAClient.extend(aggregationTime, publicationTime);
    }

    /**
     * @see SigningHAClient#getSubSigningClients()
     */
    public List<KSISigningClient> getSubSigningClients() {
        return signingHAClient.getSubSigningClients();
    }

    /**
     * @see SigningHAClient#registerAggregatorConfigurationListener(ConfigurationListener)
     */
    public void registerAggregatorConfigurationListener(ConfigurationListener<AggregatorConfiguration> listener) {
        signingHAClient.registerAggregatorConfigurationListener(listener);
    }

    /**
     * @see SigningHAClient#updateAggregationConfiguration()
     */
    public void updateAggregationConfiguration() {
        signingHAClient.updateAggregationConfiguration();
    }

    /**
     * @see ExtenderHAClient#registerExtenderConfigurationListener(ConfigurationListener)
     */
    public void registerExtenderConfigurationListener(ConfigurationListener<ExtenderConfiguration> listener) {
        extenderHAClient.registerExtenderConfigurationListener(listener);
    }

    /**
     * @see SigningHAClient#updateAggregationConfiguration()
     */
    public void updateExtenderConfiguration() {
        signingHAClient.updateAggregationConfiguration();
    }

    /**
     * @see ExtenderHAClient#getSubExtenderClients()
     */
    public List<KSIExtenderClient> getSubExtenderClients() {
        return extenderHAClient.getSubExtenderClients();
    }


    /**
     * Closes signingHaClient and extenderHaClient
     *
     * @see SigningHAClient#close()
     * @see ExtenderHAClient#close()
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
