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
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.ConfigurationListener;

import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;

/**
 * Combines {@link SigningHAService} and {@link ExtendingHAService}.
 */
public class HAService implements KSISigningService, KSIExtendingService {

    private final SigningHAService signingHAService;
    private final ExtendingHAService extendingHAService;

    private HAService(SigningHAService signingHAService, ExtendingHAService extendingHAService) {
        this.signingHAService = signingHAService;
        this.extendingHAService = extendingHAService;
    }

    /**
     * @see SigningHAService#sign(DataHash, Long)
     */
    public Future<AggregationResponse> sign(DataHash dataHash, Long level) throws KSIException {
        return signingHAService.sign(dataHash, level);
    }

    /**
     * @see ExtendingHAService#extend(Date, Date)
     */
    public Future<ExtensionResponse> extend(Date aggregationTime, Date publicationTime) throws KSIException {
        return extendingHAService.extend(aggregationTime, publicationTime);
    }

    /**
     * @see SigningHAService#registerAggregatorConfigurationListener(ConfigurationListener)
     */
    public void registerAggregatorConfigurationListener(ConfigurationListener<AggregatorConfiguration> listener) {
        signingHAService.registerAggregatorConfigurationListener(listener);
    }

    /**
     * @see SigningHAService#getAggregationConfiguration()
     */
    public Future<AggregatorConfiguration> getAggregationConfiguration() {
        return signingHAService.getAggregationConfiguration();
    }

    /**
     * @see ExtendingHAService#registerExtenderConfigurationListener(ConfigurationListener)
     */
    public void registerExtenderConfigurationListener(ConfigurationListener<ExtenderConfiguration> listener) {
        extendingHAService.registerExtenderConfigurationListener(listener);
    }

    /**
     * @see ExtendingHAService#getExtendingConfiguration()
     */
    public Future<ExtenderConfiguration> getExtendingConfiguration() {
        return extendingHAService.getExtendingConfiguration();
    }

    /**
     * @see SigningHAService#getSubSigningServices()
     */
    public List<KSISigningService> getSubSigningServices() {
        return signingHAService.getSubSigningServices();
    }

    /**
     * @see ExtendingHAService#getSubExtendingServices()
     */
    public List<KSIExtendingService> getSubExtendingServices() {
        return extendingHAService.getSubExtendingServices();
    }

    /**
     * Closes signingHaService and extenderHaService.
     *
     * @see SigningHAService#close()
     * @see ExtendingHAService#close()
     */
    public void close() {
        signingHAService.close();
        extendingHAService.close();
    }

    @Override
    public String toString() {
        return "HAService{SigningHAService='" + signingHAService + "', 'ExtendingHAService" + extendingHAService + "'}";
    }

    /**
     * Builds the {@link SigningHAService}.
     */
    public static class Builder {

        private final SigningHAService.Builder signingHAServiceBuilder = new SigningHAService.Builder();
        private final ExtendingHAService.Builder extenderHAServiceBuilder = new ExtendingHAService.Builder();

        /**
         * @see SigningHAService.Builder#addClients(List)
         *
         * @param clients list of signing clients.
         *
         * @return Instance of the builder itself.
         */
        public HAService.Builder addSigningClients(List<KSISigningClient> clients) {
            signingHAServiceBuilder.addClients(clients);
            return this;
        }

        /**
         * @see SigningHAService.Builder#addServices(List)
         *
         * @param services list of signing services.
         *
         * @return Instance of the builder itself.
         */
        public HAService.Builder addSigningServices(List<KSISigningService> services) {
            signingHAServiceBuilder.addServices(services);
            return this;
        }

        /**
         * @see ExtendingHAService.Builder#addClients(List)
         *
         * @param clients list of extender clients.
         *
         * @return Instance of the builder itself.
         */
        public HAService.Builder addExtenderClients(List<KSIExtenderClient> clients) {
            extenderHAServiceBuilder.addClients(clients);
            return this;
        }

        /**
         * @see ExtendingHAService.Builder#addServices(List)
         *
         * @param services list of extending services.
         *
         * @return Instance of the builder itself.
         */
        public HAService.Builder addExtenderServices(List<KSIExtendingService> services) {
            extenderHAServiceBuilder.addServices(services);
            return this;
        }

        /**
         * {@link HAService} builder.
         *
         * @see SigningHAService.Builder#setExecutorService(ExecutorService)
         * @see ExtendingHAService.Builder#setExecutorService(ExecutorService)
         *
         * @param executorService an instance of {@link SigningHAService.Builder#setExecutorService(ExecutorService)} or {@link ExtendingHAService.Builder#setExecutorService(ExecutorService)}.
         *
         * @return Instance of the builder itself.
         */
        public HAService.Builder setExecutorService(ExecutorService executorService) {
            signingHAServiceBuilder.setExecutorService(executorService);
            extenderHAServiceBuilder.setExecutorService(executorService);
            return this;
        }

        /**
         * Builds an instance of {@link HAService} based on what is set in this builder.
         *
         * @see SigningHAService.Builder#build()
         * @see ExtendingHAService.Builder#build()
         *
         * @return Instance of {@link HAService}.
         */
        public HAService build() {
            return new HAService(signingHAServiceBuilder.build(), extenderHAServiceBuilder.build());
        }

    }

}
