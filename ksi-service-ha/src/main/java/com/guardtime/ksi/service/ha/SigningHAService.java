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

import com.guardtime.ksi.concurrency.DefaultExecutorServiceProvider;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.ConfigurationListener;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.KSISigningClientServiceAdapter;
import com.guardtime.ksi.service.ha.configuration.SigningHAServiceHAConfigurationListener;
import com.guardtime.ksi.service.ha.tasks.ServiceCallsTask;
import com.guardtime.ksi.service.ha.tasks.SigningTask;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;

/**
 * KSI Signing Service which combines clients to achieve redundancy.
 *
 * NB! It is highly recommended that all the aggregator configurations would be in sync with each other (except credentials),
 * but if this is not the case then the configurations will be consolidated in an optimistic manner which means that if a
 * configuration parameter would improve how user can consume the service then it's preferred in the consolidated configuration.
 */
public class SigningHAService implements KSISigningService {

    private static final Logger logger = LoggerFactory.getLogger(SigningHAService.class);

    private final List<KSISigningService> subservices;
    private final ExecutorService executorService;
    private final SigningHAServiceHAConfigurationListener haConfListener;

    private SigningHAService(List<KSISigningService> subservices, ExecutorService executorService) {
        this.executorService = executorService;
        this.subservices = subservices;
        this.haConfListener = new SigningHAServiceHAConfigurationListener(this.subservices);
    }

    /**
     * Does a non-blocking signing request. Sends the request to all the subservices in parallel. First successful response is
     * used, others are cancelled. Request fails only if all the subservices fail.
     *
     * @see KSISigningService#sign(DataHash, Long)
     */
    public Future<AggregationResponse> sign(DataHash dataHash, Long level) throws KSIException {
        Util.notNull(dataHash, "dataHash");
        Util.notNull(level, "level");
        final Collection<Callable<AggregationResponse>> tasks = new ArrayList<Callable<AggregationResponse>>(subservices.size());
        for (KSISigningService subservices : subservices) {
            tasks.add(new SigningTask(subservices, dataHash, level));
        }
        return new ServiceCallFuture<AggregationResponse>(
                executorService.submit(new ServiceCallsTask<AggregationResponse>(executorService, tasks))
        );
    }

    /**
     * @return List of signing services this signing service composes of.
     */
    public List<KSISigningService> getSubSigningServices() {
        return subservices;
    }

    /**
     * Registers configuration listeners that will be called if this SigningHAServices configuration changes. They will not be
     * called if subservices configuration changes in a way that does not change the consolidated configuration. To get detailed
     * info about subservices configurations one should register their own listeners directly on subservices. Listener will
     * be called instantaneously once with the latest consolidation result as part of the registration if the latest result is
     * not null.
     *
     * @param listener May not be null.
     */
    public void registerAggregatorConfigurationListener(ConfigurationListener<AggregatorConfiguration> listener) {
        haConfListener.registerListener(listener);
    }

    /**
     * Invokes a configuration for all the subservices. Does not block until responses are received.
     * Active configuration listeners are only called if any of the responses change the state of consolidated configuration.
     */
    public void sendAggregationConfigurationRequest() {
        haConfListener.sendAggregationConfigurationRequest();
    }

    /**
     * Closes all the subservices.
     */
    public void close() {
        for (KSISigningService service : subservices) {
            try {
                service.close();
            } catch (IOException e) {
                logger.error("Failed to close subservice", e);
            }
        }
    }

    @Override
    public String toString() {
        return "SigningHAService{subservices=" + subservices + "}";
    }

    /**
     * For building the SigningHAService.
     */
    public static class Builder {

        private List<KSISigningService> services = new ArrayList<KSISigningService>();
        private ExecutorService executorService = DefaultExecutorServiceProvider.getExecutorService();

        /**
         * For adding subclients. If both clients and services are set then they are combined.
         * There should be either at least one subclient or one subservice and no more than three of them combined before
         * building. Do not have to call this if there is at least one subservice set.
         *
         * @param clients
         *      List of subclients. May not be null.
         *
         * @return Instance of the builder itself.
         */
        public Builder addClients(List<KSISigningClient> clients) {
            Util.notNull(clients, "SigningHAService.Builder.clients");
            this.services.addAll(clientsToServices(clients));
            return this;
        }

        /**
         * For adding subservices. If both clients and services are set then they are combined.
         * There should be either at least one subclient or one subservice and no more than three of them combined before
         * building. Do not have to call this if there is at least one subclient set.
         *
         * @param services
         *      List of subservices. May not be null.
         *
         * @return Instance of the builder itself.
         */
        public Builder addServices(List<KSISigningService> services) {
            Util.notNull(services, "SigningHAService.Builder.services");
            this.services.addAll(services);
            return this;
        }

        /**
         * @param executorService
         *      {@link ExecutorService} used for  asynchronous tasks. May not be null. If not set then default will be used.
         *
         * @return Instance of the builder itself.
         */
        public Builder setExecutorService(ExecutorService executorService) {
            Util.notNull(executorService, "SigningHAService.Builder.executorService");
            this.executorService = executorService;
            return this;
        }

        /**
         * Builds the {@link SigningHAService} instance.
         *
         * @return Instance of {@link SigningHAService}
         */
        public SigningHAService build() {
            List<KSISigningService> subservices = Collections.unmodifiableList(this.services);
            if (subservices.isEmpty()) {
                throw new IllegalArgumentException("Can not initialize SigningHAService without any subservices");
            }
            if (subservices.size() > 3) {
                throw new IllegalArgumentException("SigningHAService can not be initialized with more than 3 combined subservices or subclients");
            }
            return new SigningHAService(subservices, executorService);
        }

        /**
         * Converts list of {@link KSISigningClient} to a list of {@link KSISigningService} by wrapping them all with
         * {@link KSISigningClientServiceAdapter}s
         */
        private List<KSISigningService> clientsToServices(List<KSISigningClient> clients) {
            List<KSISigningService> services = new ArrayList<KSISigningService>(clients.size());
            for (KSISigningClient client : clients) {
                services.add(new KSISigningClientServiceAdapter(client));
            }
            return services;
        }

    }
}
