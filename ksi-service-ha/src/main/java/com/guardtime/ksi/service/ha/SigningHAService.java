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
import com.guardtime.ksi.pdu.KSISigningService;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.ConfigurationListener;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.KSISigningClientServiceAdapter;
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
    private final Object confRecalculationLock = new Object();
    private final List<ConfigurationListener<AggregatorConfiguration>> consolidatedConfListeners = new ArrayList<ConfigurationListener<AggregatorConfiguration>>();
    private final List<SubServiceConfListener<AggregatorConfiguration>> subServiceConfListeners = new ArrayList<SubServiceConfListener<AggregatorConfiguration>>();

    private SigningHAServiceConfiguration lastConsolidatedConfiguration;

    private SigningHAService(Builder builder) {
        this.executorService = builder.executorService;
        List<KSISigningService> subservices = new ArrayList<KSISigningService>();
        subservices.addAll(builder.services);
        subservices.addAll(clientsToServices(builder.clients));
        if (subservices.isEmpty()) {
            throw new IllegalArgumentException("Can not initialize SigningHAService without any subservices");
        }
        if (subservices.size() > 3) {
            throw new IllegalArgumentException("SigningHAService can not be initialized with more than 3 subservices");
        }
        for (KSISigningService subservice : subservices) {
            SubServiceConfListener<AggregatorConfiguration> listener = new SubServiceConfListener<AggregatorConfiguration>(subservice.toString(), new SubconfUpdateListener() {
                public void updated() {
                    recalculateConfiguration();
                }
            });
            subservice.registerAggregatorConfigurationListener(listener);
            subServiceConfListeners.add(listener);
        }
        this.subservices = Collections.unmodifiableList(subservices);
    }

    /**
     * Converts list of {@link KSISigningClient} to a list of {@link KSISigningService} by wrapping them all with
     * {@link KSISigningClientServiceAdapter}s
     */
    private static List<KSISigningService> clientsToServices(List<KSISigningClient> clients) {
        Util.notNull(clients, "SigningHAService.clients");
        List<KSISigningService> services = new ArrayList<KSISigningService>(clients.size());
        for (KSISigningClient client : clients) {
            services.add(new KSISigningClientServiceAdapter(client));
        }
        return services;
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
     * info about subservices configurations one should register their own listeners directly on subservices.
     *
     * @param listener May not be null.
     */
    public void registerAggregatorConfigurationListener(ConfigurationListener<AggregatorConfiguration> listener) {
        Util.notNull(listener, "SigningHAService consolidated configuration listener");
        consolidatedConfListeners.add(listener);
    }

    /**
     * Invokes a configuration for all the subservices. Does not block until responses are received.
     * Active configuration listeners are only called if any of the responses change the state of consolidated configuration.
     */
    public void sendAggregationConfigurationRequest() {
        for (KSISigningService service : subservices) {
            service.sendAggregationConfigurationRequest();
        }
    }

    private void recalculateConfiguration() {
        boolean hasAnySubconfs = false;
        SigningHAServiceConfiguration newConsolidatedConfiguration = null;
        SigningHAServiceConfiguration oldConsolidatedConfiguration = lastConsolidatedConfiguration;
        boolean listenersNeedUpdate;
        synchronized (confRecalculationLock) {
            for (SubServiceConfListener<AggregatorConfiguration> serviceConfListener : subServiceConfListeners) {
                if (serviceConfListener.isAccountedFor()) {
                    newConsolidatedConfiguration = consolidate(serviceConfListener.getLastConfiguration(),
                            newConsolidatedConfiguration);
                    hasAnySubconfs = true;
                }
            }
            lastConsolidatedConfiguration = newConsolidatedConfiguration;
            listenersNeedUpdate = !Util.equals(newConsolidatedConfiguration, oldConsolidatedConfiguration);
        }
        if (listenersNeedUpdate) {
            logger.info("SigningHaServices configuration changed. Old configuration: {}. New configuration: {}.",
                    oldConsolidatedConfiguration, newConsolidatedConfiguration);
            for (ConfigurationListener<AggregatorConfiguration> listener : consolidatedConfListeners) {
                listener.updated(newConsolidatedConfiguration);
            }
        }
        if (!hasAnySubconfs) {
            confRecalculationFailed();
        }
    }

    private void confRecalculationFailed() {
        try {
            throw new KSIClientException("SigningHAService has no active subconfigurations to base its consolidated configuration on");
        } catch (KSIClientException e) {
            logger.error("Configuration recalculation failed.", e);
            for (ConfigurationListener<AggregatorConfiguration> listener : consolidatedConfListeners) {
                listener.updateFailed(e);
            }
        }
    }

    private SigningHAServiceConfiguration consolidate(AggregatorConfiguration c1, AggregatorConfiguration c2) {
        if (c1 == null) {
            if (c2 != null) {
                return new SigningHAServiceConfiguration(c2);
            }
            return null;
        }
        if (c2 == null) {
            return new SigningHAServiceConfiguration(c1);
        }
        return new SigningHAServiceConfiguration(c1, c2);
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

        private List<KSISigningClient> clients = Collections.emptyList();
        private List<KSISigningService> services = Collections.emptyList();
        private ExecutorService executorService = DefaultExecutorServiceProvider.getExecutorService();

        /**
         * For setting subclients. If both clients and services are set then they are combined.
         * There should be either at least one subclient or one subservice and no more than three of them combined before
         * building. Do not have to call this if there is at least one subservice set.
         *
         * @param clients
         *      List of subclients. May not be null.
         *
         * @return Instance of the builder itself.
         */
        public Builder setClients(List<KSISigningClient> clients) {
            Util.notNull(clients, "SigningHAService.Builder.clients");
            this.clients = clients;
            return this;
        }

        /**
         * For setting subservices. If both clients and services are set then they are combined.
         * There should be either at least one subclient or one subservice and no more than three of them combined before
         * building. Do not have to call this if there is at least one subclient set.
         *
         * @param services
         *      List of subservices. May not be null.
         *
         * @return Instance of the builder itself.
         */
        public Builder setServices(List<KSISigningService> services) {
            Util.notNull(services, "SigningHAService.Builder.services");
            this.services = services;
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
            return new SigningHAService(this);
        }

    }
}
