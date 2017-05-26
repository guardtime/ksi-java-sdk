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
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIExtendingService;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.ConfigurationListener;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIExtendingClientServiceAdapter;
import com.guardtime.ksi.service.ha.tasks.ExtendingTask;
import com.guardtime.ksi.service.ha.tasks.ServiceCallsTask;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;

/**
 * KSI Extending Service which combines clients to achieve redundancy.
 *
 * NB! It is highly recommended that all the extender configurations would be in sync with each other (except credentials),
 * but if this is not the case then the configurations will be consolidated in an optimistic manner which means that if a
 * configuration parameter would improve how user can consume the service then it's preferred in the consolidated configuration.
 */
public class ExtendingHAService implements KSIExtendingService {

    private static final Logger logger = LoggerFactory.getLogger(ExtendingHAService.class);

    private final List<KSIExtendingService> subservices;
    private final List<ConfigurationListener<ExtenderConfiguration>> consolidatedConfListeners = new ArrayList<ConfigurationListener<ExtenderConfiguration>>();
    private final List<SubServiceConfListener<ExtenderConfiguration>> subServiceConfListeners = new ArrayList<SubServiceConfListener<ExtenderConfiguration>>();
    private final ExecutorService executorService;

    private ExtenderHAServiceConfiguration lastConsolidatedConfiguration;

    private ExtendingHAService(Builder builder) {
        this.executorService = builder.executorService;
        List<KSIExtendingService> subservices = new ArrayList<KSIExtendingService>();
        subservices.addAll(builder.services);
        subservices.addAll(clientsToServices(builder.clients));
        if (subservices.isEmpty()) {
            throw new IllegalArgumentException("Can not initialize ExtendingHAService without any subservices");
        }
        if (subservices.size() > 3) {
            throw new IllegalArgumentException("ExtendingHAService can not be initialized with more than 3 subservices");
        }
        for (KSIExtendingService subservice : subservices) {
            SubServiceConfListener<ExtenderConfiguration> listener = new SubServiceConfListener<ExtenderConfiguration>(subservice.toString(), new SubconfUpdateListener() {
                public void updated() {
                    recalculateConfiguration();
                }
            });
            subservice.registerExtenderConfigurationListener(listener);
            subServiceConfListeners.add(listener);
        }
        this.subservices = Collections.unmodifiableList(subservices);
    }

    /**
     * Converts list of {@link KSIExtenderClient} to a list of {@link KSIExtendingService} by wrapping them all with
     * {@link KSIExtendingClientServiceAdapter}s
     */
    private static List<KSIExtendingService> clientsToServices(List<KSIExtenderClient> clients) {
        Util.notNull(clients, "ExtendingHAService.clients");
        List<KSIExtendingService> services = new ArrayList<KSIExtendingService>(clients.size());
        for (KSIExtenderClient client : clients) {
            services.add(new KSIExtendingClientServiceAdapter(client));
        }
        return services;
    }

    private void recalculateConfiguration() {
        ExtenderHAServiceConfiguration newConsolidatedConfiguration = null;
        boolean hasAnySubconfs = false;
        for (SubServiceConfListener<ExtenderConfiguration> confListener : subServiceConfListeners) {
            if (confListener.isAccountedFor()) {
                newConsolidatedConfiguration = consolidate(confListener.getLastConfiguration(),
                        newConsolidatedConfiguration);
                hasAnySubconfs = true;
            }
        }
        ExtenderHAServiceConfiguration oldConsolidatedConfiguration = lastConsolidatedConfiguration;
        lastConsolidatedConfiguration = newConsolidatedConfiguration;
        if (!Util.equals(newConsolidatedConfiguration, oldConsolidatedConfiguration)) {
            logger.info("ExtenderHAServices configuration changed. Old configuration: {}. New configuration: {}.",
                    oldConsolidatedConfiguration, newConsolidatedConfiguration);
            for (ConfigurationListener<ExtenderConfiguration> listener : consolidatedConfListeners) {
                listener.updated(newConsolidatedConfiguration);
            }
        }
        if (!hasAnySubconfs) {
            confRecalculationFailed();
        }
    }

    private void confRecalculationFailed() {
        try {
            throw new KSIClientException("ExtendingHAService has no active subconfigurations to base its consolidated configuration on");
        } catch (KSIClientException e) {
            logger.error("Configuration recalculation failed.", e);
            for (ConfigurationListener<ExtenderConfiguration> listener : consolidatedConfListeners) {
                listener.updateFailed(e);
            }
        }
    }

    private ExtenderHAServiceConfiguration consolidate(ExtenderConfiguration c1, ExtenderConfiguration c2) {
        if (c1 == null) {
            if (c2 != null) {
                return new ExtenderHAServiceConfiguration(c2);
            }
            return null;
        }
        if (c2 == null) {
            return new ExtenderHAServiceConfiguration(c1);
        }
        return new ExtenderHAServiceConfiguration(c1, c2);
    }

    /**
     * Does a non-blocking extending request. Sends the request to all the subservices in parallel. First successful response is
     * used, others are cancelled. Request fails only if all the subservices fail.
     *
     * @see KSIExtendingService#extend(Date, Date)
     */
    public Future<ExtensionResponse> extend(Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(aggregationTime, "aggregationTime");
        Collection<KSIExtendingService> services = subservices;
        Collection<Callable<ExtensionResponse>> tasks = new ArrayList<Callable<ExtensionResponse>>(services.size());
        for (KSIExtendingService service : services) {
            tasks.add(new ExtendingTask(service, aggregationTime, publicationTime));
        }
        return new ServiceCallFuture<ExtensionResponse>(
                executorService.submit(new ServiceCallsTask<ExtensionResponse>(executorService, tasks))
        );
    }

    /**
     * @return List of extender services this service composes of.
     */
    public List<KSIExtendingService> getSubExtendingServices() {
        return subservices;
    }

    /**
     * Registers configuration listeners that will be called if this ExtenderHAServices configuration changes. They will not be
     * called if subservices configuration changes in a way that does not change the consolidated configuration. To get detailed
     * info about subservices configurations one should register their own listeners directly on subservices.
     *
     * @param listener May not be null.
     */
    public void registerExtenderConfigurationListener(ConfigurationListener<ExtenderConfiguration> listener) {
        Util.notNull(listener, "ExtendingHAService consolidated configuration listener");
        consolidatedConfListeners.add(listener);
    }

    public void sendExtenderConfigurationRequest() {
        for (KSIExtendingService service : subservices) {
            service.sendExtenderConfigurationRequest();
        }
    }

    /**
     * Closes all the subservices.
     */
    public void close() {
        for (KSIExtendingService service : subservices) {
            try {
                service.close();
            } catch (IOException e) {
                logger.error("Failed to close subservice", e);
            }
        }
    }

    /**
     * For building the ExtendingHAService.
     */
    public static class Builder {

        private List<KSIExtenderClient> clients = Collections.emptyList();
        private List<KSIExtendingService> services = Collections.emptyList();
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
        public Builder setClients(List<KSIExtenderClient> clients) {
            Util.notNull(clients, "ExtendingHAService.Builder.clients");
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
        public Builder setServices(List<KSIExtendingService> services) {
            Util.notNull(services, "ExtendingHAService.Builder.services");
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
            Util.notNull(executorService, "ExtendingHAService.Builder.executorService");
            this.executorService = executorService;
            return this;
        }

        /**
         * Builds the {@link ExtendingHAService} instance.
         *
         * @return Instance of {@link ExtendingHAService}
         */
        public ExtendingHAService build() {
            return new ExtendingHAService(this);
        }

    }
}
