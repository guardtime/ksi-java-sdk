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
package com.guardtime.ksi.service.ha;

import com.guardtime.ksi.concurrency.DefaultExecutorServiceProvider;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.ConfigurationListener;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.KSIExtendingClientServiceAdapter;
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
    private final ExecutorService executorService;
    private final ExtendingHAServiceConfigurationListener haConfListener;

    private ExtendingHAService(List<KSIExtendingService> subservices, ExecutorService executorService) {
        this.subservices = Collections.unmodifiableList(subservices);
        this.executorService = executorService;
        this.haConfListener = new ExtendingHAServiceConfigurationListener(this.subservices);
    }

    /**
     * Creates a non-blocking extending request. Sends the request to all the subservices in parallel. First successful response is
     * used, others are cancelled. Request fails only if all the subservices fail.
     *
     * @see KSIExtendingService#extend(Date, Date)
     */
    public Future<ExtensionResponse> extend(Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(aggregationTime, "aggregationTime");
        Collection<KSIExtendingService> services = subservices;
        Collection<Callable<ExtensionResponse>> tasks = new ArrayList<>(services.size());
        for (KSIExtendingService service : services) {
            tasks.add(new ExtendingTask(service, aggregationTime, publicationTime));
        }
        return new ServiceCallFuture<>(
                executorService.submit(new ServiceCallsTask<>(executorService, tasks))
        );
    }

    /**
     * @return List of extender subservices this service composes of.
     */
    public List<KSIExtendingService> getSubExtendingServices() {
        return subservices;
    }

    /**
     * Registers configuration listeners that will be called if this {@link ExtendingHAService}'s configuration changes. They will not be
     * called if subservice's configuration changes in a way that does not change the consolidated configuration. To get detailed
     * info about subservices' configurations one should register their own listeners directly on subservices. Listener will
     * be called instantaneously once with the latest consolidation result as part of the registration if the latest result is
     * not null.
     *
     * @param listener may not be null.
     */
    public void registerExtenderConfigurationListener(ConfigurationListener<ExtenderConfiguration> listener) {
        haConfListener.registerListener(listener);
    }

    /**
     * Invokes a configuration for all the subservices. Does not block until responses are received.
     * Active configuration listeners are only called if any of the responses change the state of consolidated configuration.
     *
     * @return A future of the result. Can be used as an alternative to listeners to access the configuration result.
     */
    public Future<ExtenderConfiguration> getExtendingConfiguration() {
        return haConfListener.getExtensionConfiguration();
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
     * Builds the {@link ExtendingHAService}.
     */
    public static class Builder {

        private List<KSIExtendingService> services = new ArrayList<>();
        private ExecutorService executorService = DefaultExecutorServiceProvider.getExecutorService();

        /**
         * Adds subclients. If both, clients and services, are set then they are combined.
         * There should be either at least one subclient or one subservice and no more than three of them combined before
         * building. Do not have to call this if there is at least one subservice set.
         *
         * @param clients list of subclients, may not be null.
         * @return Instance of the builder itself.
         */
        public Builder addClients(List<KSIExtenderClient> clients) {
            Util.notNull(clients, "ExtendingHAService.Builder.clients");
            this.services.addAll(clientsToServices(clients));
            return this;
        }

        /**
         * Adds subservices. If both, clients and services, are set then they are combined.
         * There should be either at least one subclient or one subservice and no more than three of them combined before
         * building. Do not have to call this if there is at least one subclient set.
         *
         * @param services list of subservices, may not be null.
         * @return Instance of the builder itself.
         */
        public Builder addServices(List<KSIExtendingService> services) {
            Util.notNull(services, "ExtendingHAService.Builder.services");
            this.services.addAll(services);
            return this;
        }

        /**
         * @param executorService {@link ExecutorService} used for  asynchronous tasks. May not be null. If not set then default
         *                        will be used.
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
         * @return Instance of {@link ExtendingHAService}.
         */
        public ExtendingHAService build() {
            List<KSIExtendingService> subservices = Collections.unmodifiableList(this.services);
            if (subservices.isEmpty()) {
                throw new IllegalArgumentException("Can not initialize ExtendingHAService without any subservices");
            }
            if (subservices.size() > 3) {
                throw new IllegalArgumentException("ExtendingHAService can not be initialized with more than 3 subservices");
            }
            return new ExtendingHAService(subservices, this.executorService);
        }

        /**
         * Converts list of {@link KSIExtenderClient} to a list of {@link KSIExtendingService} by wrapping them all with
         * {@link KSIExtendingClientServiceAdapter}s.
         */
        private List<KSIExtendingService> clientsToServices(List<KSIExtenderClient> clients) {
            List<KSIExtendingService> services = new ArrayList<>(clients.size());
            for (KSIExtenderClient client : clients) {
                services.add(new KSIExtendingClientServiceAdapter(client));
            }
            return services;
        }

    }
}
