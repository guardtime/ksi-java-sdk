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
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.ConfigurationListener;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
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
 * KSI Extender Client which combines other clients to achieve redundancy.
 *
 * NB! It is highly recommended that all the extender configurations would be in sync with each other (except credentials),
 * but if this is not the case then the configurations will be consolidated in an optimistic manner which means that if a
 * configuration parameter would improve how user can consume the service then it's preferred in the consolidated configuration.
 */
public class ExtenderHAClient implements KSIExtenderClient {

    private static final Logger logger = LoggerFactory.getLogger(ExtenderHAClient.class);

    private final List<KSIExtenderClient> subclients;

    private final List<ConfigurationListener<ExtenderConfiguration>> consolidatedConfListeners = new ArrayList<ConfigurationListener<ExtenderConfiguration>>();
    private final List<SubClientConfListener<ExtenderConfiguration>> subClientConfListeners = new ArrayList<SubClientConfListener<ExtenderConfiguration>>();
    private ExtenderHAClientConfiguration lastConsolidatedConfiguration;

    private final ExecutorService executorService;

    /**
     * Used to initialize ExtenderHAClient with a custom {@link ExecutorService}.
     *
     * @param extenderClients
     *          List of subclients to send the extending requests. May not be empty or null. May not contain more than 3 subclients.
     * @param executorService
     *          {@link ExecutorService} used for asynchronous tasks. May not be null.
     */
    public ExtenderHAClient(List<KSIExtenderClient> extenderClients, ExecutorService executorService) {
        Util.notNull(executorService, "ExtenderHAClient.executorService");
        this.executorService = executorService;
        if (extenderClients == null || extenderClients.isEmpty()) {
            throw new IllegalArgumentException("Can not initialize without any subclients");
        }
        if (extenderClients.size() > 3) {
            throw new IllegalArgumentException("ExtenderHAClient can not be initialized with more than 3 subclients");
        }
        this.subclients = Collections.unmodifiableList(extenderClients);
        for (KSIExtenderClient extenderClient : subclients) {
            SubClientConfListener<ExtenderConfiguration> listener = new SubClientConfListener<ExtenderConfiguration>(
                    extenderClient.toString(), new SubconfUpdateListener() {
                public void updated() {
                    recalculateConfiguration();
                }
            });
            extenderClient.registerExtenderConfigurationListener(listener);
            subClientConfListeners.add(listener);
        }
    }

    /**
     * Used to initialize ExtenderHAClient.
     *
     * @param extenderClients
     *          List of subclients to send the extending requests. May not be empty or null. May not contain more than 3 subclients.
     *
     */
    public ExtenderHAClient(List<KSIExtenderClient> extenderClients) {
        this(extenderClients, DefaultExecutorServiceProvider.getExecutorService());
    }

    private void recalculateConfiguration() {
        ExtenderHAClientConfiguration newConsolidatedConfiguration = null;
        boolean hasAnySubconfs = false;
        for (SubClientConfListener<ExtenderConfiguration> clientConfListener : subClientConfListeners) {
            if (clientConfListener.isAccountedFor()) {
                newConsolidatedConfiguration = consolidate(clientConfListener.getLastConfiguration(),
                        newConsolidatedConfiguration);
                hasAnySubconfs = true;
            }
        }
        ExtenderHAClientConfiguration oldConsolidatedConfiguration = lastConsolidatedConfiguration;
        lastConsolidatedConfiguration = newConsolidatedConfiguration;
        if (!Util.equals(newConsolidatedConfiguration, oldConsolidatedConfiguration)) {
            logger.info("ExtenderHaClients configuration has changed compared to it's last known state. Old configuration: {}. " +
                    "New configuration: {}.", oldConsolidatedConfiguration, newConsolidatedConfiguration);
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
            throw new KSIClientException("ExtenderHAClient has no active subconfigurations to base it's consolidated configuration on");
        } catch (KSIClientException e) {
            logger.error("Configuration recalculation failed.", e);
            for (ConfigurationListener<ExtenderConfiguration> listener : consolidatedConfListeners) {
                listener.updateFailed(e);
            }
        }
    }

    private ExtenderHAClientConfiguration consolidate(ExtenderConfiguration c1, ExtenderConfiguration c2) {
        if (c1 == null) {
            if (c2 != null) {
                return new ExtenderHAClientConfiguration(c2);
            }
            return null;
        }
        if (c2 == null) {
            return new ExtenderHAClientConfiguration(c1);
        }
        return new ExtenderHAClientConfiguration(c1, c2);
    }

    /**
     * Does a non-blocking extending request. Sends the request to all the subclients in parallel. First successful response is
     * used, others are cancelled. Request fails only if all the subclients fail.
     *
     * @see KSIExtenderClient#extend(Date, Date)
     */
    public Future<ExtensionResponse> extend(Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(aggregationTime, "aggregationTime");
        Collection<KSIExtenderClient> clients = subclients;
        Collection<Callable<ExtensionResponse>> tasks = new ArrayList<Callable<ExtensionResponse>>(clients.size());
        for (KSIExtenderClient client : clients) {
            tasks.add(new ExtendingTask(client, aggregationTime, publicationTime));
        }
        return new ServiceCallFuture<ExtensionResponse>(
                executorService.submit(new ServiceCallsTask<ExtensionResponse>(executorService, tasks))
        );
    }

    /**
     * @return List of extender clients this extender client composes of.
     */
    public List<KSIExtenderClient> getSubExtenderClients() {
        return subclients;
    }

    /**
     * Registers configuration listeners that will be called if this ExtenderHAClients configuration changes. They will not be
     * called if subclients configuration changes in a way that does not change the consolidated configuration. To get detailed
     * info about subclients configurations one should register their own listeners directly on subclients.
     *
     * @param listener May not be null.
     */
    public void registerExtenderConfigurationListener(ConfigurationListener<ExtenderConfiguration> listener) {
        Util.notNull(listener, "ExtenderHAClient consolidated configuration listener");
        consolidatedConfListeners.add(listener);
    }

    public void updateExtenderConfiguration() throws KSIException {
        for (KSIExtenderClient subclient : subclients) {
            subclient.updateExtenderConfiguration();
        }
    }

    /**
     * Closes all the subclients.
     */
    public void close() {
        for (KSIExtenderClient client : subclients) {
            try {
                client.close();
            } catch (IOException e) {
                logger.error("Failed to close subclient", e);
            }
        }
    }
}
