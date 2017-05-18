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
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.ConfigurationListener;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSISigningClient;
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
 * KSI Signing Client which combines other clients to achieve redundancy.
 *
 * NB! It is highly recommended that all the aggregator configurations would be in sync with each other (except credentials),
 * but if this is not the case then the configurations will be consolidated in an optimistic manner which means that if a
 * configuration parameter would improve how user can consume the service then it's preferred in the consolidated configuration.
 */
public class SigningHAClient implements KSISigningClient {

    private static final Logger logger = LoggerFactory.getLogger(SigningHAClient.class);

    private final List<KSISigningClient> subclients;

    private final ExecutorService executorService;

    private final Object confRecalculationLock = new Object();

    private final List<ConfigurationListener<AggregatorConfiguration>> consolidatedConfListeners = new ArrayList<ConfigurationListener<AggregatorConfiguration>>();
    private final List<SubClientConfListener<AggregatorConfiguration>> subClientConfListeners = new ArrayList<SubClientConfListener<AggregatorConfiguration>>();
    private SigningHAClientConfiguration lastConsolidatedConfiguration;

    /**
     * Used to initialize SigningHAClient.
     *
     * @param signingClients List of subclients to send the signing requests. May not be empty or null. May not contain more than 3 subclients.
     */
    public SigningHAClient(List<KSISigningClient> signingClients) {
        this(signingClients, DefaultExecutorServiceProvider.getExecutorService());
    }


    /**
     * Used to initialize SigningHAClient with custom {@link ExecutorService}.
     *
     * @param signingClients
     *          List of subclients to send the signing requests. May not be empty or null. May not contain more than 3 subclients.
     * @param executorService
     *          {@link ExecutorService} used for asynchronous tasks. May not be null.
     */
    public SigningHAClient(List<KSISigningClient> signingClients, ExecutorService executorService) {
        Util.notNull(executorService, "SigningHAClient.executorService");
        this.executorService = executorService;
        if (signingClients == null || signingClients.isEmpty()) {
            throw new IllegalArgumentException("Can not initialize without any subclients");
        }
        if (signingClients.size() > 3) {
            throw new IllegalArgumentException("SigningHAClient can not be initialized with more than 3 subclients");
        }
        this.subclients = Collections.unmodifiableList(signingClients);
        for (KSISigningClient signingClient : subclients) {
            SubClientConfListener<AggregatorConfiguration> listener = new SubClientConfListener<AggregatorConfiguration>(
                    signingClient.toString(), new SubconfUpdateListener() {
                public void updated() {
                    recalculateConfiguration();
                }
            });
            signingClient.registerAggregatorConfigurationListener(listener);
            subClientConfListeners.add(listener);
        }
    }

    /**
     * Does a non-blocking signing request. Sends the request to all the subclients in parallel. First successful response is
     * used, others are cancelled. Request fails only if all the subclients fail.
     *
     * @see KSISigningClient#sign(DataHash, Long)
     */
    public Future<AggregationResponse> sign(DataHash dataHash, Long level) throws KSIException {
        Util.notNull(dataHash, "dataHash");
        Util.notNull(level, "level");
        final Collection<Callable<AggregationResponse>> tasks = new ArrayList<Callable<AggregationResponse>>(subclients.size());
        for (KSISigningClient client : subclients) {
            tasks.add(new SigningTask(client, dataHash, level));
        }
        return new ServiceCallFuture<AggregationResponse>(
                executorService.submit(new ServiceCallsTask<AggregationResponse>(executorService, tasks))
        );
    }

    /**
     * @return List of signing clients this signing client composes of.
     */
    public List<KSISigningClient> getSubSigningClients() {
        return subclients;
    }

    /**
     * Registers configuration listeners that will be called if this SigningHAClients configuration changes. They will not be
     * called if subclients configuration changes in a way that does not change the consolidated configuration. To get detailed
     * info about subclients configurations one should register their own listeners directly on subclients.
     *
     * @param listener May not be null.
     */
    public void registerAggregatorConfigurationListener(ConfigurationListener<AggregatorConfiguration> listener) {
        Util.notNull(listener, "SigningHAClient consolidated configuration listener");
        consolidatedConfListeners.add(listener);
    }

    public void sendAggregationConfigurationRequest() {
        for (KSISigningClient subclient : subclients) {
            subclient.sendAggregationConfigurationRequest();
        }
    }

    private void recalculateConfiguration() {
        boolean hasAnySubconfs = false;
        SigningHAClientConfiguration newConsolidatedConfiguration = null;
        SigningHAClientConfiguration oldConsolidatedConfiguration = lastConsolidatedConfiguration;
        boolean listenersNeedUpdate;
        synchronized (confRecalculationLock) {
            for (SubClientConfListener<AggregatorConfiguration> clientConfListener : subClientConfListeners) {
                if (clientConfListener.isAccountedFor()) {
                    newConsolidatedConfiguration = consolidate(clientConfListener.getLastConfiguration(),
                            newConsolidatedConfiguration);
                    hasAnySubconfs = true;
                }
            }
            lastConsolidatedConfiguration = newConsolidatedConfiguration;
            listenersNeedUpdate = !Util.equals(newConsolidatedConfiguration, oldConsolidatedConfiguration);
        }
        if (listenersNeedUpdate) {
            logger.info("SigningHaClients configuration changed. Old configuration: {}. New configuration: {}.",
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
            throw new KSIClientException("SigningHAClient has no active subconfigurations to base it's consolitated configuration on.");
        } catch (KSIClientException e) {
            logger.error("Configuration recalculation failed.", e);
            for (ConfigurationListener<AggregatorConfiguration> listener : consolidatedConfListeners) {
                listener.updateFailed(e);
            }
        }
    }

    private SigningHAClientConfiguration consolidate(AggregatorConfiguration c1, AggregatorConfiguration c2) {
        if (c1 == null) {
            if (c2 != null) {
                return new SigningHAClientConfiguration(c2);
            }
            return null;
        }
        if (c2 == null) {
            return new SigningHAClientConfiguration(c1);
        }
        return new SigningHAClientConfiguration(c1, c2);
    }

    /**
     * Closes all the subclients.
     */
    public void close() {
        for (KSISigningClient client : subclients) {
            try {
                client.close();
            } catch (IOException e) {
                logger.error("Failed to close subclient", e);
            }
        }
    }

    @Override
    public String toString() {
        return "SigningHAClient{subclients=" + subclients + "}";
    }
}
