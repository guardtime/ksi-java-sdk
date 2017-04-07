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
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.ha.selectionmaker.RoundRobinSelectionMaker;
import com.guardtime.ksi.service.ha.selectionmaker.SelectionMaker;
import com.guardtime.ksi.service.ha.settings.SingleFunctionHAClientSettings;
import com.guardtime.ksi.service.ha.tasks.ServiceCallingTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

abstract class AbstractHAClient<CLIENT extends Closeable, SERVICE_RESPONSE, SERVICE_CONFIG_RESPONSE> implements Closeable {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final SelectionMaker<CLIENT> clientsPicker;
    private final ExecutorService executorService = Executors.newCachedThreadPool();
    private final Map<Long, Map<String, Exception>> failedRequests = new ConcurrentHashMap<Long, Map<String, Exception>>();

    private final String implName;

    AbstractHAClient(List<CLIENT> subclients, SingleFunctionHAClientSettings settings) throws KSIException {
        this.implName = getClass().getSimpleName();
        if (subclients == null) {
            subclients = Collections.emptyList();
        }
        if (settings == null) {
            settings = new SingleFunctionHAClientSettings(subclients.size());
        }
        if (settings.getActiveClientsInSingleSelection() > subclients.size()) {
            throw new KSIClientException("Invalid input parameter. It is not possible to have more clients in one selection " +
                    "than there are available clients");
        }
        this.clientsPicker = new RoundRobinSelectionMaker<CLIENT>(subclients, settings.getActiveClientsInSingleSelection());
        logger.info("Client initialized with settings %s and %d subclients", settings, subclients.size());
    }

    Collection<CLIENT> preprareClients() throws KSIClientException {
        Collection<CLIENT> clients = clientsPicker.select();
        if (clients.isEmpty()) {
            throw new KSIClientException("It is not possible to perform a request using " + implName + " because there are no clients in selection");
        }
        logger.debug("ksiClientsPicker picked clients: {}", clients);
        return clients;
    }

    SERVICE_CONFIG_RESPONSE getConfiguration(Collection<Callable<SERVICE_CONFIG_RESPONSE>> configurationRequestTasks) throws KSIClientException {
        try {
            List<java.util.concurrent.Future<SERVICE_CONFIG_RESPONSE>> configurationFutures = callAllServices(configurationRequestTasks);
            List<SERVICE_CONFIG_RESPONSE> configurations = new ArrayList<SERVICE_CONFIG_RESPONSE>();
            for (java.util.concurrent.Future<SERVICE_CONFIG_RESPONSE> configurationFuture : configurationFutures) {
                try {
                    configurations.add(configurationFuture.get());
                } catch (Exception e) {
                    logger.error("Asking configuration from " + implName + " clients subclient failed", e);
                }
            }
            if (configurations.isEmpty()) {
                throw new KSIClientException(implName + " received no configuration responses to use for building the most optimal configuration");
            }
            if (!areAllConfigrationsSame(configurations)) {
                logger.warn("Configurations gotten via " + implName + " from subclients differ from eachother. This could " +
                        "mean that external services our configured wrong. All configurations: " + configurationsToString(configurations));
            }
            return composeAggregatedConfiguration(configurations);
        } catch (Exception e) {
            throw new KSIClientException("Asking extender configurations failed", e);
        }
    }

    private boolean areAllConfigrationsSame(List<SERVICE_CONFIG_RESPONSE> configurations) {
        for (int i = 1; i < configurations.size(); i++) {
            if (!configurationsEqual(configurations.get(i - 1), configurations.get(i))) {
                return false;
            }
        }
        return true;
    }

    protected abstract boolean configurationsEqual(SERVICE_CONFIG_RESPONSE c1, SERVICE_CONFIG_RESPONSE c2);

    protected abstract String configurationsToString(List<SERVICE_CONFIG_RESPONSE> configurations);

    protected abstract SERVICE_CONFIG_RESPONSE composeAggregatedConfiguration(List<SERVICE_CONFIG_RESPONSE> configurations);

    ServiceCallFuture<SERVICE_RESPONSE> callAnyService(Collection<ServiceCallingTask<SERVICE_RESPONSE>> tasks, Long requestId)
            throws KSIClientException {
        registerTasksExceptionHolders(tasks, requestId);
        Future<SERVICE_RESPONSE> clientResponse = executorService.submit(new ServiceCallsTask(requestId, tasks));
        return new ServiceCallFuture<SERVICE_RESPONSE>(clientResponse);
    }


    List<Future<SERVICE_CONFIG_RESPONSE>> callAllServices(Collection<Callable<SERVICE_CONFIG_RESPONSE>> tasks)
            throws KSIClientException, InterruptedException {
        return executorService.invokeAll(tasks);
    }

    private void registerTasksExceptionHolders(Collection<ServiceCallingTask<SERVICE_RESPONSE>> tasks, Long requestId) {
        Map<String, Exception> exceptionHolder = registerSubclientsExceptionHolder(requestId);
        for (ServiceCallingTask<SERVICE_RESPONSE> task : tasks) {
            task.setExceptionHolder(exceptionHolder);
        }
    }

    private Map<String, Exception> registerSubclientsExceptionHolder(Long id) {
        failedRequests.put(id, new ConcurrentHashMap<String, Exception>());
        return failedRequests.get(id);
    }

    private Map<String, Exception> deRegisterSubclientsExceptionHolder(Long id) {
        return failedRequests.remove(id);
    }

    public void close() throws IOException {
        for (Closeable client : clientsPicker.getAll()) {
            try {
                client.close();
            } catch (IOException e) {
                logger.error("Failed to close subclient", e);
            }
        }
    }

    Collection<CLIENT> getAllSubclients() {
        return clientsPicker.getAll();
    }

    int getNumberClientsUsedInOneRound() {
        return clientsPicker.getNumberOfObjectsGivenInOneSelection();
    }

    @Override
    public String toString() {
        return implName + "{LB Strategy=" + clientsPicker + "}";
    }

    private class ServiceCallsTask implements Callable<SERVICE_RESPONSE> {

        private final Long requestId;
        private final Collection<ServiceCallingTask<SERVICE_RESPONSE>>  serviceCallTasks;

        ServiceCallsTask(Long requestId, Collection<ServiceCallingTask<SERVICE_RESPONSE>> serviceCallTasks) {
            this.requestId = requestId;
            this.serviceCallTasks = serviceCallTasks;
        }

        public SERVICE_RESPONSE call() throws Exception {
            try {
                SERVICE_RESPONSE clientResponse = executorService.invokeAny(serviceCallTasks);
                deRegisterSubclientsExceptionHolder(requestId);
                return clientResponse;
            } catch (Exception e) {
                Map<String, Exception> subExceptions = deRegisterSubclientsExceptionHolder(requestId);
                if (subExceptions != null && !subExceptions.isEmpty()) {
                    throw new AllHAClientSubclientsFailedException("Invoking all subclients of " + implName + " failed.", subExceptions);
                } else {
                    throw new KSIClientException("Invoking " + implName + " failed", e);
                }
            }
        }
    }
}
