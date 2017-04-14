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

import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.ha.selectionmaker.RoundRobinSelectionMaker;
import com.guardtime.ksi.service.ha.tasks.ServiceCallingTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * This is an abstract class for different types of High Availability clients. All of them have two common parts:
 * <ul>
 *     <li>They all have configurations to ask for and the way it's asked is the same although the configuration contents are not.</li>
 *     <li>All the HA services are invoked in the same principle: all subclients are invoked and the first successful one counts.
 *          If all of them fail then a combined exception is thrown.</li>
 * </ul>
 *
 * To avoid duplication common algorithmic parts are implemented in this abstract superclass and as concrete types are different,
 * they are represented as generics
 *
 * @param <CLIENT> Type of subclients we are dealing with. Can be for example {@link com.guardtime.ksi.service.client.KSISigningClient} or
 *                {@link com.guardtime.ksi.service.client.KSIExtenderClient}. Needs to be {@link Closeable} so that if HAClient is closed
 *                then all it's subclients can also be closed.
 * @param <SERVICE_RESPONSE> Type of response the CLIENT service call returns.
 * @param <SERVICE_CONFIG_RESPONSE> Type of response the CLIENT configuration call returns.
 */
abstract class AbstractHAClient<CLIENT extends Closeable, SERVICE_RESPONSE, SERVICE_CONFIG_RESPONSE> implements Closeable {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final RoundRobinSelectionMaker<CLIENT> clientsPicker;
    private final ExecutorService executorService = Executors.newCachedThreadPool();
    private final Map<Long, Map<String, Exception>> failedRequests = new ConcurrentHashMap<Long, Map<String, Exception>>();

    private final String implName;

    /**
     * @param subclients List of all the subclients. Must contain at least one subclient.
     * @param clientsForRequest Number of clients selected to serve any single request. If null then it's set equal to the size of subClients list
     */
    AbstractHAClient(List<CLIENT> subclients, Integer clientsForRequest) {
        this.implName = getClass().getSimpleName();
        if (subclients == null || subclients.isEmpty()) {
            throw new IllegalArgumentException("Can not initialize " + implName + "without any subclients");
        }
        if (clientsForRequest == null) {
            clientsForRequest = subclients.size();
        }
        if (clientsForRequest <= 0) {
            throw new IllegalArgumentException("Can not initialize " + implName + " with less than one subclient per selection");
        }
        if (clientsForRequest > subclients.size()) {
            throw new IllegalArgumentException("Invalid input parameter. It is not possible to have more clients in one selection " +
                    "than there are available clients");
        }
        this.clientsPicker = new RoundRobinSelectionMaker<CLIENT>(subclients, clientsForRequest);
        logger.info("Client initialized with %s subclients for any single request %s and %d total number of subclients", clientsForRequest, subclients.size());
    }

    /**
     *
     * @return Selection of clients for any single request. Selection is based on chosen load balancing algorithm and configuration
     * @throws KSIClientException
     */
    Collection<CLIENT> prepareClients() throws KSIClientException {
        Collection<CLIENT> clients = clientsPicker.select();
        logger.debug("ksiClientsPicker picked clients: {}", clients);
        return clients;
    }

    /**
     * Invokes all configurationRequestTasks and waits for and returns aggregated configuration based on successful answers
     *
     * @param configurationRequestTasks List of configuration request task to invoke
     * @return  Aggregated configuration based on the tasks that ended successfully
     * @throws KSIClientException If none of the tasks ended successfully.
     */
    SERVICE_CONFIG_RESPONSE getConfiguration(Collection<Callable<SERVICE_CONFIG_RESPONSE>> configurationRequestTasks) throws KSIClientException {
        try {
            List<java.util.concurrent.Future<SERVICE_CONFIG_RESPONSE>> configurationFutures = callAllServiceConfigurations(configurationRequestTasks);
            List<SERVICE_CONFIG_RESPONSE> configurations = new ArrayList<SERVICE_CONFIG_RESPONSE>();
            for (java.util.concurrent.Future<SERVICE_CONFIG_RESPONSE> configurationFuture : configurationFutures) {
                try {
                    configurations.add(configurationFuture.get());
                } catch (Exception e) {
                    logger.warn("Asking configuration from " + implName + " clients subclient failed", e);
                }
            }
            if (configurations.isEmpty()) {
                throw new KSIClientException(implName + " received no configuration responses to use for building the most optimal configuration");
            }
            if (!areAllConfsEqual(configurations)) {
                logger.warn("Configurations gotten via " + implName + " from subclients differ from eachother. This could " +
                        "mean that external services are configured wrong. All configurations: " + configurationsToString(configurations));
            }
            return aggregateConfigurations(configurations);
        } catch (Exception e) {
            throw new KSIClientException("Asking extender configurations failed", e);
        }
    }

    private boolean areAllConfsEqual(List<SERVICE_CONFIG_RESPONSE> configurations) {
        for (int i = 1; i < configurations.size(); i++) {
            if (!configurationsEqual(configurations.get(i - 1), configurations.get(i))) {
                return false;
            }
        }
        return true;
    }

    protected abstract boolean configurationsEqual(SERVICE_CONFIG_RESPONSE c1, SERVICE_CONFIG_RESPONSE c2);

    protected abstract String configurationsToString(List<SERVICE_CONFIG_RESPONSE> configurations);

    protected abstract SERVICE_CONFIG_RESPONSE aggregateConfigurations(List<SERVICE_CONFIG_RESPONSE> configurations);

    /**
     * Invokes all service calling tasks and returns a future that eventually returns the result of first successful one.
     *
     * @param tasks List of service call tasks
     * @param requestId ID of the request to keep track of requests
     * @return {@link ServiceCallFuture<SERVICE_RESPONSE>} that can be used to get the first successful service response
     */
    ServiceCallFuture<SERVICE_RESPONSE> callAnyService(Collection<ServiceCallingTask<SERVICE_RESPONSE>> tasks, Long requestId) {
        registerTasksExceptionHolders(tasks, requestId);
        Future<SERVICE_RESPONSE> clientResponse = executorService.submit(new ServiceCallsTask(requestId, tasks));
        return new ServiceCallFuture<SERVICE_RESPONSE>(clientResponse);
    }

    /**
     * Invokes the tasks that ask for all the subclients configurations.
     *
     * @param tasks Configuration asking tasks for different subclients.
     * @return {@link List<Future>} of all the subclients configurations
     *
     * @throws InterruptedException
     */
    List<Future<SERVICE_CONFIG_RESPONSE>> callAllServiceConfigurations(Collection<Callable<SERVICE_CONFIG_RESPONSE>> tasks)
            throws InterruptedException {
        return executorService.invokeAll(tasks);
    }

    /**
     * All tasks contain exception holders to keep track which asynchronous service calls have failed. Those exception holders
     * can be used to build combined exception if all the service calls fail. This method sets a common exception holder for
     * all tasks meant for a single logical request.
     */
    private void registerTasksExceptionHolders(Collection<ServiceCallingTask<SERVICE_RESPONSE>> tasks, Long requestId) {
        Map<String, Exception> exceptionHolder = registerSubclientsExceptionHolder(requestId);
        for (ServiceCallingTask<SERVICE_RESPONSE> task : tasks) {
            task.setExceptionHolder(exceptionHolder);
        }
    }

    /**
     * Registers and created a new exception holder for a logical request.
     */
    private Map<String, Exception> registerSubclientsExceptionHolder(Long id) {
        failedRequests.put(id, new ConcurrentHashMap<String, Exception>());
        return failedRequests.get(id);
    }

    /**
     * Removed an exception holder from registry. Should be called if all subclients have finished.
     */
    private Map<String, Exception> deregisterSubclientsExceptionHolder(Long id) {
        return failedRequests.remove(id);
    }

    /**
     * Closes all the subclients. Does not fail to close next in line if closing previous one fails.
     */
    public void close() {
        for (Closeable client : clientsPicker.getAll()) {
            try {
                client.close();
            } catch (IOException e) {
                logger.error("Failed to close subclient", e);
            }
        }
    }

    /**
     * @return All the available clients tha the HAClient was configured with
     */
    Collection<CLIENT> getAllSubclients() {
        return clientsPicker.getAll();
    }

    /**
     * @return Number of clients returned by client picking algorithm for any single request
     */
    int getRequestClientselectionSize() {
        return clientsPicker.selectionSize();
    }

    @Override
    public String toString() {
        return implName + "{LB Strategy=" + clientsPicker + "}";
    }

    /**
     * Task for invoking all the subclient tasks and returning the first successful one or throwing an exception if they all fail
     */
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
                deregisterSubclientsExceptionHolder(requestId);
                return clientResponse;
            } catch (Exception e) {
                Map<String, Exception> subExceptions = deregisterSubclientsExceptionHolder(requestId);
                if (subExceptions != null && !subExceptions.isEmpty()) {
                    throw new HASubclientsFailedException("Invoking all subclients of " + implName + " failed.", subExceptions);
                } else {
                    throw new KSIClientException("Invoking " + implName + " failed", e);
                }
            }
        }
    }
}
