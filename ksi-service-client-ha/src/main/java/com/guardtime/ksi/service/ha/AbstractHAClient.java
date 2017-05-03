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
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * This is an abstract class for different types of High Availability clients. All of them have two common parts: <ul> <li>They
 * all have configurations to ask for and the way it's asked is the same although the configuration contents are not.</li> <li>All
 * the HA services are invoked in the same principle: all subclients are invoked and the first successful one counts. If all of
 * them fail then a combined exception is thrown.</li> </ul>
 *
 * To avoid duplication common algorithmic parts are implemented in this abstract superclass and as concrete types are different,
 * they are represented as generics
 *
 * @param <CLIENT>                  Type of subclients we are dealing with. Can be for example {@link
 *                                  com.guardtime.ksi.service.client.KSISigningClient} or
 *                                  {@link com.guardtime.ksi.service.client.KSIExtenderClient}.
 *                                  Needs to be {@link Closeable} so that if HAClient is closed then all it's subclients can also
 *                                  be closed.
 * @param <SERVICE_RESPONSE>        Type of response the CLIENT service call returns.
 * @param <SERVICE_CONFIG_RESPONSE> Type of response the CLIENT configuration call returns.
 */
abstract class AbstractHAClient<CLIENT extends Closeable, SERVICE_RESPONSE, SERVICE_CONFIG_RESPONSE> implements Closeable {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final Collection<CLIENT> subclients;
    private final ExecutorService executorService = Executors.newCachedThreadPool();

    /**
     * @param subclients        List of all the subclients. Must contain at least one subclient.
     */
    AbstractHAClient(Collection<CLIENT> subclients) {
        if (subclients == null || subclients.isEmpty()) {
            throw new IllegalArgumentException("Can not initialize " + getClass() + "without any subclients");
        }
        this.subclients = subclients;
        logger.info("Client initialized with {} subclients.", subclients.size());
    }

    /**
     * Invokes all configurationRequestTasks and waits for and returns aggregated configuration based on successful answers
     *
     * @param configurationRequestTasks List of configuration request task to invoke
     * @return Aggregated configuration based on the tasks that ended successfully
     * @throws KSIClientException If none of the tasks ended successfully.
     */
    SERVICE_CONFIG_RESPONSE getConfiguration(Collection<Callable<SERVICE_CONFIG_RESPONSE>> configurationRequestTasks) throws KSIClientException {
        try {
            List<Future<SERVICE_CONFIG_RESPONSE>> configurationFutures = executorService.invokeAll(configurationRequestTasks);
            List<SERVICE_CONFIG_RESPONSE> configurations = new ArrayList<SERVICE_CONFIG_RESPONSE>();
            for (Future<SERVICE_CONFIG_RESPONSE> configurationFuture : configurationFutures) {
                try {
                    configurations.add(configurationFuture.get());
                } catch (Exception e) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Asking configuration from subclient failed.", e);
                    } else  {
                        logger.warn("Asking configuration from subclient failed. Subclient description: '{}' Reason: '{}'", Util.exceptionSummary(e));
                    }
                }
            }
            if (configurations.isEmpty()) {
                throw new KSIClientException(getClass() + " received no configuration responses.");
            }
            if (!areAllConfsEqual(configurations)) {
                logger.warn("Received configurations from subclients differ from each other. This could " +
                        "mean that external services are configured wrong. All configurations: " + configurationsToString(configurations));
            }
            return aggregateConfigurations(configurations);
        } catch (Exception e) {
            throw new KSIClientException("Asking configurations via " + getClass() + " failed", e);
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
     * @return {@link ServiceCallFuture<SERVICE_RESPONSE>} that can be used to get the first successful service response
     */
    ServiceCallFuture<SERVICE_RESPONSE> callAnyService(Collection<Callable<SERVICE_RESPONSE>> tasks) {
        Future<SERVICE_RESPONSE> clientResponse = executorService.submit(new ServiceCallsTask(tasks));
        return new ServiceCallFuture<SERVICE_RESPONSE>(clientResponse);
    }

    /**
     * Closes all the subclients. Does not fail to close next in line if closing previous one fails.
     */
    public void close() {
        for (CLIENT client : subclients) {
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
    Collection<CLIENT> getSubclients() {
        return subclients;
    }

    @Override
    public String toString() {
        return getClass() + "{subclients=" + subclients + "}";
    }

    /**
     * Task for invoking all the subclient tasks and returning the first successful one or throwing an exception if they all fail
     */
    private class ServiceCallsTask implements Callable<SERVICE_RESPONSE> {

        private final Collection<Callable<SERVICE_RESPONSE>> serviceCallTasks;

        ServiceCallsTask(Collection<Callable<SERVICE_RESPONSE>> serviceCallTasks) {
            this.serviceCallTasks = serviceCallTasks;
        }

        public SERVICE_RESPONSE call() throws Exception {
            return executorService.invokeAny(serviceCallTasks);
        }
    }
}
