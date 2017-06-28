/*
 * Copyright 2013-2016 Guardtime, Inc.
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
package com.guardtime.ksi.service;

import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

/**
 * Helper for handling asynchronous configuration requests and keeping track that registered listeners would be appropriately
 * updated of results.
 *
 * @param <T> type of configuration this handler handles.
 */
public class ConfigurationHandler<T> {

    private static final Logger logger = LoggerFactory.getLogger(ConfigurationHandler.class);

    private List<ConfigurationListener<T>> listeners = new ArrayList<ConfigurationListener<T>>();
    private final ExecutorService executorService;

    /**
     * Can be used to initialize ConfigurationHandler with a custom {@link ExecutorService}
     * @param executorService
     *          {@link ExecutorService} that this configuration handler should use
     */
    public ConfigurationHandler(ExecutorService executorService) {
        this.executorService = executorService;
    }

    /**
     * For registering a new listener.
     *
     * @param listener May not be null.
     */
    public void registerListener(ConfigurationListener<T> listener) {
        Util.notNull(listener, "Configuration listener");
        listeners.add(listener);
    }

    /**
     * Invokes a configuration request and updates listeners asynchronously.
     *
     * @param configurationRequest May not be null.
     */
    public Future<T> doConfigurationUpdate(final ConfigurationRequest<T> configurationRequest) {
        Util.notNull(configurationRequest, "ConfigurationRequest passed to ConfigurationHandler");
        return executorService.submit(new Callable<T>() {
            public T call() throws Exception {
                try {
                    T conf = configurationRequest.invoke();
                    updateListenersWithNewConfiguration(conf);
                    return conf;
                } catch (Exception e) {
                    updateListenersWithFailure(e);
                    throw e;
                }
            }
        });
    }

    private void updateListenersWithNewConfiguration(T newConfiguration) {
        for (ConfigurationListener<T> listener : listeners) {
            try {
                listener.updated(newConfiguration);
            } catch (Exception e) {
                logger.error("Updating a listener with new configuration failed.", e);
            }
        }
    }

    private void updateListenersWithFailure(Throwable t) {
        for (ConfigurationListener<T> listener : listeners) {
            try {
                listener.updateFailed(t);
            } catch (Exception e) {
                logger.error("Updating a listener with configuration request failure failed.", e);
            }
        }
    }

}
