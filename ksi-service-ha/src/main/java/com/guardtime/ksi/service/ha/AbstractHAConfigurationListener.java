/*
 * Copyright 2013-2017 Guardtime, Inc.
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

import com.guardtime.ksi.service.ConfigurationListener;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Common parts of configuration consolidation and listener updates for different HA services.
 *
 * @param <T> Type of configuration handled (aggregator or extender).
 */
abstract class AbstractHAConfigurationListener<T> implements ConfigurationListener<T>{

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final List<ConfigurationListener<T>> consolidatedConfListeners = new ArrayList<>();
    ConsolidatedResult<T> lastConsolidatedConfiguration;
    private final Object lock = new Object();

    protected abstract T consolidate(T lastConfiguration, T newConsolidatedConfiguration);

    abstract List<SubServiceConfListener<T>> getSubServiceConfListeners();

    void registerListener(ConfigurationListener<T> listener) {
        Util.notNull(listener, "Consolidated configuration listener");
        consolidatedConfListeners.add(listener);
        if (lastConsolidatedConfiguration != null) {
            updateListener(listener);
        }
    }

    public void updated(T configuration) {
        recalculateConfiguration();
    }

    public void updateFailed(Throwable reason) {
        recalculateConfiguration();
    }

    private void recalculateConfiguration() {
        T newConsolidatedConfiguration = null;
        ConsolidatedResult<T> oldConsolidatedConfiguration = lastConsolidatedConfiguration;
        boolean listenersNeedUpdate;
        synchronized (lock) {
            for (SubServiceConfListener<T> serviceConfListener : getSubServiceConfListeners()) {
                if (serviceConfListener.isAccountedFor()) {
                    newConsolidatedConfiguration = consolidate(serviceConfListener.getLastConfiguration(),
                            newConsolidatedConfiguration);
                }
            }
            resetLastConsolidatedConfiguration(newConsolidatedConfiguration);
            listenersNeedUpdate = !Util.equals(lastConsolidatedConfiguration, oldConsolidatedConfiguration);
        }
        if (listenersNeedUpdate) {
            logger.info("HA service configuration changed. Old configuration: {}. New configuration: {}.",
                    oldConsolidatedConfiguration, lastConsolidatedConfiguration);
            updateListeners();
        }
    }

    private void updateListeners() {
        for (ConfigurationListener<T> listener : consolidatedConfListeners) {
            updateListener(listener);
        }
    }

    private void updateListener(ConfigurationListener<T> listener) {
        if (lastConsolidatedConfiguration.wasSuccessful()) {
            listener.updated(lastConsolidatedConfiguration.getResult());
        } else {
            listener.updateFailed(lastConsolidatedConfiguration.getException());
        }
    }

    private void resetLastConsolidatedConfiguration(T newConsolidatedConfiguration) {
        if (newConsolidatedConfiguration == null) {
            lastConsolidatedConfiguration = new ConsolidatedResult<>(new HAConfigurationConsolidationException());
        } else {
            lastConsolidatedConfiguration = new ConsolidatedResult<>(newConsolidatedConfiguration);
        }
    }

}
