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
package com.guardtime.ksi.service.ha.configuration;

import com.guardtime.ksi.service.client.ConfigurationListener;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper to keep track of the last known state of certain subclients configuration
 */
class SubServiceConfListener<T> implements ConfigurationListener<T> {

    private static final Logger logger = LoggerFactory.getLogger(SubServiceConfListener.class);

    private final SubconfUpdateListener subconfUpdateListener;

    private final String clientId;
    private T lastConfiguration;

    /**
     * @param clientId Something to distinguish the client from other clients. Used in logging.
     * @param subconfUpdateListener Listener to call every time subclients configuration is updated. It's implementation
     *                                    should start the recalculation process.
     */
    SubServiceConfListener(String clientId, SubconfUpdateListener subconfUpdateListener) {
        Util.notNull(clientId, "SubServiceConfListener.clientId");
        Util.notNull(subconfUpdateListener, "SubServiceConfListener.subconfUpdateListener");
        this.clientId = clientId;
        this.subconfUpdateListener = subconfUpdateListener;
    }

    /**
     * @return True if last request succeeded. Means that this configuration can be accounted for in consolidation process.
     */
    boolean isAccountedFor() {
        return lastConfiguration != null;
    }

    /**
     * @return Result of the last configuration request. Null if last request failed.
     */
    T getLastConfiguration() {
        return lastConfiguration;
    }

    public void updated(T configuration) {
        lastConfiguration = configuration;
        subconfUpdateListener.updated();
    }

    public void updateFailed(Throwable t) {
        lastConfiguration = null;
        logger.warn("SigningHAService " + clientId + " subclients configuration request failed.", t);
        subconfUpdateListener.updated();
    }
}
