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
package com.guardtime.ksi.service.ha.settings;

import com.guardtime.ksi.exceptions.KSIException;

/**
 * Settings for the HAClient.
 */
public class HAClientSettings {
    private final int activeSigningClientsPerRequest;
    private final int threadPoolSize;

    public HAClientSettings(int activeSigningClientsPerRequest, int threadPoolSize) throws KSIException {
        if (activeSigningClientsPerRequest < 1) {
            throw new KSIException("Invalid input parameter. Property activeSigningClientsPerRequest must not be smaller than 1");
        }
        if (threadPoolSize < 1) {
            throw new KSIException("Invalid input parameter. Property threadPoolSize must not be smaller than 1");
        }
        this.activeSigningClientsPerRequest = activeSigningClientsPerRequest;
        this.threadPoolSize = threadPoolSize;
    }

    public int getActiveSigningClientsPerRequest() {
        return activeSigningClientsPerRequest;
    }

    public int getThreadPoolSize() {
        return threadPoolSize;
    }

    @Override
    public String toString() {
        return "HAClientSettings{" +
                "activeSigningClientsPerRequest=" + activeSigningClientsPerRequest +
                ", threadPoolSize=" + threadPoolSize +
                '}';
    }
}
