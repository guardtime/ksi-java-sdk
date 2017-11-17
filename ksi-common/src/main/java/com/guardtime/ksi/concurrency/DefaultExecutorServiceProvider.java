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

package com.guardtime.ksi.concurrency;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * SDK's different components use this class to get access to a common default {@link ExecutorService} if one has not been
 * provided to them.
 */
public class DefaultExecutorServiceProvider {

    private static int executorPoolSize = 1000;
    private static ExecutorService executorService;

    static {
        String poolSize = System.getProperty("executor.pool.size");
        if (poolSize != null) {
            try {
                executorPoolSize = Integer.parseInt(poolSize);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid system property 'executor.pool.size' value", e);
            }
        }
    }

    /**
     * Used to get the default {@link ExecutorService} instance, which is a cached thread pool.
     */
    public synchronized static ExecutorService getExecutorService() {
        if (executorService == null) {
            executorService = Executors.newCachedThreadPool();
            ((ThreadPoolExecutor) executorService).setMaximumPoolSize(executorPoolSize);
        }
        return executorService;
    }
}
