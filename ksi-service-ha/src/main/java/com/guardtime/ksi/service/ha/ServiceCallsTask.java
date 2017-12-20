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

import java.util.Collection;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;

/**
 * Task for invoking all the subclient tasks and returning the first successful one or throwing an exception if they all fail.
 */
class ServiceCallsTask<T> implements Callable<T> {

    private final ExecutorService executorService;
    private final Collection<Callable<T>> serviceCallTasks;

    ServiceCallsTask(ExecutorService executorService, Collection<Callable<T>> serviceCallTasks) {
        this.executorService = executorService;
        this.serviceCallTasks = serviceCallTasks;
    }

    public T call() throws Exception {
        return executorService.invokeAny(serviceCallTasks);
    }
}
