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
package com.guardtime.ksi.service.ha.tasks;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.Callable;

public abstract class ServiceCallingTask<T> implements Callable<T>{

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    protected Map<String, Exception> exceptionHolder;

    private final String clientKey;
    protected final KSIRequestContext requestContext;

    public ServiceCallingTask(String clientKey, KSIRequestContext requestContext) {
        this.clientKey = clientKey;
        this.requestContext = requestContext;
    }

    public void setExceptionHolder(Map<String, Exception> exceptionRegistry) {
        this.exceptionHolder = exceptionRegistry;
    }

    public T call() throws Exception {
        Util.notNull(exceptionHolder, "ExtendingTask.exceptionHolder");
        try {
            return completeTask();
        } catch (Exception e) {
            logger.error("Request sent via client " + clientKey + " failed", e);
            exceptionHolder.put(clientKey, e);
            throw e;
        }
    }

    protected abstract T completeTask() throws KSIException;

    public static String createClientKey(Object client) {
        return "#" + Util.nextLong() + ": " + client.toString();
    }
}
