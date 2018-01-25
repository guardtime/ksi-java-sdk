/*
 * Copyright 2013-2018 Guardtime, Inc.
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
package com.guardtime.ksi.service;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIClientException;

import java.util.concurrent.ExecutionException;

/**
 * Future wrapping configuration request result.
 *
 * @param <T> Configuration type
 */
class ConfigurationFuture<T> implements Future<T> {

    private final java.util.concurrent.Future<T> requestFuture;
    private T result;

    ConfigurationFuture(java.util.concurrent.Future<T> requestFuture) {
        this.requestFuture = requestFuture;
    }

    public synchronized T getResult() throws KSIException {
        if (result != null) {
            return result;
        }
        waitForResponse();
        return result;
    }

    private void waitForResponse() throws KSIException {
        try {
            result = requestFuture.get();
        } catch (InterruptedException e) {
            throw new KSIClientException("Configuration update was interrupted", e);
        } catch (ExecutionException e) {
            throw new KSIClientException("Configuration update execution failed", e);
        }
    }

    public boolean isFinished() {
        return result != null || requestFuture.isDone();
    }
}
