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

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.Future;

import java.util.Collection;

class HAConfFuture<T> implements Future<T> {

    private final Collection<Future<T>> confFutures;
    private final ConfResultSupplier<ConsolidatedResult<T>> lastConsolidatedConfigurationSupplier;
    private ConsolidatedResult<T> consolidationResult;

    HAConfFuture(Collection<Future<T>> confFutures, ConfResultSupplier<ConsolidatedResult<T>> confResultSupplier) {
        this.confFutures = confFutures;
        this.lastConsolidatedConfigurationSupplier = confResultSupplier;
    }

    public synchronized T getResult() throws KSIException {
        if (consolidationResult == null) {
            waitForAllResponses();
            consolidationResult = lastConsolidatedConfigurationSupplier.get();
        }
        if (consolidationResult.wasSuccessful()) {
            return consolidationResult.getResult();
        }
        throw new KSIException("Configuration consolidation failed in HA service", consolidationResult.getException());
    }

    private void waitForAllResponses() {
        for (Future<T> confFuture : confFutures) {
            try {
                confFuture.getResult();
            } catch (Exception e) {
                // Configuration related exceptions will be handled in services themselves
            }
        }
    }

    public boolean isFinished() {
        if (consolidationResult == null) {
            for (Future<T> confFuture : confFutures) {
                if (!confFuture.isFinished()) {
                    return false;
                }
            }
        }
        return true;
    }

    interface ConfResultSupplier<T> {
        T get();
    }
}
