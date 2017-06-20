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

import com.guardtime.ksi.util.Util;

class ConsolidationResult<T> {

    private final T latestResultIfItWasSuccessful;
    private final HAConfigurationConsolidationException latestResultIfItWasUnsuccessful;

    ConsolidationResult(T latestResultIfItWasSuccessful) {
        Util.notNull(latestResultIfItWasSuccessful, "Consolidation result");
        this.latestResultIfItWasSuccessful = latestResultIfItWasSuccessful;
        this.latestResultIfItWasUnsuccessful = null;
    }

    ConsolidationResult(HAConfigurationConsolidationException latestResultIfItWasUnsuccessful) {
        Util.notNull(latestResultIfItWasUnsuccessful, "Consolidation result");
        this.latestResultIfItWasUnsuccessful = latestResultIfItWasUnsuccessful;
        this.latestResultIfItWasSuccessful = null;
    }

    boolean wasSuccessful() {
        return latestResultIfItWasSuccessful != null;
    }

    public T getResult() {
        return latestResultIfItWasSuccessful;
    }

    public Throwable getException() {
        return latestResultIfItWasUnsuccessful;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ConsolidationResult<?> that = (ConsolidationResult<?>) o;

        boolean successful = wasSuccessful();
        if (successful != that.wasSuccessful()) return false;

        return successful ? getResult().equals(that.getResult()) : getException().equals(that.getException());
    }
}
