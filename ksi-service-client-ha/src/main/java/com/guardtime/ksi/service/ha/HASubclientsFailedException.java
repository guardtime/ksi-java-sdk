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

import com.guardtime.ksi.service.client.KSIClientException;

import java.util.Map;

/**
 * This exception is thrown if all subclients of a HAClient fail.
 */
public class HASubclientsFailedException extends KSIClientException {

    private Map<String, Exception> subclientExceptions;

    HASubclientsFailedException(String message, Map<String, Exception> subclientExceptions) {
        super(message);
        this.subclientExceptions = subclientExceptions;
    }

    /**
     * @return Exceptions thrown by subclients. Map keys are results of subclient ids and values are corresponding exceptions.
     */
    public Map<String, Exception> getExceptions() {
        return subclientExceptions;
    }

}
