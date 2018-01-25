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
package com.guardtime.ksi.service.ha;

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.service.client.KSIClientException;

import java.util.concurrent.Callable;

/**
 * Task for doing a signing request.
 */
class SigningTask implements Callable<AggregationResponse> {

    private final KSISigningService service;
    private DataHash dataHash;
    private Long level;

    /**
     * @param service
     *          {@link KSISigningService} used for the signing request.
     * @param dataHash
     *          {@link DataHash} of the data to be signed.
     * @param level
     *          level of the hash to be signed.
     */
    public SigningTask(KSISigningService service, DataHash dataHash, Long level) {
        this.service = service;
        this.dataHash = dataHash;
        this.level = level;
    }

    public AggregationResponse call() throws KSIClientException {
        try {
            return service.sign(dataHash, level).getResult();
        } catch (Exception e) {
            throw new KSIClientException("Signing via service '" + service + "' failed", e);
        }
    }
}
