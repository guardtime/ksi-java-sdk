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

import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSISigningClient;

/**
 * Task for doing a signing request.
 */
public class SigningTask extends ServiceCallingTask<AggregationResponse> {

    private final KSISigningClient client;
    private DataHash dataHash;
    private Long level;

    /**
     * @param client
     *          {@link KSISigningClient} used for the signing request.
     * @param requestContext
     *          {@link KSIRequestContext} for the signing request.
     * @param dataHash
     *          {@link DataHash} of the data to be signed.
     * @param level
     *          Level of the hash to be signed.
     */
    public SigningTask(KSISigningClient client, KSIRequestContext requestContext, DataHash dataHash, Long level) {
        super(requestContext);
        this.client = client;
        this.dataHash = dataHash;
        this.level = level;
    }

    public AggregationResponse call() throws KSIClientException {
        try {
            return client.sign(requestContext, dataHash, level).getResult();
        } catch (Exception e) {
            throw new KSIClientException("Signing via client '" + client + "' failed", e);
        }
    }
}
