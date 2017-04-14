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

package com.guardtime.ksi.service.client;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.AggregationResponseFuture;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.Future;

import java.io.Closeable;

/**
 * KSI client for signing service
 */
public interface KSISigningClient extends Closeable {

    /**
     * Used to create new signature.
     *
     * @param requestContext - instance of {@link KSIRequestContext}.
     * @param dataHash - instance of {@link DataHash} to be signed.
     * @param level - level of the dataHash to be signed in the overall tree.
     *
     * @return instance of {@link AggregationResponseFuture} containing Aggregation response data.
     * @throws KSIException
     */
    Future<AggregationResponse> sign(KSIRequestContext requestContext, DataHash dataHash, Long level) throws KSIException;

    /**
     *
     * @param requestContext - instance of {@link KSIRequestContext}.
     * @return {@link AggregatorConfiguration} one should rely on when using this client
     * @throws KSIException
     */
    AggregatorConfiguration getAggregatorConfiguration(KSIRequestContext requestContext) throws KSIException;
}
