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
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.AggregationResponseFuture;
import com.guardtime.ksi.pdu.AggregatorConfiguration;

import java.io.Closeable;
import java.util.List;

/**
 * Provides KSI services to communicate with the aggregator(s).
 */
public interface KSISigningService extends Closeable {

    /**
     * Creates a new KSI signature.
     *
     * @param dataHash instance of {@link DataHash} to be signed.
     * @param level the dataHash's level in the local aggregation tree.
     *
     * @return Instance of {@link AggregationResponseFuture} containing Aggregation response data.
     * @throws KSIException in case any error occurs.
     */
    Future<AggregationResponse> sign(DataHash dataHash, Long level) throws KSIException;

    /**
     * Gets all the subservices in case of the implementation that combines multiple KSISigningServices. If the implementation
     * is a KSISigningService connecting directly to a single gateway, an empty list is returned.
     *
     * @return List of subservices.
     */
    List<KSISigningService> getSubSigningServices();

    /**
     * Registers a new {@link ConfigurationListener}&lt;{@link AggregatorConfiguration}&gt;
     * for the KSISigningService. Each time KSISigningService's configuration is
     * updated, this listener is called.
     *
     * @param listener an instance of {@link ConfigurationListener}&lt;{@link AggregatorConfiguration}&gt;. 
     *
     */
    void registerAggregatorConfigurationListener(ConfigurationListener<AggregatorConfiguration> listener);

    /**
     * Makes the KSISigningService ask for configuration update. On completion of the update, the registered {@link ConfigurationListener}s
     * are called.
     *
     * @return Future of the {@link AggregatorConfiguration}.
     */
    Future<AggregatorConfiguration> getAggregationConfiguration();

}
