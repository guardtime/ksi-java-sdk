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

package com.guardtime.ksi.pdu;

import com.guardtime.ksi.hashing.HashAlgorithm;

import java.util.List;

/**
 * The aggregator configuration.
 */
public interface AggregatorConfiguration {

    /**
     * @return The maximum level value that the client's aggregation tree is allowed to have.
     */
    Long getMaximumLevel();

    /**
     * @return The hash function that the client is recommended to use in its aggregation trees.
     */
    HashAlgorithm getAggregationAlgorithm();

    /**
     * @return The recommended duration of client's aggregation round, in milliseconds.
     */
    Long getAggregationPeriod();

    /**
     * @return The maximum number of requests the client is allowed to send within one aggregation period of the
     * recommended duration.
     */
    Long getMaximumRequests();

    /**
     * @return List of parent server URIs
     */
    List<String> getParents();

}
