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

import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregatorConfiguration;

import java.util.List;

class AggregatedAggregatorConfiguration implements AggregatorConfiguration {

    private final Long maximumRequests;
    private final List<String> parents;
    private final Long aggregationPeriod;
    private final HashAlgorithm aggregationAlgorithm;
    private final Long maximumLevel;

    AggregatedAggregatorConfiguration(List<AggregatorConfiguration> subConfigurations, int totalNumberOfClients, int numberOfClientsInOneRound) {
        Long minMaximumRequests = null;
        Long maxAggregationPeriod = null;
        Long minMaxLevel = null;
        HashAlgorithm aggregatedHashAlgorithm = null;
        List<String> aggregatedParents = null;
        for (AggregatorConfiguration subConfiguration : subConfigurations) {
            Long subConfMaxRequests = subConfiguration.getMaximumRequests();
            Long subConfAggregationPeriod = subConfiguration.getAggregationPeriod();
            Long subConfMaxLevel = subConfiguration.getMaximumLevel();
            if (minMaximumRequests == null || (subConfMaxRequests != null && subConfMaxRequests <= minMaximumRequests)) {
                minMaximumRequests = subConfMaxRequests;
            }

            if (maxAggregationPeriod == null || (subConfAggregationPeriod != null && subConfAggregationPeriod >=
                    maxAggregationPeriod)) {
                maxAggregationPeriod = subConfAggregationPeriod;
            }
            if (minMaxLevel == null || (subConfMaxLevel != null && subConfMaxLevel <= minMaxLevel)) {
                minMaxLevel = subConfMaxLevel;
            }
            HashAlgorithm subConfAggregationAlgorithm = subConfiguration.getAggregationAlgorithm();
            if (subConfAggregationAlgorithm != null && aggregatedHashAlgorithm == null) {
                aggregatedHashAlgorithm = subConfAggregationAlgorithm;
            }
            List<String> subConfParents = subConfiguration.getParents();
            if (subConfParents != null && aggregatedParents == null) {
                aggregatedParents = subConfParents;
            }
        }
        this.maximumRequests = calculateMaxRequests(totalNumberOfClients, numberOfClientsInOneRound, minMaximumRequests);
        this.aggregationPeriod = maxAggregationPeriod;
        this.maximumLevel = minMaxLevel;
        this.aggregationAlgorithm = aggregatedHashAlgorithm;
        this.parents = aggregatedParents;
    }

    Long calculateMaxRequests(int totalNumberOfClients, int numberOfClientsInOneRound, Long subConfMaximumRequests) {
        return subConfMaximumRequests == null ? null : (long) (subConfMaximumRequests * ((double) totalNumberOfClients / numberOfClientsInOneRound));
    }

    public Long getMaximumLevel() {
        return maximumLevel;
    }

    public HashAlgorithm getAggregationAlgorithm() {
        return aggregationAlgorithm;
    }

    public Long getAggregationPeriod() {
        return aggregationPeriod;
    }

    public Long getMaximumRequests() {
        return maximumRequests;
    }

    public List<String> getParents() {
        return parents;
    }

}
