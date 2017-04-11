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

class HAAggregatorConfiguration implements AggregatorConfiguration {

    private final Long maximumRequests;
    private final List<String> parents;
    private final Long aggregationPeriod;
    private final HashAlgorithm aggregationAlgorithm;
    private final Long maximumLevel;

    HAAggregatorConfiguration(List<AggregatorConfiguration> confs, int totalClients, int clientsInRound) {
        Long minMaxRequests = null;
        Long maxAggregationPeriod = null;
        Long minMaxLevel = null;
        HashAlgorithm aggregatedHashAlgorithm = null;
        List<String> aggregatedParents = null;
        for (AggregatorConfiguration conf : confs) {
            Long confMaxRequests = conf.getMaximumRequests();
            Long confAggregationPeriod = conf.getAggregationPeriod();
            Long confMaxLevel = conf.getMaximumLevel();
            if (minMaxRequests == null || (confMaxRequests != null && confMaxRequests <= minMaxRequests)) {
                minMaxRequests = confMaxRequests;
            }

            if (maxAggregationPeriod == null || (confAggregationPeriod != null && confAggregationPeriod >= maxAggregationPeriod)) {
                maxAggregationPeriod = confAggregationPeriod;
            }
            if (minMaxLevel == null || (confMaxLevel != null && confMaxLevel <= minMaxLevel)) {
                minMaxLevel = confMaxLevel;
            }
            HashAlgorithm confAggrAlgorithm = conf.getAggregationAlgorithm();
            if (confAggrAlgorithm != null && aggregatedHashAlgorithm == null) {
                aggregatedHashAlgorithm = confAggrAlgorithm;
            }
            List<String> subConfParents = conf.getParents();
            if (subConfParents != null && aggregatedParents == null) {
                aggregatedParents = subConfParents;
            }
        }
        this.maximumRequests = calculateMaxRequests(totalClients, clientsInRound, minMaxRequests);
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
