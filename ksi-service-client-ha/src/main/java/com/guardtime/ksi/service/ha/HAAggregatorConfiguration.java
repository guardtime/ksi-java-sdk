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

    private Long maxRequests;
    private List<String> parents;
    private Long aggregationPeriod;
    private HashAlgorithm aggregationAlgorithm;
    private Long maxLevel;

    HAAggregatorConfiguration(List<AggregatorConfiguration> confs, int totalClients, int clientsInRound) {
        for (AggregatorConfiguration conf : confs) {

            Long confMaxRequests = conf.getMaximumRequests();
            Long confAggregationPeriod = conf.getAggregationPeriod();
            Long confMaxLevel = conf.getMaximumLevel();
            HashAlgorithm confAggrAlgorithm = conf.getAggregationAlgorithm();
            List<String> confParents = conf.getParents();

            if (isSmaller(maxRequests, confMaxRequests)) {
                maxRequests = confMaxRequests;
            }
            if (isBigger(aggregationPeriod, confAggregationPeriod)) {
                aggregationPeriod = confAggregationPeriod;
            }
            if (isSmaller(maxLevel, confMaxLevel)) {
                maxLevel = confMaxLevel;
            }
            if (confAggrAlgorithm != null) {
                aggregationAlgorithm = confAggrAlgorithm;
            }
            if (confParents != null) {
                parents = confParents;
            }
        }
        this.maxRequests = adjustMaxRequests(totalClients, clientsInRound, maxRequests);
    }

    private boolean isBigger(Long oldVal, Long newVal) {
        return oldVal == null || (newVal != null && newVal > oldVal);
    }

    private boolean isSmaller(Long oldVal, Long newVal) {
        return oldVal == null || (newVal != null && newVal < oldVal);
    }

    /**
     * If a load balancing strategy is used then client can actually send more requests per second than it could
     * to any single gateway because load is distributed. This method adjusts the max requests accordingly.
     */
    private Long adjustMaxRequests(int totalNumberOfClients, int numberOfClientsInOneRound, Long maxRequests) {
        if (maxRequests == null) {
            return null;
        }
        double percentageOfClientsTakingRequest = ((double) totalNumberOfClients) / numberOfClientsInOneRound;
        return (long) (maxRequests * percentageOfClientsTakingRequest);
    }

    public Long getMaximumLevel() {
        return maxLevel;
    }

    public HashAlgorithm getAggregationAlgorithm() {
        return aggregationAlgorithm;
    }

    public Long getAggregationPeriod() {
        return aggregationPeriod;
    }

    public Long getMaximumRequests() {
        return maxRequests;
    }

    public List<String> getParents() {
        return parents;
    }

}
