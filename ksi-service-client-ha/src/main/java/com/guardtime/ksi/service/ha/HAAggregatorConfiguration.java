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

            if (isNewValSmaller(maxRequests, confMaxRequests)) {
                maxRequests = confMaxRequests;
            }
            if (isNewValBigger(aggregationPeriod, confAggregationPeriod)) {
                aggregationPeriod = confAggregationPeriod;
            }
            if (isNewValSmaller(maxLevel, confMaxLevel)) {
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

    private boolean isNewValBigger(Long oldVal, Long newVal) {
        return oldVal == null || (newVal != null && newVal > oldVal);
    }

    private boolean isNewValSmaller(Long oldVal, Long newVal) {
        return oldVal == null || (newVal != null && newVal < oldVal);
    }

    private Long adjustMaxRequests(int totalNumberOfClients, int numberOfClientsInOneRound, Long subConfMaximumRequests) {
        return subConfMaximumRequests == null ?
                null :
                (long) (subConfMaximumRequests * ((double) totalNumberOfClients / numberOfClientsInOneRound));
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
