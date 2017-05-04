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
import com.guardtime.ksi.pdu.SubclientConfiguration;

import java.util.List;

import static com.guardtime.ksi.service.ha.HAConfUtil.hasMoreContents;
import static com.guardtime.ksi.service.ha.HAConfUtil.isBigger;
import static com.guardtime.ksi.service.ha.HAConfUtil.isSmaller;

/**
 * Aggregated configuration based on multiple configurations and HAClient settings.
 */
class HAAggregatorConfiguration implements AggregatorConfiguration {

    private List<SubclientConfiguration<AggregatorConfiguration>> subclientConfigurations;
    private Long maxRequests;
    private List<String> parents;
    private Long aggregationPeriod;
    private HashAlgorithm aggregationAlgorithm;
    private Long maxLevel;

    /**
     * @param confs
     *          All the configurations that were received from subclients
     */
    HAAggregatorConfiguration(List<SubclientConfiguration<AggregatorConfiguration>> confs) {
        this.subclientConfigurations = confs;
        for (SubclientConfiguration<AggregatorConfiguration> confRequest : confs) {
            if (confRequest.isSucceeded()) {
                AggregatorConfiguration conf = confRequest.getConfiguration();
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
                if (hasMoreContents(parents, confParents)) {
                    parents = confParents;
                }
            }
        }
    }

    /**
     * @return Smallest maximum level of all the subconfigurations.
     */
    public Long getMaximumLevel() {
        return maxLevel;
    }

    /**
     * @return Random aggregation algorithm of all the subconfigurations. Non-null values are preferred.
     */
    public HashAlgorithm getAggregationAlgorithm() {
        return aggregationAlgorithm;
    }

    /**
     * @return Biggest aggregation period of all the subconfigurations.
     */
    public Long getAggregationPeriod() {
        return aggregationPeriod;
    }

    /**
     * @return Smallest maxRequests of all subconfigurations.
     */
    public Long getMaximumRequests() {
        return maxRequests;
    }

    /**
     * @return Largest set of parents.
     */
    public List<String> getParents() {
        return parents;
    }

    /**
     * @return List of all subclients configuration request results.
     */
    public List<SubclientConfiguration<AggregatorConfiguration>> getSubConfigurations() {
        return subclientConfigurations;
    }

}
