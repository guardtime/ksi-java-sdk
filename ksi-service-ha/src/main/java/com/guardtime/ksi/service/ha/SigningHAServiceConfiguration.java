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
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

class SigningHAServiceConfiguration implements AggregatorConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(SigningHAServiceConfiguration.class);

    private static final int MIN_MAX_REQS = 0;
    private static final int MAX_MAX_REQS = 16000;
    private static final int MIN_MAX_LEVEL = 0;
    private static final int MAX_MAX_LEVEL = 20;
    private static final int MIN_AGGR_PERIOD = 100;
    private static final int MAX_AGGR_PERIOD = 20000;

    private final Long maxLevel;
    private final HashAlgorithm aggrAlgorithm;
    private final Long aggrPeriod;
    private final Long maxRequests;
    private final List<String> parents;

    /**
     * Creates a new {@link SigningHAServiceConfiguration} with properties from the given configuration.
     *
     * @param configuration May not be null.
     */
    SigningHAServiceConfiguration(AggregatorConfiguration configuration) {
        Util.notNull(configuration, "SigningHAServiceConfiguration configuration to copy");
        this.maxLevel = normalizeMaxLevel(configuration.getMaximumLevel());
        this.aggrPeriod = normalizeAggregationPeriod(configuration.getAggregationPeriod());
        this.maxRequests = normalizeMaxRequests(configuration.getMaximumRequests());
        this.aggrAlgorithm = configuration.getAggregationAlgorithm();
        this.parents = configuration.getParents();
    }

    /**
     * Consolidates two configurations to make the maximum out of them. Neither of the configurations may be null.
     */
    SigningHAServiceConfiguration(AggregatorConfiguration c1, AggregatorConfiguration c2) {
        Util.notNull(c1, "SigningHAServiceConfiguration first configuration to consolidate");
        Util.notNull(c2, "SigningHAServiceConfiguration second configuration to consolidate");

        Long c1MaxLevel = normalizeMaxLevel(c1.getMaximumLevel());
        Long c2MaxLevel = normalizeMaxLevel(c2.getMaximumLevel());
        this.maxLevel = HAConfUtil.isBigger(c1MaxLevel, c2MaxLevel) ? c2MaxLevel : c1MaxLevel;

        Long c1AggrPeriod = normalizeAggregationPeriod(c1.getAggregationPeriod());
        Long c2AggrPeriod = normalizeAggregationPeriod(c2.getAggregationPeriod());
        this.aggrPeriod = HAConfUtil.isSmaller(c1AggrPeriod, c2AggrPeriod) ? c2AggrPeriod : c1AggrPeriod;

        Long c1MaxReqs = normalizeMaxRequests(c1.getMaximumRequests());
        Long c2MaxReqs = normalizeMaxRequests(c2.getMaximumRequests());
        this.maxRequests = HAConfUtil.isBigger(c1MaxReqs, c2MaxReqs) ? c2MaxReqs : c1MaxReqs;

        this.aggrAlgorithm = c1.getAggregationAlgorithm() == null ? c2.getAggregationAlgorithm() : c1.getAggregationAlgorithm();
        this.parents = c1.getParents() == null ? c2.getParents() : c1.getParents();
    }

    public Long getMaximumLevel() {
        return maxLevel;
    }

    public HashAlgorithm getAggregationAlgorithm() {
        return aggrAlgorithm;
    }

    public Long getAggregationPeriod() {
        return aggrPeriod;
    }

    public Long getMaximumRequests() {
        return maxRequests;
    }

    public List<String> getParents() {
        return parents;
    }

    private Long normalizeMaxRequests(Long maxRequests) {
        if (isMaxRequestsSane(maxRequests)) {
            return maxRequests;
        } else {
            logger.warn("Received max requests '{}' from an aggregator. Will not use it as only values between {} and {} are considered sane.", maxRequests, MIN_MAX_REQS, MAX_MAX_REQS);
            return null;
        }
    }

    private Long normalizeMaxLevel(Long maxLevel) {
        if (isMaxLevelSane(maxLevel)) {
            return maxLevel;
        } else {
            logger.warn("Received max level '{}' from an aggregator. Will not use it as only values between {} and {} are considered sane.", maxLevel, MIN_MAX_LEVEL, MAX_MAX_LEVEL);
            return null;
        }
    }

    private Long normalizeAggregationPeriod(Long maxLevel) {
        if (isAggregationPeriodSane(maxLevel)) {
            return maxLevel;
        } else {
            logger.warn("Received aggregation period '{}' from an aggregator. Will not use it as only values between {} and {} are considered sane.", maxLevel, MIN_AGGR_PERIOD, MAX_AGGR_PERIOD);
            return null;
        }
    }

    private boolean isMaxRequestsSane(Long maxRequests) {
        return maxRequests == null || (maxRequests > MIN_MAX_REQS && maxRequests <= MAX_MAX_REQS);
    }

    private boolean isMaxLevelSane(Long maxLevel) {
        return maxLevel == null || (maxLevel >= MIN_MAX_LEVEL && maxLevel <= MAX_MAX_LEVEL);
    }

    private boolean isAggregationPeriodSane(Long aggrPeriod) {
        return aggrPeriod == null || (aggrPeriod >= MIN_AGGR_PERIOD && aggrPeriod <= MAX_AGGR_PERIOD);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AggregatorConfiguration)) return false;

        AggregatorConfiguration that = (AggregatorConfiguration) o;

        return Util.equals(this.getAggregationAlgorithm(), that.getAggregationAlgorithm()) &&
                Util.equals(this.getAggregationPeriod(), that.getAggregationPeriod()) &&
                Util.equals(this.getMaximumLevel(), that.getMaximumLevel()) &&
                Util.equals(this.getMaximumRequests(), that.getMaximumRequests()) &&
                Util.equalsIgnoreOrder(this.getParents(), that.getParents());
    }

    @Override
    public String toString() {
        return "SigningHAServiceConfiguration{" +
                "maxLevel=" + maxLevel +
                ", aggrAlgorithm=" + aggrAlgorithm +
                ", aggrPeriod=" + aggrPeriod +
                ", maxRequests=" + maxRequests +
                ", parents=" + parents +
                '}';
    }
}
