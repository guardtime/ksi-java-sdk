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

import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.List;


/**
 * {@link ExtenderConfiguration} that can be used to consolidate multiple {@link ExtendingHAService} subclients configurations.
 */
class ExtendingHAServiceConfiguration implements ExtenderConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(ExtendingHAServiceConfiguration.class);

    private static final Date JAN_01_2006_00_00_00 = new Date(1136073600000L);
    private static final int MIN_MAX_REQS = 0;
    private static final int MAX_MAX_REQS = 16000;

    private final Long maxRequests;
    private final List<String> parents;
    private final Date calFirstTime;
    private final Date calLastTime;

    /**
     * Creates a new {@link ExtendingHAServiceConfiguration} by copying all the properties from the given configuration.
     * If any of the given properties is not sane then it's left unset.
     *
     * @param configuration may not be null.
     */
    ExtendingHAServiceConfiguration(ExtenderConfiguration configuration) {
        Util.notNull(configuration, "ExtendingHAServiceConfiguration configuration to copy");
        this.maxRequests = normalizeMaxRequests(configuration.getMaximumRequests());
        this.calFirstTime = normalizeCalFirstTime(configuration.getCalendarFirstTime(), configuration.getCalendarLastTime());
        this.calLastTime = normalizeCalLastTime(configuration.getCalendarLastTime(), configuration.getCalendarFirstTime());
        this.parents = configuration.getParents();
    }

    /**
     * Consolidates two configurations to make the maximum out of them. Neither of the configurations may be null.
     */
    ExtendingHAServiceConfiguration(ExtenderConfiguration c1, ExtenderConfiguration c2) {
        Util.notNull(c1, "ExtendingHAServiceConfiguration first configuration to consolidate");
        Util.notNull(c2, "ExtendingHAServiceConfiguration second configuration to consolidate");

        Long c1MaxReqs = normalizeMaxRequests(c1.getMaximumRequests());
        Long c2MaxReqs = normalizeMaxRequests(c2.getMaximumRequests());
        this.maxRequests = HAConfUtil.isBigger(c1MaxReqs, c2MaxReqs) ? c2MaxReqs : c1MaxReqs;

        Date c1CalFirstTime = normalizeCalFirstTime(c1.getCalendarFirstTime(), c1.getCalendarLastTime());
        Date c2CalFirstTime = normalizeCalFirstTime(c2.getCalendarFirstTime(), c2.getCalendarLastTime());
        this.calFirstTime = HAConfUtil.isBefore(c1CalFirstTime, c2CalFirstTime) ? c2CalFirstTime : c1CalFirstTime;

        Date c1CalLastTime = normalizeCalLastTime(c1.getCalendarLastTime(), c1.getCalendarFirstTime());
        Date c2CalLastTime = normalizeCalLastTime(c2.getCalendarLastTime(), c2.getCalendarFirstTime());
        this.calLastTime = HAConfUtil.isAfter(c1CalLastTime, c2CalLastTime) ? c2CalLastTime : c1.getCalendarLastTime();

        List<String> c1Parents = c1.getParents();
        List<String> c2Parents = c2.getParents();
        this.parents = c1Parents == null ? c2Parents : c1Parents;
    }

    public Long getMaximumRequests() {
        return maxRequests;
    }

    public List<String> getParents() {
        return parents;
    }

    public Date getCalendarFirstTime() {
        return calFirstTime;
    }

    public Date getCalendarLastTime() {
        return calLastTime;
    }

    private Long normalizeMaxRequests(Long maxRequests) {
        if (isMaxRequestsSane(maxRequests)) {
            return maxRequests;
        } else {
            logger.warn("Received max requests '{}' from an extender. Will not use it as only values between {} and {} are considered sane.", maxRequests, MIN_MAX_REQS, MAX_MAX_REQS);
            return null;
        }
    }

    private Date normalizeCalFirstTime(Date calFirstTime, Date calLastTime) {
        if (isCalFirstTimeSane(calFirstTime, calLastTime)) {
            return calFirstTime;
        } else {
            logger.warn("Received calendar first time '{}' from an extender. Will not use it as it is not sane. Calendar first time has to be after {} and before calendar last time ({}).",
                    calFirstTime, JAN_01_2006_00_00_00, calLastTime);
            return null;
        }
    }

    private Date normalizeCalLastTime(Date calLastTime, Date calFirstTime) {
        if (isCalLastTimeSane(calLastTime, calFirstTime)) {
            return calLastTime;
        } else {
            logger.warn("Received calendar last time '{}' from an extender. Will not use it as it is not sane. Calendar last time has to be after {} and after calendar first time ({}).",
                    calLastTime, JAN_01_2006_00_00_00, calFirstTime);
            return null;
        }
    }

    private boolean isMaxRequestsSane(Long maxRequests) {
        return maxRequests == null || (maxRequests > MIN_MAX_REQS && maxRequests <= MAX_MAX_REQS);
    }

    private boolean isCalFirstTimeSane(Date calFirstTime, Date calLastTime) {
        return (calFirstTime == null && calLastTime == null) ||
                (calFirstTime != null && calLastTime != null && calFirstTime.after(JAN_01_2006_00_00_00) && !calFirstTime.after(calLastTime));
    }

    private boolean isCalLastTimeSane(Date calLastTime, Date calFirstTime) {
        return (calFirstTime == null && calLastTime == null) ||
                (calFirstTime != null && calLastTime != null && calLastTime.after(JAN_01_2006_00_00_00) && !calLastTime.before(calFirstTime));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ExtenderConfiguration)) return false;

        ExtenderConfiguration that = (ExtenderConfiguration) o;

        return Util.equals(this.getCalendarFirstTime(), that.getCalendarFirstTime()) &&
                Util.equals(this.getCalendarLastTime(), that.getCalendarLastTime()) &&
                Util.equals(this.getMaximumRequests(), that.getMaximumRequests()) &&
                Util.equalsIgnoreOrder(this.getParents(), that.getParents());
    }

    @Override
    public String toString() {
        return "ExtendingHAServiceConfiguration{" +
                "maxRequests=" + maxRequests +
                ", parents=" + parents +
                ", calFirstTime=" + calFirstTime +
                ", calLastTime=" + calLastTime +
                '}';
    }
}
