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

package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.CalendarHashChainLink;
import com.guardtime.ksi.unisignature.inmemory.InvalidCalendarHashChainException;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.List;
import java.util.ListIterator;

/**
 * Verifies that calendar hash chain registration time (calculated from the shape of the calendar
 * hash chain) equals to calendar hash chain aggregation time. If calendar hash chain is missing then status {@link
 * VerificationResultCode#OK} will be returned.
 */
public class CalendarHashChainRegistrationTimeRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(CalendarHashChainRegistrationTimeRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        if (context.getCalendarHashChain() == null) {
            return VerificationResultCode.OK;
        }

        Date aggregationTime = context.getCalendarHashChain().getAggregationTime();
        Date registrationTime = calculateRegistrationTime(context.getCalendarHashChain());
        if (aggregationTime.equals(registrationTime)) {
            return VerificationResultCode.OK;
        }
        LOGGER.info("Invalid calendar hash chain registration time. Expected {}, calculated {}", aggregationTime.getTime(), registrationTime.getTime());
        return VerificationResultCode.FAIL;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_05;
    }

    /**
     * Calculates the time when the signature was registered in the KSI hash calendar.
     */
    private Date calculateRegistrationTime(CalendarHashChain calendarHashChain) throws InvalidCalendarHashChainException {
        List<CalendarHashChainLink> chain = calendarHashChain.getChainLinks();
        long r = calendarHashChain.getPublicationTime().getTime() / 1000; // publication time in seconds
        long t = 0;
        // iterate over the chain in reverse
        ListIterator<CalendarHashChainLink> li = chain.listIterator(chain.size());
        while (li.hasPrevious()) {
            if (r <= 0) {
                LOGGER.warn("Calendar hash chain shape is inconsistent with publication time");
                r = 0;
                return new Date(0);
            }
            CalendarHashChainLink link = li.previous();

            if (!link.isRightLink()) {
                r = highBit(r) - 1;
            } else {
                t = t + highBit(r);
                r = r - highBit(r);
            }
        }

        if (r != 0) {
            LOGGER.warn("Calendar hash chain shape inconsistent with publication time");
            t = 0;
        }

        return new Date(t*1000);
    }
    /**
     * Returns the value of the highest 1-bit in r, which is also the highest integral power of 2 that is less than or
     * equal to r, or 2^floor(log2(r)).
     *
     * @param r
     *         input value
     * @return value of the highest 1-bit in r
     */
    private long highBit(long r) {
        return 1L << (63 - Long.numberOfLeadingZeros(r));
    }

}
