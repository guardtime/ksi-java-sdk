/*
 * Copyright 2013-2015 Guardtime, Inc.
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
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * This rule is used to verify that calendar hash chain registration time (calculated from the shape of the calendar
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
        Date registrationTime = context.getCalendarHashChain().getRegistrationTime();
        if (aggregationTime.equals(registrationTime)) {
            return VerificationResultCode.OK;
        }
        LOGGER.info("Invalid calendar hash chain registration time. Expected {}, calculated {}", aggregationTime.getTime(), registrationTime.getTime());
        return VerificationResultCode.FAIL;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.INT_05;
    }

}
