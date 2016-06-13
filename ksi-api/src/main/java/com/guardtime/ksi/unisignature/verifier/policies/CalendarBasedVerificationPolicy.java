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

package com.guardtime.ksi.unisignature.verifier.policies;

import com.guardtime.ksi.unisignature.verifier.rules.*;

/**
 * Calendar-based verification takes as input the computed output hash of aggregation hash chains and the `aggregation
 * time'. It requires on-line access to the extending service and allows verification using the calendar database as the
 * trust anchor.
 */
public class CalendarBasedVerificationPolicy extends InternalVerificationPolicy {

    private static final String TYPE_CALENDAR_BASED_POLICY = "CALENDAR_BASED_POLICY";

    public CalendarBasedVerificationPolicy() {

        Rule signatureDoesNotContainCalendarChainRule = new CompositeRule(false,
                new CalendarHashChainDoesNotExistRule(),
                new ExtendedSignatureCalendarChainInputHashRule(),
                new ExtendedSignatureCalendarChainAggregationTimeRule()
        );

        Rule alreadyExtendedSignatureRule = new CompositeRule(false,
                new CalendarHashChainExistenceRule(),
                new CompositeRule(true,
                        new CompositeRule(false,
                                new SignatureDoesNotContainPublicationRule(),
                                new ExtendedSignatureCalendarHashChainRightLinksMatchesRule()
                        ),

                        new CompositeRule(false,
                                new SignaturePublicationRecordExistenceRule(),
                                new ExtendedSignatureCalendarChainRootHashRule()
                        )
                ),
                new ExtendedSignatureCalendarChainInputHashRule(),
                new ExtendedSignatureCalendarChainAggregationTimeRule()
        );

        addRule(new CompositeRule(true, signatureDoesNotContainCalendarChainRule, alreadyExtendedSignatureRule));
    }

    public String getName() {
        return "Calendar-based verification policy";
    }

    public String getType() {
        return TYPE_CALENDAR_BASED_POLICY;
    }

}
