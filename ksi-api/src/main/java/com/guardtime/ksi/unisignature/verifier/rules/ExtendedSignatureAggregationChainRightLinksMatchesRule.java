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
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.CalendarHashChainLink;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * This rule checks that: <ul> <li>the extended signature contains the same count of right aggregation hash chain
 * links</li> <li>the extended signature right aggregation hash chain links are equal to the not extended signature
 * right links</li> </ul>
 */
public class ExtendedSignatureAggregationChainRightLinksMatchesRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExtendedSignatureAggregationChainRightLinksMatchesRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        KSISignature signature = context.getSignature();
        CalendarHashChain extendedCalendarHashChain = context.getExtendedCalendarHashChain(signature.getCalendarHashChain().getPublicationTime());

        List<CalendarHashChainLink> signatureLinks = signature.getCalendarHashChain().getChainLinks();
        List<CalendarHashChainLink> extendedSignatureLinks = extendedCalendarHashChain.getChainLinks();

        if (signatureLinks.size() != extendedSignatureLinks.size()) {
            LOGGER.info("Extended signature aggregation chain links count does not match with initial signature aggregation chain links count. Expected {}, found {}.", signatureLinks.size(), extendedSignatureLinks.size());
            return VerificationResultCode.FAIL;
        }
        for (int i = 0; i < extendedSignatureLinks.size(); i++) {
            CalendarHashChainLink link = extendedSignatureLinks.get(i);
            if (link.isRightLink()) {
                CalendarHashChainLink initialLink = signatureLinks.get(i);
                if (!link.equals(initialLink)) {
                    LOGGER.info("Extended signature contains different aggregation hash chain right link");
                    return VerificationResultCode.FAIL;
                }
            }
        }

        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.CAL_04;
    }

}
