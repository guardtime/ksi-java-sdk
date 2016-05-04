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

import java.util.LinkedList;
import java.util.List;

/**
 * This rule checks that: <ul> <li>the extended calendar hash chain contains the same count of right links</li> <li>the
 * extended calendar hash chain right links are equal to the not extended calendar hash chain right links</li> </ul>
 */
public class ExtendedSignatureCalendarHashChainRightLinksMatchesRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExtendedSignatureCalendarHashChainRightLinksMatchesRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        KSISignature signature = context.getSignature();
        CalendarHashChain extendedCalendarHashChain = context.getExtendedCalendarHashChain(signature.getCalendarHashChain().getPublicationTime());

        List<CalendarHashChainLink> signatureRightLinks = getRightLinks(signature.getCalendarHashChain());
        List<CalendarHashChainLink> extendedSignatureRightLinks = getRightLinks(extendedCalendarHashChain);

        if (signatureRightLinks.size() != extendedSignatureRightLinks.size()) {
            LOGGER.info("Extended signature calendar hash chain right links count does not match with initial signature calendar hash chain right links count. Expected {}, found {}.", signatureRightLinks.size(), extendedSignatureRightLinks.size());
            return VerificationResultCode.FAIL;
        }

        for (int i = 0; i < extendedSignatureRightLinks.size(); i++) {
            CalendarHashChainLink link = extendedSignatureRightLinks.get(i);
            CalendarHashChainLink initialLink = signatureRightLinks.get(i);
            if (!link.equals(initialLink)) {
                LOGGER.info("Extended signature contains different calendar hash chain right link");
                return VerificationResultCode.FAIL;
            }
        }

        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.CAL_04;
    }

    private List<CalendarHashChainLink> getRightLinks(CalendarHashChain hashChain) {
        List<CalendarHashChainLink> returnable = new LinkedList<CalendarHashChainLink>();
        for (CalendarHashChainLink link : hashChain.getChainLinks()) {
            if (link.isRightLink()) {
                returnable.add(link);
            }
        }
        return returnable;
    }

}
