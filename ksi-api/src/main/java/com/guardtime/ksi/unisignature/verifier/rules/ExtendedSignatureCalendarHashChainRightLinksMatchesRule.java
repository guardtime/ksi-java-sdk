/*
 * Copyright 2013-2018 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 *  "Guardtime" and "KSI" are trademarks or registered trademarks of
 *  Guardtime, Inc., and no license to trademarks is granted; Guardtime
 *  reserves and retains all trademark rights.
 *
 */

package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.guardtime.ksi.unisignature.CalendarHashChainUtil.areCalendarHashChainRightLinksConsistent;

/**
 * Checks that: <ul> <li>the extended calendar hash chain contains the same count of right
 * links</li> <li>the extended calendar hash chain right links are equal to the not extended
 * calendar hash chain right links</li> </ul>
 */
public class ExtendedSignatureCalendarHashChainRightLinksMatchesRule extends BaseRule {

    private static final Logger logger = LoggerFactory.getLogger(ExtendedSignatureCalendarHashChainRightLinksMatchesRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        KSISignature signature = context.getSignature();
        CalendarHashChain extendedCalendarHashChain = context.getExtendedCalendarHashChain(signature.getCalendarHashChain().getPublicationTime());

        if (areCalendarHashChainRightLinksConsistent(signature.getCalendarHashChain(), extendedCalendarHashChain)) {
            return VerificationResultCode.OK;
        } else {
            logger.info("Extended calendar hash chain right links do not match with signature calendar hash chain right links");
            return VerificationResultCode.FAIL;
        }
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.CAL_04;
    }
}
