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
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.CalendarHashChain;

/**
 * Checks that reproduced calendar hash chain (reproduced by sending extension request with the same
 * aggregation and publication time as the attached calendar chain) matches with the already present calendar hash chain
 * root hash.
 * <p/>
 * If signature (that is being validated), does not contain calendar hash chain then status {@link
 * VerificationResultCode#OK} will be returned.
 */
public class ExtendedSignatureCalendarChainRootHashRule extends BaseRule {

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        CalendarHashChain calendarHashChain = context.getCalendarHashChain();
        CalendarHashChain extendedSignatureCalendarHashChain = context.getExtendedCalendarHashChain(calendarHashChain.getPublicationTime());

        if (calendarHashChain.getOutputHash().equals(extendedSignatureCalendarHashChain.getOutputHash())) {
            return VerificationResultCode.OK;
        }

        return VerificationResultCode.FAIL;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.CAL_01;
    }

}
