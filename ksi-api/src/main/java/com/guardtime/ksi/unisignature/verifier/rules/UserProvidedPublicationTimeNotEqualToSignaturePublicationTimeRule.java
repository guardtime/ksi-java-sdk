/*
 * Copyright 2013-2017 Guardtime, Inc.
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
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;

import java.util.Date;

/**
 * Verifies that user provided publication time does not equal to signature publication time
 */
public class UserProvidedPublicationTimeNotEqualToSignaturePublicationTimeRule extends BaseRule {

    @Override
    VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        Date registrationTime = context.getPublicationRecord().getPublicationTime();
        Date userPublicationTime = context.getUserProvidedPublication().getPublicationTime();
        if (registrationTime.equals(userPublicationTime)) {
            return VerificationResultCode.NA;
        }
        return VerificationResultCode.OK;
    }

    @Override
    VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.GEN_02;
    }

}
