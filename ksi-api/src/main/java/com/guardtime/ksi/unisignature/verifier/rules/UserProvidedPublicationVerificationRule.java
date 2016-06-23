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
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This rule is used verify that user provided publication equals to publication inside the signature.
 */
public class UserProvidedPublicationVerificationRule extends BaseRule {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserProvidedPublicationVerificationRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        PublicationData publication = context.getUserProvidedPublication();
        PublicationRecord signaturePublicationRecord = context.getPublicationRecord();
        PublicationData signaturePublicationData = signaturePublicationRecord.getPublicationData();
        if (!publication.equals(signaturePublicationData)) {
            LOGGER.info("User provided publication '{}' does not equal to signature publication '{}'", publication, signaturePublicationData);
            return VerificationResultCode.NA;
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.GEN_2;
    }
}
