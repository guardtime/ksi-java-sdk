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
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.unisignature.CalendarHashChain;

/**
 * Verifies that publications file publication hash matches with extender response calendar root hash.
 */
public class PublicationsFilePublicationHashMatchesExtenderResponseRule extends BaseRule {

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        PublicationsFile publicationsFile = context.getPublicationsFile();
        PublicationRecord publicationRecord = publicationsFile.getPublicationRecord(context.getCalendarHashChain().getAggregationTime());
        CalendarHashChain extendedCalendarHashChain = context.getExtendedCalendarHashChain(publicationRecord.getPublicationTime());
        if (!publicationRecord.getPublicationData().getPublicationDataHash().equals(extendedCalendarHashChain.getOutputHash())) {
            return VerificationResultCode.FAIL;
        }
        return VerificationResultCode.OK;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.PUB_01;
    }
}
