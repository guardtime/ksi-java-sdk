/*
 * Copyright 2017 Guardtime, Inc.
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
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.CalendarHashChainLink;
import com.guardtime.ksi.unisignature.inmemory.InvalidCalendarHashChainException;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * Verifies if any of the response calendar hash chain aggregation hash algorithms (derived from the left link)
 * were deprecated at the publication time.
 */
public class CalendarHashChainAlgorithmDeprecatedExtenderResponseRule extends BaseRule {

    private static final Logger logger = LoggerFactory.getLogger(CalendarHashChainAlgorithmDeprecatedExtenderResponseRule.class);

    public VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
        PublicationsFile publicationsFile = context.getPublicationsFile();
        PublicationRecord publicationRecord =
                publicationsFile.getPublicationRecord(context.getSignature().getAggregationTime());
        CalendarHashChain extendedCalendarHashChain =
                context.getExtendedCalendarHashChain(publicationRecord.getPublicationTime());
        if (isAlgorithmsDeprecated(extendedCalendarHashChain, publicationRecord.getPublicationTime())) {
            return VerificationResultCode.NA;
        }
        return VerificationResultCode.OK;
    }

    private boolean isAlgorithmsDeprecated(CalendarHashChain calendarHashChain, Date publicationTime)
            throws InvalidCalendarHashChainException {
        for (CalendarHashChainLink link : calendarHashChain.getChainLinks()) {
            if (!link.isRightLink() && link.getDataHash().getAlgorithm().isDeprecated(publicationTime)) {
                logger.info("Calendar hash chain aggregation hash algorithm {} is deprecated.",
                        link.getDataHash().getAlgorithm().getName());
                return true;
            }
        }
        return false;
    }

    public VerificationErrorCode getErrorCode() {
        return VerificationErrorCode.GEN_02;
    }

}
