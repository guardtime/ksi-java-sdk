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

package com.guardtime.ksi.multisignature.file;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.unisignature.CalendarHashChain;

/**
 * {@link ReferenceChecker} implementation to check if calendar hash chain and calendar authentication record are
 * linked.
 */
final class CalendarAuthenticationRecordReferenceChecker implements ReferenceChecker<CalendarHashChain> {

    private final PublicationData publicationData;

    public CalendarAuthenticationRecordReferenceChecker(PublicationData publicationData) {
        this.publicationData = publicationData;
    }

    public boolean complies(CalendarHashChain element) throws KSIException {
        return publicationData.equals(new PublicationData(element.getPublicationTime(), element.getOutputHash()));
    }
}
