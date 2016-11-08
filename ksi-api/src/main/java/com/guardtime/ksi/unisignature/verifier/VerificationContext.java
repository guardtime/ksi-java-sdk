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

package com.guardtime.ksi.unisignature.verifier;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.unisignature.*;

import java.security.cert.Certificate;
import java.util.Date;

/**
 * This interface represents a verification context. Verification context contains information needed for verification.
 */
public interface VerificationContext {

    /**
     * Returns signature to be verified.
     */
    KSISignature getSignature();

    /**
     * Returns extended signature calendar hash chain
     *
     * @param publicationTime
     *         publication time to extend
     * @return instance of extended signature calendar hash chain
     * @throws KSIException
     *         when extending fails
     */
    CalendarHashChain getExtendedCalendarHashChain(Date publicationTime) throws KSIException;

    /**
     * Returns extended calendar hash chain. The signature is extended to a top of the calendar.
     *
     * @return instance  of extended calendar hash chain
     * @throws KSIException
     *         when extending fails.
     */
    CalendarHashChain getExtendedCalendarHashChain() throws KSIException;

    /**
     * Returns user provided publication. If user has not provided the publication then this method returns null.
     */
    PublicationData getUserProvidedPublication();

    /**
     * Returns the document hash provided by the user or calculated from the input data. Returns null when document is
     * missing.
     */
    DataHash getDocumentHash();

    /**
     * True when extending is allowed when using {@link com.guardtime.ksi.unisignature.verifier.policies.UserProvidedPublicationBasedVerificationPolicy}
     * or {@link com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy}
     */
    boolean isExtendingAllowed();

    /**
     * Returns instance of KSI publications file
     */
    PublicationsFile getPublicationsFile();

    /**
     * This method is used to get certificate from {@link PublicationsFile}.
     *
     * @param certificateId
     *         certificate id
     * @return instance of {@link Certificate} or null
     */
    Certificate getCertificate(byte[] certificateId);

    /**
     * Helper method. Same as {@link KSISignature#getAggregationHashChains()}
     */
    AggregationHashChain[] getAggregationHashChains();

    /**
     * Helper method. Same as {@link KSISignature#getCalendarHashChain()}
     */
    CalendarHashChain getCalendarHashChain();

    /**
     * Helper method.
     */
    AggregationHashChain getLastAggregationHashChain();

    /**
     * Helper method. Same as {@link KSISignature#getCalendarAuthenticationRecord()}
     */
    CalendarAuthenticationRecord getCalendarAuthenticationRecord();

    /**
     * Helper method. Same as {@link KSISignature#getRfc3161Record()}
     */
    RFC3161Record getRfc3161Record();

    /**
     * Helper method. Same as {@link KSISignature#getPublicationRecord()}
     */
    PublicationRecord getPublicationRecord();

    /**
     * Sets the pdu factory used in verification process
     */
    void setPduFactory(PduFactory pduFactory);

    /**
     * Sets the KSISignatureComponentFactory used in verification process
     */
    void setKsiSignatureComponentFactory(KSISignatureComponentFactory signatureComponentFactory);

}
