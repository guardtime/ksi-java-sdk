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

package com.guardtime.ksi.unisignature;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.tlv.TLVElement;

import java.io.InputStream;
import java.util.List;

/**
 * Interface for creating keyless signatures. Implementation of this class can be used to get instance of {@link
 * KSISignature}.
 */
public interface KSISignatureFactory {

    /**
     * Creates keyless uni-signature from input stream.
     *
     * @param input
     *         input stream to be used to createSignature data
     * @return instance of {@link KSISignature}
     * @throws KSIException
     *         when error occurs (e.g input data is invalid)
     */
    KSISignature createSignature(InputStream input) throws KSIException;


    /**
     * Creates keyless uni-signature from input TLV element.
     *
     * @param element
     *         instance of {@link TLVElement}. not null
     * @param originalInputHash - original input hash. It is used to verify signature if it is present.
     * @return instance of {@link KSISignature}
     * @throws KSIException
     *         when error occurs (e.g input data is invalid)
     */
    KSISignature createSignature(TLVElement element, DataHash originalInputHash) throws KSIException;

    /**
     * Creates keyless uni-signature from input TLV element.
     *
     * @param element
     *         instance of {@link TLVElement}. not null
     * @param originalInputHash - original input hash. It is used to verify signature if it is present.
     * @param level - local aggregation tree height
     * @return instance of {@link KSISignature}
     * @throws KSIException
     *         when error occurs (e.g input data is invalid)
     */
    KSISignature createSignature(TLVElement element, DataHash originalInputHash, long level) throws KSIException;

    /**
     * Creates keyless uni-signature from given elements.
     *
     * @param aggregationHashChains
     *         list of aggregation hash chain element. not null
     * @param calendarHashChain
     *         calendar hash chain element. not null.
     * @param authenticationRecord
     *         calendar hash chain authentication element.
     * @param publicationRecord
     *         signature publication record.
     * @param rfc3161Record
     *         signature RFC3161 record
     * @return instance of {@link KSISignature}
     * @throws KSIException
     *         when error occurs (e.g input data is invalid)
     */
    KSISignature createSignature(List<AggregationHashChain> aggregationHashChains, CalendarHashChain calendarHashChain, CalendarAuthenticationRecord authenticationRecord, PublicationRecord publicationRecord, RFC3161Record rfc3161Record) throws KSIException;

}
