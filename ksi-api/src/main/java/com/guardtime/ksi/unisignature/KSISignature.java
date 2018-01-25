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

package com.guardtime.ksi.unisignature;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;

import java.io.OutputStream;
import java.util.Date;

/**
 * This interface represents a keyless uni-signature. KSI signature consist of the following components: <ul> <li>One or
 * more aggregation hash chain components that together form a single continuous chain.</li> <li>At most one calendar
 * hash chain component. Represents the computation of the published hash value from the per-round root hash value.</li>
 * <li>Publication record. Contains the published hash value and bibliographic references to the media where it
 * appeared.</li> <li>Authentication record. Contains the trace of authenticating a party (e.g. a key-based signature).
 * There are two types of authentication records: one for aggregation hash chains and another for calendar hash
 * chains.</li> <li>At most one RFC 3161 compatibility record</li> </ul>
 */
public interface KSISignature {

    /**
     * Returns aggregation hash chains. Aggregation hash chains are sorted by aggregation time and aggregation chain
     * indexes. At least one aggregation hash chain is always present.
     */
    AggregationHashChain[] getAggregationHashChains();

    /**
     * Returns the signature calendar hash chain.
     */
    CalendarHashChain getCalendarHashChain();

    /**
     * Returns the signature calendar authentication record if signature isn't extended. If signature is extended the
     * null is returned.
     */
    CalendarAuthenticationRecord getCalendarAuthenticationRecord();

    /**
     * Returns the instance of signature publication record if signature is extended. Returns null if signature isn't
     * extended.
     */
    SignaturePublicationRecord getPublicationRecord();

    /**
     * An older implementation of the KSI service used the formats and protocols specified in the X.509 time-stamping
     * standard (RFC 3161). In that format, the hash value of the time-stamped datum was not signed directly, but via
     * several intermediate structures. This method returns the RFC3161 compatibility record (or null is RFC3161 record
     * isn't present).
     */
    RFC3161Record getRfc3161Record();

    /**
     * If RFC3161 compatibility record is present then RFC3161 input hash will be returned. If RFC3161 record isn't
     * present then first aggregation chain input hash will be returned.
     */
    DataHash getInputHash();

    /**
     * Returns the aggregation time.
     */
    Date getAggregationTime();

    /**
     * Returns the publication time.
     */
    Date getPublicationTime();

    /**
     * Returns an array of the identities present in all aggregation hash chains. The identities in the array are
     * ordered - the higher-aggregator identity is before lower-aggregator identity.
     */
    Identity[] getAggregationHashChainIdentity();

    /**
     * Returns true if signature contains signature publication record element.
     */
    boolean isExtended();

    /**
     * Writes {@link KSISignature} to given output stream
     *
     * @param output
     *         instance of {@link OutputStream}
     * @throws KSIException
     *         will be thrown when writing to stream fails
     */
    void writeTo(OutputStream output) throws KSIException;

}
