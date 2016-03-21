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
package com.guardtime.ksi.service;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.publication.PublicationsFile;

import java.util.Date;

/**
 * KSI service interface. Contains the following services <ul> <li>signature creation service <li>signature extension
 * service <li>publications file download service </ul>
 */
public interface KSIService {

    /**
     * Creates new signature.
     *
     * @param dataHash
     *         hash to sign
     * @return signature creation Future.
     * @throws KSIProtocolException
     *         will be thrown when signature future creation fails
     */
    CreateSignatureFuture sign(DataHash dataHash) throws KSIException;

    //TODO
    CreateSignatureFuture sign(DataHash dataHash, long level) throws KSIException;

    /**
     * This method is used to send extension request to the server. {@link ExtensionRequestFuture#getResult()} method
     * can be used to get extended calendar hash chain starting from the aggregation time to publication time. When
     * publication time is missing then the most recent calendar record is used by server.
     *
     * @param aggregationTime
     *         the time of the aggregation round from which the calendar hash chain should start. must not be null.
     * @param publicationTime
     *         the time of the calendar root hash value to which the aggregation hash value should be connected by the
     *         calendar hash chain.Its absence means a request for a calendar hash chain from aggregation time to the
     *         most recent calendar record the extension server has.
     * @return signature extension Future.
     * @throws KSIException
     *         if createSignature signature future creation fails
     */
    ExtensionRequestFuture extend(Date aggregationTime, Date publicationTime) throws KSIException;

    /**
     * Execute asynchronous publications file download call.
     *
     * @return request future object
     * @throws KSIProtocolException
     *         if publications file future creation fails
     */
    Future<PublicationsFile> getPublicationsFile() throws KSIException;

}
