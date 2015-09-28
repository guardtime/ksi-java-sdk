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
package com.guardtime.ksi.publication;


import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.publication.inmemory.CertificateNotFoundException;

import java.security.cert.Certificate;
import java.util.Date;

/**
 * <p> KSI trust store provides trusted certificates and publications for verifying keyless signatures. It provides
 * methods for getting trusted certificates for verifying authentication records and a list of publications for
 * verifying calendar hash chains.</p>
 *
 * @see PublicationsFile
 */
public interface PublicationsFile {

    /**
     * Finds and returns certificate form trust store by certificate ID.
     *
     * @param certificateId
     *         certificate id to search for
     * @return certificate instance of {@link Certificate}
     * @throws CertificateNotFoundException
     *         if certificate with given id wasn't found
     */
    Certificate findCertificateById(byte[] certificateId) throws CertificateNotFoundException;

    /**
     * This method is used to get the "closest" publication after the input time.
     *
     * @param publicationTime
     *         time to be used to find the closest publication
     * @return instance of {@link PublicationRecord} if the closest publication exists. null otherwise.
     */
    PublicationRecord getPublicationRecord(Date publicationTime);

    /**
     * This method is used to get the newest publication from publications file.
     *
     * @return returns the newest publications
     * @throws KSIException
     *         when error occurs
     */
    PublicationRecord getLatestPublication() throws KSIException;

    /**
     * @return human readable description for this KSI Trust provider
     */
    String getName();

}
