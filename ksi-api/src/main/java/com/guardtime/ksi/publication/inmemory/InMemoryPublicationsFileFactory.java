/*
 * Copyright 2013-2018 Guardtime, Inc.
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

package com.guardtime.ksi.publication.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.PublicationsFileFactory;
import com.guardtime.ksi.trust.CMSSignature;
import com.guardtime.ksi.trust.CMSSignatureVerifier;
import com.guardtime.ksi.trust.PKITrustStore;

import java.io.InputStream;

/**
 * In memory implementation of the {@link PublicationsFileFactory}.
 *
 * @see PublicationsFileFactory
 */
public class InMemoryPublicationsFileFactory implements PublicationsFileFactory {

    private PKITrustStore trustStore;

    public InMemoryPublicationsFileFactory(PKITrustStore trustStore) throws KSIException {
        if (trustStore == null) {
            throw new KSIException("Invalid input parameter. PKI trust store must be present");
        }
        this.trustStore = trustStore;
    }

    /**
     * This method is used to read publications file from input stream. Input stream must be present and must be signed
     * by trusted PKI certificate.
     *
     * @param input
     *         input stream to be used to read publications file data
     * @return returns instance of {@link PublicationsFile}
     * @throws KSIException
     *         when error occurs
     */
    public PublicationsFile create(InputStream input) throws KSIException {
        InMemoryPublicationsFile publicationsFile = new InMemoryPublicationsFile(input);

        CMSSignature signature = publicationsFile.getSignature();
        CMSSignatureVerifier verifier = new CMSSignatureVerifier(trustStore);
        verifier.verify(signature);
        return publicationsFile;
    }

}
