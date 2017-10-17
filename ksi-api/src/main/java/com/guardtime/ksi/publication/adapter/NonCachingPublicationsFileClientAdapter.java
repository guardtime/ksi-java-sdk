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

package com.guardtime.ksi.publication.adapter;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.PublicationsFileFactory;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;

/**
 * An adapter for publications file client. The publications file is fetched over the network on each KSI request
 * that needs a publication file.
 */
public class NonCachingPublicationsFileClientAdapter implements PublicationsFileClientAdapter {

    private final KSIPublicationsFileClient publicationsFileClient;
    private final PublicationsFileFactory publicationsFileFactory;

    /**
     * @param publicationsFileClient
     *         The publications file client that fetches the file.
     * @param publicationsFileFactory
     *         factory to use to parse publications file
     */
    public NonCachingPublicationsFileClientAdapter(KSIPublicationsFileClient publicationsFileClient, PublicationsFileFactory publicationsFileFactory) {
        this.publicationsFileClient = publicationsFileClient;
        this.publicationsFileFactory = publicationsFileFactory;
    }

    public PublicationsFile getPublicationsFile() throws KSIException {
        Future<ByteBuffer> data = publicationsFileClient.getPublicationsFile();
        return publicationsFileFactory.create(new ByteArrayInputStream(data.getResult().array()));
    }

    public KSIPublicationsFileClient getPublicationsFileClient() {
        return publicationsFileClient;
    }
}
