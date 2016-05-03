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
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.publication.PublicationsFileFactory;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;

/**
 * This is a adapter for publications file client. It's responsibility is to cache the publication file data so that it
 * would not be fetched again over the network on each KSI request that needs a publication file. Cache is loaded for
 * the first time lazily (e.g. it's not loaded until it's actually needed).
 */
public class CachingPublicationsFileClientAdapter implements PublicationsFileClientAdapter {

    private static final Logger logger = LoggerFactory.getLogger(CachingPublicationsFileClientAdapter.class);

    private final PublicationsFileFactory publicationsFileFactory;
    private final KSIPublicationsFileClient publicationsFileClient;
    private final long cacheExpirationTime;
    private long cacheLastUpdated;
    private PublicationsFile cachedPublicationsFile;

    /**
     * @param publicationsFileClient
     *         The actual publications file client that fetches the file if cache needs updating.
     * @param publicationsFileFactory
     *         factory to use to parse publications file
     * @param cacheExpirationTime
     *         The amount of time in milliseconds after which cache needs to be updated.
     */
    public CachingPublicationsFileClientAdapter(KSIPublicationsFileClient publicationsFileClient, PublicationsFileFactory publicationsFileFactory, long cacheExpirationTime) {
        this.publicationsFileClient = publicationsFileClient;
        this.publicationsFileFactory = publicationsFileFactory;
        this.cacheExpirationTime = cacheExpirationTime;
    }

    public synchronized PublicationsFile getPublicationsFile() throws KSIException {
        if (isCacheUpdateNeeded()) {
            logger.debug("Publication file cache will be updated.");
            ByteBuffer data = publicationsFileClient.getPublicationsFile().getResult();
            cachedPublicationsFile = publicationsFileFactory.create(new ByteArrayInputStream(data.array()));
            cacheLastUpdated = System.currentTimeMillis();
        } else {
            logger.debug("Returning cached publication file data.");
        }
        return cachedPublicationsFile;
    }

    public KSIPublicationsFileClient getPublicationsFileClient() {
        return publicationsFileClient;
    }

    boolean isCacheUpdateNeeded() {
        return cachedPublicationsFile == null || System.currentTimeMillis() - cacheExpirationTime >= cacheLastUpdated;
    }

}
