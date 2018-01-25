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

package com.guardtime.ksi.publication.adapter;

import com.guardtime.ksi.publication.inmemory.InMemoryPublicationsFileFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static org.mockito.Mockito.*;
import static org.mockito.internal.verification.VerificationModeFactory.times;
import static org.testng.AssertJUnit.assertNotNull;


public class CachingPublicationsFileClientAdapterTest extends AbstractPublicationsFileClientAdapterTest {

    private static final long CACHE_EXPIRATION_TIME = 2000L;

    private CachingPublicationsFileClientAdapter adapter;

    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        this.adapter = new CachingPublicationsFileClientAdapter(mockedPublicationsFileClient, new InMemoryPublicationsFileFactory(mockedTrustStore), CACHE_EXPIRATION_TIME);
    }

    @Test
    public void tesCachingPublicationsFileAdapterReturnsPublicationFile() throws Exception {
        assertNotNull(adapter.getPublicationsFile());
    }

    @Test
    public void testCachingPublicationsFileAdapterCachesRequest() throws Exception {
        adapter.getPublicationsFile();
        adapter.getPublicationsFile();
        verify(mockedPublicationsFileClient, times(1)).getPublicationsFile();
    }

    @Test
    public void testCachingPublicationsFileAdapterUpdatesCache() throws Exception {
        CachingPublicationsFileClientAdapter spy = spy(adapter);
        doReturn(true).doReturn(false).doReturn(true).when(spy).isCacheUpdateNeeded();
        spy.getPublicationsFile();
        spy.getPublicationsFile();
        spy.getPublicationsFile();
        verify(mockedPublicationsFileClient, times(2)).getPublicationsFile();
    }

}
