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
package com.guardtime.ksi.service;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.publication.adapter.NonCachingPublicationsFileClientAdapter;
import com.guardtime.ksi.publication.inmemory.InMemoryPublicationsFileFactory;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureFactory;
import org.bouncycastle.util.Store;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;

import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;

public class AbstractCommonServiceTest {

    protected static final String PUBLICATIONS_FILE_15_04_2014 = "publications.15042014.tlv";

    protected KSISigningClient mockedSigningClient;
    protected KSIExtenderClient mockedExtenderClient;
    protected KSIPublicationsFileClient mockedPublicationsFileClient;
    protected KSIServiceImpl ksiService;
    protected Future<TLVElement> mockedResponse;
    protected Future<ByteBuffer> mockedPublicationsFileResponse;
    protected PKITrustStore mockedTrustStore;

    @BeforeMethod
    public void init() throws Exception {
        mockedSigningClient = Mockito.mock(KSISigningClient.class);
        mockedExtenderClient = Mockito.mock(KSIExtenderClient.class);
        mockedPublicationsFileClient = Mockito.mock(KSIPublicationsFileClient.class);
        mockedTrustStore = Mockito.mock(PKITrustStore.class);
        Mockito.when(mockedSigningClient.getServiceCredentials()).thenReturn(TestUtil.CREDENTIALS_ANONYMOUS);
        Mockito.when(mockedExtenderClient.getServiceCredentials()).thenReturn(TestUtil.CREDENTIALS_ANONYMOUS);
        Mockito.when(mockedTrustStore.isTrusted(Mockito.any(X509Certificate.class), Mockito.any(Store.class))).thenReturn(true);

        InMemoryPublicationsFileFactory publicationsFileFactory = new InMemoryPublicationsFileFactory(mockedTrustStore);
        ksiService = Mockito.spy(new KSIServiceImpl(mockedSigningClient, mockedExtenderClient, new NonCachingPublicationsFileClientAdapter(mockedPublicationsFileClient, publicationsFileFactory), new InMemoryKsiSignatureFactory()));
        mockedResponse = Mockito.mock(Future.class);
        mockedPublicationsFileResponse = Mockito.mock(Future.class);
        Mockito.when(ksiService.generateRequestId()).thenReturn(42275443333883166L);
    }

}
