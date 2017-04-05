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

import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;
import com.guardtime.ksi.trust.PKITrustStore;
import com.guardtime.ksi.util.Util;
import org.bouncycastle.util.Store;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;

import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;

import static com.guardtime.ksi.CommonTestUtil.load;
import static com.guardtime.ksi.Resources.PUBLICATIONS_FILE_2016_07_27;

public class AbstractPublicationsFileClientAdapterTest {

    protected KSIPublicationsFileClient mockedPublicationsFileClient;
    protected Future mockedPublicationsFileResponse;
    protected PKITrustStore mockedTrustStore;

    @BeforeMethod
    public void setUp() throws Exception {
        mockedTrustStore = Mockito.mock(PKITrustStore.class);
        Mockito.when(mockedTrustStore.isTrusted(Mockito.any(X509Certificate.class), Mockito.any(Store.class))).thenReturn(true);

        mockedPublicationsFileClient = Mockito.mock(KSIPublicationsFileClient.class);
        mockedPublicationsFileResponse = Mockito.mock(Future.class);
        Mockito.when(mockedPublicationsFileResponse.getResult()).thenReturn(ByteBuffer.wrap(Util.toByteArray(load(PUBLICATIONS_FILE_2016_07_27))));
        Mockito.when(mockedPublicationsFileClient.getPublicationsFile()).thenReturn(mockedPublicationsFileResponse);
    }


}
