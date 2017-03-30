/*
 * Copyright 2013-2017 Guardtime, Inc.
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
package com.guardtime.ksi.service.ha;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.ha.settings.HAClientSettings;
import org.testng.annotations.Test;

import java.io.ByteArrayInputStream;
import java.util.Collections;
import java.util.Date;

import static org.mockito.Mockito.mock;

public class HAClientTest {

    @Test(expectedExceptions = KSIException.class,
            expectedExceptionsMessageRegExp = "It is impossible to perform a signing request using this HAClient because there " +
                    "are no signing clients in selection")
    public void testAddingNoSigningClientsAndAttemptingToSign() throws Exception {
        HAClient haClient = new HAClient(null, Collections.singletonList(mock(KSIExtenderClient.class)));
        haClient.sign(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 1L), mock(DataHash.class), 0L);
    }

    @Test(expectedExceptions = KSIException.class,
            expectedExceptionsMessageRegExp = "It is impossible to perform a signing request using this HAClient because there " +
                    "are no extending clients in selection")
    public void testAddingNoExtendingClientsAndAttemptingToExtend() throws Exception {
        HAClient haClient = new HAClient(Collections.singletonList(mock(KSISigningClient.class)), null);
        haClient.extend(new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 1L), new Date(), new Date());
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Property " +
            "HAClientSettings.activeSigningClientsPerRequest must not be larger than the list of given KSI signing clients")
    public void testActiveSigningClientsPerRequestLargerThanSigningClientsList() throws Exception {
        new HAClient(
                Collections.singletonList(mock(KSISigningClient.class)),
                Collections.singletonList(mock(KSIExtenderClient.class)),
                new HAClientSettings(2, 1)
        );
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Invalid input parameter. Property " +
            "HAClientSettings.activeExtenderClientsPerRequest must not be larger than the list of given KSI extender clients")
    public void testActiveExtenderClientsPerRequestLargerThanSigningClientsList() throws Exception {
        new HAClient(
                Collections.singletonList(mock(KSISigningClient.class)),
                Collections.singletonList(mock(KSIExtenderClient.class)),
                new HAClientSettings(1, 2)
        );
    }

    @Test(expectedExceptions = KSIClientException.class, expectedExceptionsMessageRegExp = "HAClient.sign\\(inputStream\\) is not supported. Use HAClient.sign\\(ksiRequestContext, dataHash, level\\) instead")
    public void testSigningStream() throws Exception {
        HAClient client = new HAClient(
                Collections.singletonList(mock(KSISigningClient.class)),
                Collections.singletonList(mock(KSIExtenderClient.class))
        );
        client.sign(new ByteArrayInputStream(new byte[]{}));
    }

    @Test(expectedExceptions = KSIClientException.class, expectedExceptionsMessageRegExp = "HAClient.extend\\(inputStream\\) is not supported. Use HAClient.extend\\(ksiRequestContext, aggregationTime, publicationTime\\) instead")
    public void testExtendingStream() throws Exception {
        HAClient client = new HAClient(
                Collections.singletonList(mock(KSISigningClient.class)),
                Collections.singletonList(mock(KSIExtenderClient.class))
        );
        client.extend(new ByteArrayInputStream(new byte[]{}));
    }

}
