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
package com.guardtime.ksi.integration;

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSIServiceCredentials;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.http.HttpClientSettings;
import com.guardtime.ksi.service.ha.HAClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import org.testng.annotations.BeforeMethod;

import java.util.ArrayList;
import java.util.List;

public class AbstractConfigurationIntegrationTest extends AbstractCommonIntegrationTest {

    private static final HttpClientSettings FAULTY_HTTP_SETTINGS =
            new HttpClientSettings("http://.", "http://.", "http://.", new KSIServiceCredentials(".", "."));

    KSI ksiV2;
    KSI haKsi;

    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        SimpleHttpClient simpleHttpClientV2 = new SimpleHttpClient(loadHTTPSettings(PduVersion.V2));
        SimpleHttpClient failingClient = new SimpleHttpClient(FAULTY_HTTP_SETTINGS);
        List<KSISigningClient> signingClients = new ArrayList<KSISigningClient>();
        signingClients.add(simpleHttpClientV2);
        signingClients.add(failingClient);
        signingClients.add(simpleHttpClient);
        List<KSIExtenderClient> extenderClients = new ArrayList<KSIExtenderClient>();
        extenderClients.add(simpleHttpClientV2);
        extenderClients.add(failingClient);
        extenderClients.add(simpleHttpClient);
        HAClient haClient = new HAClient(signingClients, extenderClients);
        this.haKsi = createKsi(haClient, haClient, simpleHttpClient);
        this.ksiV2 = createKsi(simpleHttpClientV2,simpleHttpClientV2, simpleHttpClientV2);
    }

}
