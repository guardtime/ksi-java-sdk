/*
 *
 *  Copyright 2013-2018 Guardtime, Inc.
 *
 *  This file is part of the Guardtime client SDK.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
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
package com.guardtime.ksi.integration;

import com.guardtime.ksi.KSI;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.http.apache.ApacheHttpExtenderClient;
import com.guardtime.ksi.service.client.http.apache.ApacheHttpPublicationsFileClient;
import com.guardtime.ksi.service.client.http.apache.ApacheHttpSigningClient;
import com.guardtime.ksi.service.ha.HAService;
import com.guardtime.ksi.service.http.simple.SimpleHttpExtenderClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpPublicationsFileClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpSigningClient;
import com.guardtime.ksi.service.tcp.TCPClient;

import org.testng.annotations.AfterClass;
import org.testng.annotations.DataProvider;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class AbstractKsiDataProviderIntegrationTest extends AbstractCommonIntegrationTest {

    protected static final String KSI_DATA_GROUP_NAME = "ksiDataProvider";

    private static KSI simpleHttpKsi = null;
    private static KSI apacheKsi = null;
    private static KSI tcpKsi = null;
    private static KSI haKsi = null;

    @AfterClass
    public void tearDown() throws Exception {
        super.tearDown();
        if (simpleHttpKsi != null) simpleHttpKsi.close();
        if (apacheKsi != null) apacheKsi.close();
        if (tcpKsi != null) tcpKsi.close();
        if (haKsi != null) haKsi.close();
    }

    @DataProvider(name = KSI_DATA_GROUP_NAME)
    public static Object[][] transportProtocols() throws Exception {
        if (signingSettings == null) {
            signingSettings = loadSignerSettings();
        }

        if (extenderSettings == null){
            extenderSettings = loadExtenderSettings();
        }

        if (publicationsFileSettings == null) {
            publicationsFileSettings = loadPublicationsFileSettings();
        }

        SimpleHttpSigningClient simpleHttpSigningClient = new SimpleHttpSigningClient(signingSettings);
        ApacheHttpSigningClient apacheHttpSigningClient = new ApacheHttpSigningClient(signingSettings);

        SimpleHttpExtenderClient simpleHttpExtenderClient = new SimpleHttpExtenderClient(extenderSettings);
        ApacheHttpExtenderClient apacheHttpExtenderClient = new ApacheHttpExtenderClient(extenderSettings);

        SimpleHttpPublicationsFileClient simpleHttpPublicationsFileClient1 = new SimpleHttpPublicationsFileClient(publicationsFileSettings);
        ApacheHttpPublicationsFileClient apacheHttpPublicationsFileClient1 = new ApacheHttpPublicationsFileClient(publicationsFileSettings);
        SimpleHttpPublicationsFileClient simpleHttpPublicationsFileClient2 = new SimpleHttpPublicationsFileClient(publicationsFileSettings);
        ApacheHttpPublicationsFileClient apacheHttpPublicationsFileClient2 = new ApacheHttpPublicationsFileClient(publicationsFileSettings);

        KSISigningClient tcpClient = new TCPClient(loadTCPSigningSettings(), loadTCPExtendingSettings());

        PendingKSIService pendingKSIService = new PendingKSIService();

        List<KSISigningClient> signingClientsForHa = new ArrayList<KSISigningClient>();
        signingClientsForHa.add(simpleHttpSigningClient);
        signingClientsForHa.add(apacheHttpSigningClient);
        List<KSISigningService> signingServicesForHa = new ArrayList<KSISigningService>();
        signingServicesForHa.add(pendingKSIService);

        List<KSIExtenderClient> extenderClientsForHa = new ArrayList<KSIExtenderClient>();
        extenderClientsForHa.add(simpleHttpExtenderClient);
        extenderClientsForHa.add(apacheHttpExtenderClient);
        List<KSIExtendingService> extendingServicesForHa = new ArrayList<KSIExtendingService>();
        extendingServicesForHa.add(pendingKSIService);

        HAService haService = new HAService.Builder()
                .addSigningClients(signingClientsForHa)
                .addSigningServices(signingServicesForHa)
                .addExtenderClients(extenderClientsForHa)
                .addExtenderServices(extendingServicesForHa)
                .build();
        simpleHttpKsi = createKsi(simpleHttpExtenderClient, simpleHttpSigningClient, simpleHttpPublicationsFileClient1);
        apacheKsi = createKsi(apacheHttpExtenderClient, apacheHttpSigningClient, apacheHttpPublicationsFileClient1);
        tcpKsi = createKsi((KSIExtenderClient) tcpClient, tcpClient, simpleHttpPublicationsFileClient2);
        haKsi = createKsi(haService, haService, apacheHttpPublicationsFileClient2);

        return new Object[][] {
                new Object[] {simpleHttpKsi},
                new Object[] {apacheKsi},
                new Object[] {tcpKsi},
                new Object[] {haKsi}
        };
    }
}
