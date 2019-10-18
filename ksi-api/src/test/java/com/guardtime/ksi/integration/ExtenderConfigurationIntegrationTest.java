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
package com.guardtime.ksi.integration;

import com.guardtime.ksi.AsyncContext;
import com.guardtime.ksi.KSI;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.ConfigurationListener;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.ha.HAService;
import com.guardtime.ksi.service.http.simple.SimpleHttpExtenderClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpPublicationsFileClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpSigningClient;

import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.Collections;

public class ExtenderConfigurationIntegrationTest extends AbstractCommonIntegrationTest {

    private HAService haServiceV2;
    private KSI ksiV2;

    @BeforeClass
    public void setUp() throws Exception {
        super.setUp();

        SimpleHttpSigningClient signingClientV2 = new SimpleHttpSigningClient(loadSignerSettings(PduVersion.V2));

        SimpleHttpExtenderClient extenderClientV2 = new SimpleHttpExtenderClient(loadExtenderSettings(PduVersion.V2));

        SimpleHttpPublicationsFileClient publicationsFileClient = new SimpleHttpPublicationsFileClient(loadPublicationsFileSettings());

        haServiceV2 = new HAService.Builder().addSigningClients(Collections.<KSISigningClient>singletonList(signingClientV2))
                .addExtenderClients(Collections.<KSIExtenderClient>singletonList(extenderClientV2)).build();

        this.ksiV2 = createKsi(extenderClientV2, signingClientV2, publicationsFileClient);
    }

    @AfterClass
    public void tearDown() throws Exception {
        super.tearDown();
        if (haServiceV2 != null) haServiceV2.close();
        if (ksiV2 != null) ksiV2.close();
    }

    @Test
    public void testExtenderConfigurationRequestV2() throws Exception {
        final AsyncContext ac = new AsyncContext();

        haServiceV2.registerExtenderConfigurationListener(new ConfigurationListener<ExtenderConfiguration>() {
            public void updated(ExtenderConfiguration extenderConfiguration) {
                try {
                    Assert.assertNotNull(extenderConfiguration);
                    ac.succeed();
                } catch (AssertionError e) {
                    ac.fail(e);
                }
            }

            public void updateFailed(Throwable t) {
                try {
                    Assert.fail("Configuration update failed", t);
                } catch (AssertionError e) {
                    ac.fail(e);
                }
            }
        });
        haServiceV2.getExtendingConfiguration();
        ac.await();
    }

    @Test
    public void testSynchronousExtenderConfigurationRequestV2() throws Exception {
        ExtenderConfiguration response = ksiV2.getExtendingService().getExtendingConfiguration().getResult();
        Assert.assertNotNull(response);
    }

    @Test
    public void testSynchronousExtendingConfigurationRequestHA() throws Exception {
        Assert.assertNotNull(haServiceV2.getExtendingConfiguration().getResult());
    }
}
