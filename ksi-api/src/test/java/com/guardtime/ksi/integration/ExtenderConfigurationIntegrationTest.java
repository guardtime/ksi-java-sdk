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
package com.guardtime.ksi.integration;

import com.guardtime.ksi.AsyncContext;
import com.guardtime.ksi.KSI;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.ConfigurationListener;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSIExtendingClientServiceAdapter;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.ha.HAService;
import com.guardtime.ksi.service.http.simple.SimpleHttpExtenderClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpPublicationsFileClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpSigningClient;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.Collections;

import static com.guardtime.ksi.TestUtil.assertCause;

public class ExtenderConfigurationIntegrationTest extends AbstractCommonIntegrationTest {

    private HAService haServiceV2;
    private HAService haServiceV1;
    private KSI ksiV2;
    private KSI ksiV1;
    private SimpleHttpExtenderClient extenderClientV1;

    @BeforeClass
    public void setUp() throws Exception {
        super.setUp();

        SimpleHttpSigningClient signingClientV1 = new SimpleHttpSigningClient(loadSignerSettings(PduVersion.V1));
        SimpleHttpSigningClient signingClientV2 = new SimpleHttpSigningClient(loadSignerSettings(PduVersion.V2));

        extenderClientV1 = new SimpleHttpExtenderClient(loadExtenderSettings(PduVersion.V1));
        SimpleHttpExtenderClient extenderClientV2 = new SimpleHttpExtenderClient(loadExtenderSettings(PduVersion.V2));

        SimpleHttpPublicationsFileClient publicationsFileClient = new SimpleHttpPublicationsFileClient(loadPublicationsFileSettings());

        haServiceV2 = new HAService.Builder().addSigningClients(Collections.<KSISigningClient>singletonList(signingClientV2))
                .addExtenderClients(Collections.<KSIExtenderClient>singletonList(extenderClientV2)).build();
        haServiceV1 = new HAService.Builder().addSigningClients(Collections.<KSISigningClient>singletonList(signingClientV1))
                .addExtenderClients(Collections.<KSIExtenderClient>singletonList(extenderClientV1)).build();

        this.ksiV2 = createKsi(extenderClientV2, signingClientV2, publicationsFileClient);
        this.ksiV1 = createKsi(extenderClientV1, signingClientV1, publicationsFileClient);
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
    public void testExtenderConfigurationRequestWithHAServiceV1() throws Exception {
        final AsyncContext ac = new AsyncContext();
        haServiceV1.registerExtenderConfigurationListener(new ConfigurationListener<ExtenderConfiguration>() {
            public void updated(ExtenderConfiguration extenderConfiguration) {
                try {
                    Assert.fail("Configuration request was not supposed to succeed because of PDU V1, but it did.");
                } catch (AssertionError e) {
                    ac.fail(e);
                }
            }

            public void updateFailed(Throwable t) {
                try {
                    if ("HA service has no active subconfigurations to base its consolidated configuration on".equals(t.getMessage())) {
                        ac.succeed();
                    } else {
                        Assert.fail("Configuration update failed for unexpected reason", t);
                    }
                } catch (AssertionError e) {
                    ac.fail(e);
                }
            }
        });
        haServiceV1.getExtendingConfiguration();
        ac.await();
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Not supported. Configure the SDK to use PDU v2 format.")
    public void testExtenderConfigurationRequestWithSimpleHttpClientV1() throws Throwable {
        final AsyncContext ac = new AsyncContext();
        KSIExtendingClientServiceAdapter simpleHttpService = new KSIExtendingClientServiceAdapter(extenderClientV1);
        simpleHttpService.registerExtenderConfigurationListener(new ConfigurationListener<ExtenderConfiguration>() {
            public void updated(ExtenderConfiguration extenderConfiguration) {
                try {
                    Assert.fail("Configuration request was not supposed to succeed because of PDU V1, but it did.");
                } catch (AssertionError e) {
                    ac.fail(e);
                }
            }

            public void updateFailed(Throwable t) {
                try {
                    if ("Not supported. Configure the SDK to use PDU v2 format.".equals(t.getMessage())) {
                        ac.succeed();
                    } else {
                        Assert.fail("Configuration update failed for unexpected reason", t);
                    }
                } catch (AssertionError e) {
                    ac.fail(e);
                }
            }
        });
        Future<ExtenderConfiguration> extendingConfiguration = simpleHttpService.getExtendingConfiguration();

        ac.await();
        try {
            extendingConfiguration.getResult();
        } catch (Exception e) {
            throw e.getCause().getCause();
        }
    }

    @Test
    public void testSynchronousExtenderConfigurationRequestV2() throws Exception {
        ExtenderConfiguration response = ksiV2.getExtendingService().getExtendingConfiguration().getResult();
        Assert.assertNotNull(response);
    }

    @Test
    public void testSynchronousExtenderConfigurationRequestV1() throws Throwable {
        try {
            ksiV1.getExtendingService().getExtendingConfiguration().getResult();
            Assert.fail("Configuration update was not supposed to succeed with PDU V1");
        } catch (Exception e) {
            assertCause(KSIException.class, "Not supported. Configure the SDK to use PDU v2 format.", e);
        }
    }

    @Test
    public void testSynchronousExtendingConfigurationRequestHA() throws Exception {
        Assert.assertNotNull(haServiceV2.getExtendingConfiguration().getResult());
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Configuration consolidation failed in HA service")
    public void testSynchronousConfigurationHAFail() throws Exception {
        haServiceV1.getExtendingConfiguration().getResult();
    }

}
