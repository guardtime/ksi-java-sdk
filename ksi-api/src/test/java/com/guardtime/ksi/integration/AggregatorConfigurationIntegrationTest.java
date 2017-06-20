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
import com.guardtime.ksi.pdu.AggregatorConfiguration;

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.client.ConfigurationListener;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.client.KSISigningClientServiceAdapter;
import com.guardtime.ksi.service.ha.HAService;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Collections;

import static com.guardtime.ksi.TestUtil.assertCause;

public class AggregatorConfigurationIntegrationTest extends AbstractCommonIntegrationTest {

    private HAService haServiceV2;
    private HAService haServiceV1;
    private KSI ksiV2;

    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        SimpleHttpClient simpleHttpClientV2 = new SimpleHttpClient(loadHTTPSettings(PduVersion.V2));
        haServiceV2 = new HAService.Builder().setSigningClients(Collections.<KSISigningClient>singletonList(simpleHttpClientV2))
                .setExtenderClients(Collections.<KSIExtenderClient>singletonList(simpleHttpClientV2)).build();
        haServiceV1 = new HAService.Builder().setSigningClients(Collections.<KSISigningClient>singletonList(simpleHttpClient))
                .setExtenderClients(Collections.<KSIExtenderClient>singletonList(simpleHttpClient)).build();
        this.ksiV2 = createKsi(simpleHttpClientV2, simpleHttpClientV2, simpleHttpClientV2);
    }

    @Test
    public void testAggregationConfigurationRequestV2() throws Exception {
        final AsyncContext ac = new AsyncContext();

        haServiceV2.registerAggregatorConfigurationListener(new ConfigurationListener<AggregatorConfiguration>() {
            public void updated(AggregatorConfiguration aggregatorConfiguration) {
                try {
                    Assert.assertNotNull(aggregatorConfiguration);
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
        haServiceV2.getAggregationConfiguration();
        ac.await();
    }

    @Test
    public void testAggregationConfigurationRequestWithHAServiceV1() throws Exception {
        final AsyncContext ac = new AsyncContext();
        haServiceV1.registerAggregatorConfigurationListener(new ConfigurationListener<AggregatorConfiguration>() {
            public void updated(AggregatorConfiguration aggregatorConfiguration) {
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
        haServiceV1.getAggregationConfiguration();

        ac.await();
    }

    @Test
    public void testAggregationConfigurationRequestWithSimpleHttpClientV1() throws Exception {

        final AsyncContext ac = new AsyncContext();
        KSISigningClientServiceAdapter simpleHttpService = new KSISigningClientServiceAdapter(simpleHttpClient);
        simpleHttpService.registerAggregatorConfigurationListener(new ConfigurationListener<AggregatorConfiguration>() {
            public void updated(AggregatorConfiguration aggregatorConfiguration) {
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
        simpleHttpService.getAggregationConfiguration();

        ac.await();
    }

    @Test
    public void testSynchronousAggregationConfigurationRequestV2() throws Exception {
        AggregatorConfiguration response = ksiV2.getAggregatorConfiguration();
        Assert.assertNotNull(response);
    }

    @Test
    public void testSynchronousAggregationConfigurationRequestV1() throws Throwable {
        try {
            ksi.getAggregatorConfiguration();
            Assert.fail("Configuration update was not supposed to succeed with PDU V1");
        } catch (Exception e) {
           assertCause(KSIException.class, "Not supported. Configure the SDK to use PDU v2 format.", e);
        }
    }

    @Test
    public void testSynchronousAggregationConfigurationRequestHA() throws Exception {
        Assert.assertNotNull(haServiceV2.getAggregationConfiguration().getResult());
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Configuration consolidation failed in HA service")
    public void testSynchronousConfigurationHAFail() throws Exception {
        haServiceV1.getAggregationConfiguration().getResult();
    }

}
