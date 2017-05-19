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

import com.guardtime.ksi.pdu.AggregatorConfiguration;

import com.guardtime.ksi.pdu.PduVersion;
import com.guardtime.ksi.service.client.ConfigurationListener;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.client.KSISigningClient;
import com.guardtime.ksi.service.ha.HAClient;
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Collections;

public class AggregatorConfigurationIntegrationTest extends AbstractCommonIntegrationTest {

    private HAClient haClientV2;
    private HAClient haClientV1;

    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        SimpleHttpClient simpleHttpClientV2 = new SimpleHttpClient(loadHTTPSettings(PduVersion.V2));
        haClientV2 = new HAClient(Collections.singletonList((KSISigningClient) simpleHttpClientV2),
                Collections.singletonList((KSIExtenderClient) simpleHttpClientV2));
        haClientV1 = new HAClient(Collections.singletonList((KSISigningClient) simpleHttpClient),
                Collections.singletonList((KSIExtenderClient) simpleHttpClient));
    }

    @Test
    public void testAggregationConfigurationRequestV2() throws Exception {
        final AsyncContext ac = new AsyncContext();

        haClientV2.registerAggregatorConfigurationListener(new ConfigurationListener<AggregatorConfiguration>() {
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
        haClientV2.sendAggregationConfigurationRequest();
        ac.await();
    }

    @Test
    public void testAggregationConfigurationRequestWithHaClientV1() throws Exception {
        final AsyncContext ac = new AsyncContext();
        haClientV1.registerAggregatorConfigurationListener(new ConfigurationListener<AggregatorConfiguration>() {
            public void updated(AggregatorConfiguration aggregatorConfiguration) {
                try {
                    Assert.fail("Configuration request was not supposed to succeed because of PDU V1, but it did.");
                } catch (AssertionError e) {
                    ac.fail(e);
                }
            }

            public void updateFailed(Throwable t) {
                try {
                    if ("SigningHAClient has no active subconfigurations to base it's consolitated configuration on.".equals(t.getMessage())) {
                        ac.succeed();
                    } else {
                        Assert.fail("Configuration update failed for unexpected reason", t);
                    }
                } catch (AssertionError e) {
                    ac.fail(e);
                }
            }
        });
        haClientV1.sendAggregationConfigurationRequest();

        ac.await();
    }

    @Test
    public void testAggregationConfigurationRequestWithSimpleHttpClientV1() throws Exception {
        final AsyncContext ac = new AsyncContext();
        simpleHttpClient.registerAggregatorConfigurationListener(new ConfigurationListener<AggregatorConfiguration>() {
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
        simpleHttpClient.sendAggregationConfigurationRequest();

        ac.await();
    }
}
