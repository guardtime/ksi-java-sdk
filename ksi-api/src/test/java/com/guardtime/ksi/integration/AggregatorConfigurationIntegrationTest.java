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
import com.guardtime.ksi.service.http.simple.SimpleHttpClient;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class AggregatorConfigurationIntegrationTest extends AbstractCommonIntegrationTest {

    private SimpleHttpClient simpleHttpClientV2;

    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        simpleHttpClientV2 = new SimpleHttpClient(loadHTTPSettings(PduVersion.V2));
    }

    @Test
    public void testAggregationConfigurationRequestV2() throws Exception {
        final AsyncContext ac = new AsyncContext();

        simpleHttpClientV2.registerAggregatorConfigurationListener(new ConfigurationListener<AggregatorConfiguration>() {
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
        simpleHttpClientV2.sendAggregationConfigurationRequest();
        ac.await();
    }

    @Test
    public void testAggregationConfigurationRequestV1() throws Exception {
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
