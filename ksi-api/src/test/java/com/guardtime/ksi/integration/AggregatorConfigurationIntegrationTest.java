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

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.v2.PduV2Factory;
import com.guardtime.ksi.service.client.KSIServiceCredentials;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Date;
import java.util.List;

public class AggregatorConfigurationIntegrationTest extends AbstractCommonIntegrationTest {

    @Test
    public void testConfigurationResponseParsingV2() throws Exception {
        KSIRequestContext context = new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 1L);
        PduV2Factory factory = new PduV2Factory();
        AggregatorConfiguration cnf = factory.readAggregatorConfigurationResponse(context, TestUtil.loadTlv("aggregator-response-with-conf-ack-and-signature.tlv"));

        Assert.assertEquals(cnf.getAggregationAlgorithm(), HashAlgorithm.SHA2_384);
        Assert.assertTrue(cnf.getAggregationPeriod().equals(12288L));
        Assert.assertTrue(cnf.getMaximumLevel().equals(19L));
        Assert.assertTrue(cnf.getMaximumRequests().equals(17L));
        Assert.assertTrue(cnf.getParents().size() == 3);
        for (String parent : cnf.getParents()){
            Assert.assertTrue(parent.contains(".url"));
        }
    }

    @Test
    public void testConfigurationResponseParsingV2_2() throws Exception {
        KSIRequestContext context = new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 1L);
        PduV2Factory factory = new PduV2Factory();
        AggregatorConfiguration cnf = factory.readAggregatorConfigurationResponse(context, TestUtil.loadTlv("aggregator-response-multiple-confs.tlv"));

        Assert.assertNotNull(cnf);
        Assert.assertEquals(cnf.getAggregationAlgorithm(), HashAlgorithm.RIPEMD_160);
        Assert.assertTrue(cnf.getAggregationPeriod().equals(2L));
        Assert.assertTrue(cnf.getMaximumLevel().equals(2L));
        Assert.assertTrue(cnf.getMaximumRequests().equals(2L));
        Assert.assertTrue(cnf.getParents().size() == 1);
        for (String parent : cnf.getParents()){
            Assert.assertEquals(parent, "anon");
        }
    }

    @Test
    public void testConfigurationResponseParsingV2_3() throws Exception {
        KSIRequestContext context = new KSIRequestContext(new KSIServiceCredentials("anon", "anon"), 1L);
        PduV2Factory factory = new PduV2Factory();
        AggregatorConfiguration cnf = factory.readAggregatorConfigurationResponse(context, TestUtil.loadTlv("aggregator-response-with-empty-conf.tlv"));

        Assert.assertNotNull(cnf);
        Assert.assertNull(cnf.getAggregationAlgorithm());
        Assert.assertNull(cnf.getAggregationPeriod());
        Assert.assertNull(cnf.getMaximumLevel());
        Assert.assertNull(cnf.getMaximumRequests());
        Assert.assertTrue(cnf.getParents().isEmpty());
    }

    @Test
    public void testAggregationConfigurationRequestV2() throws Exception {
        AggregatorConfiguration response = ksiV2.getAggregatorConfiguration();
        Assert.assertNotNull(response);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Not supported. Configure the SDK to use PDU v2 format.")
    public void testAggregationConfigurationRequestV1() throws Exception {
        ksi.getAggregatorConfiguration();
    }
}
