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
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.v2.PduV2Factory;
import com.guardtime.ksi.service.client.KSIServiceCredentials;

import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Date;

public class ExtenderConfigurationIntegrationTest extends AbstractCommonIntegrationTest {

    @Test
    public void testExtenderConfigurationRequestV2() throws Exception {
        ExtenderConfiguration response = ksiV2.getExtenderConfiguration();
        Assert.assertNotNull(response);
    }

    @Test(expectedExceptions = KSIException.class, expectedExceptionsMessageRegExp = "Not supported. Configure the SDK to use PDU v2 format.")
    public void testExtenderConfigurationRequestV1() throws Exception {
        ksi.getExtenderConfiguration();
    }

}
