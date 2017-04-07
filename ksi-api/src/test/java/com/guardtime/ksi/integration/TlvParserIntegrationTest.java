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

import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.unisignature.verifier.policies.CalendarBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

import static com.guardtime.ksi.Resources.EXTENDED_SIGNATURE_2017_03_14;

public class TlvParserIntegrationTest extends AbstractCommonIntegrationTest{

    private static final Logger LOGGER = LoggerFactory.getLogger(TlvParserIntegrationTest.class);
    private final Policy policy = new KeyBasedVerificationPolicy();

    @Test(groups = TEST_GROUP_INTEGRATION, dataProvider = EXTENDER_RESPONSES_DATA_PROVIDER)
    public void testVerifySignatureWithExtraElementsInAggregationResponse(DataHolderForIntegrationTests testData) throws Exception {
        try {
            KSIExtenderClient mockedExtenderClient = Mockito.mock(KSIExtenderClient.class);
            LOGGER.info("Used response file: " + testData.getTestFile());
            String responseFile = testData.getTestFile();
            mockExtenderResponseCalendarHashCain(responseFile, mockedExtenderClient);

            testData.setTestFile(EXTENDED_SIGNATURE_2017_03_14);
            testData.setHttpClient(mockedExtenderClient);

            testExecution(testData, new CalendarBasedVerificationPolicy());
        } catch (Exception e) {
            if (!(e.getMessage().contains(testData.getExpectedExceptionMessage()) && e.getClass().toString().contains(testData.getExpectedExceptionClass()))) {
                throw e;
            }
        }

    }
}
