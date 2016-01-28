/*
 * Copyright 2013-2015 Guardtime, Inc.
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
import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.CalendarBasedVerificationPolicy;
import org.testng.Assert;
import org.testng.annotations.Test;

public class ExtendIntegrationTest extends AbstractCommonIntegrationTest {

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION)
    public void extendUnextendedSignatureToHead(KSI ksi, KSIExtenderClient extenderClient) throws Exception {
        KSISignature sig = TestUtil.loadSignature("ok-sig-2014-06-2.ksig");
        KSISignature extended = ksi.extendToCalendarHead(sig);
        VerificationResult result = ksi.verify(TestUtil.buildContext(extended, ksi, extenderClient, getFileHash(INPUT_FILE)), new CalendarBasedVerificationPolicy());
        Assert.assertTrue(result.isOk());
    }

    @Test(dataProvider = KSI_DATA_GROUP_NAME, groups = TEST_GROUP_INTEGRATION, expectedExceptions = KSIException.class)
    public void extendFreshSignature(KSI ksi, KSIExtenderClient extenderClient) throws Exception {
        DataHash dataHash = getFileHash(INPUT_FILE);
        KSISignature sig = ksi.sign(dataHash);
        ksi.extend(sig);
    }

}
