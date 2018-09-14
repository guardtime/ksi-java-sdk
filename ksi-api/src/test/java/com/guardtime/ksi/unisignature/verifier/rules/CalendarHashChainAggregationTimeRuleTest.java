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

package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;

import org.testng.Assert;
import org.testng.annotations.Test;

import static com.guardtime.ksi.Resources.SIGNATURE_2017_03_14;
import static com.guardtime.ksi.Resources.SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_AGGREGATION_TIME;
import static com.guardtime.ksi.Resources.SIGNATURE_ONLY_AGGREGATION_HASH_CHAINS;

public class CalendarHashChainAggregationTimeRuleTest extends AbstractRuleTest {

    private CalendarHashChainAggregationTimeRule rule = new CalendarHashChainAggregationTimeRule();

    @Test
    public void testSignatureWithInconsistentAggregationTimesReturnsFailedStatus_Ok() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_CALENDAR_HASH_CHAIN_INVALID_AGGREGATION_TIME)));
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.INT_04);
    }

    @Test
    public void testSignatureWithoutCalendarHashChainReturnsOkStatus_Ok() throws Exception {
        RuleResult result = rule.verify(build(TestUtil.loadSignature(SIGNATURE_ONLY_AGGREGATION_HASH_CHAINS)));
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
    }

    @Test
    public void testSignatureWithCorrectAggregationChainAggregationTimeReturnsOkStatus_Ok() throws Exception {
        Assert.assertEquals(rule.verify(build(TestUtil.loadSignature(SIGNATURE_2017_03_14))).getResultCode(), VerificationResultCode.OK);
    }

}