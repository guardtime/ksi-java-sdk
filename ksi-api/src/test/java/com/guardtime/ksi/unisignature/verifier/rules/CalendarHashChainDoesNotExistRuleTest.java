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

package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class CalendarHashChainDoesNotExistRuleTest {

    private CalendarHashChainDoesNotExistRule rule = new CalendarHashChainDoesNotExistRule();

    private VerificationContext mockedContext;

    @BeforeMethod
    public void setUp() throws Exception {
        this.mockedContext = Mockito.mock(VerificationContext.class);
    }

    @Test
    public void testVerifySignatureWithoutCalendarHashChain_Ok() throws Exception {
        Mockito.when(mockedContext.getCalendarHashChain()).thenReturn(null);
        RuleResult result = rule.verify(mockedContext);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
    }

    @Test
    public void testVerifySignatureWithCalendarHashChain_Ok() throws Exception {
        Mockito.when(mockedContext.getCalendarHashChain()).thenReturn(Mockito.mock(CalendarHashChain.class));
        RuleResult result = rule.verify(mockedContext);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.NA);
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.GEN_02);

    }

}