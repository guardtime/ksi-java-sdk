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

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Date;

public class ExtendedSignatureCalendarChainInputHashRuleTest extends AbstractRuleTest {

    private Rule rule = new ExtendedSignatureCalendarChainInputHashRule();
    private VerificationContext mockedVerificationContext;

    @BeforeMethod
    public void setUp() throws Exception {
        KSISignature sig = TestUtil.loadSignature("ok-sig-2014-04-30.1-extended.ksig");
        this.mockedVerificationContext = Mockito.mock(VerificationContext.class);
        Mockito.when(mockedVerificationContext.getSignature()).thenReturn(sig);
        Mockito.when(mockedVerificationContext.getCalendarHashChain()).thenReturn(sig.getCalendarHashChain());
        Mockito.when(mockedVerificationContext.getUserProvidedPublication()).thenReturn(sig.getPublicationRecord().getPublicationData());
        Mockito.when(mockedVerificationContext.getLastAggregationHashChain()).thenReturn(sig.getAggregationHashChains()[sig.getAggregationHashChains().length - 1]);
    }

    @Test
    public void testVerifyExtendedCalendarChainInputHashMatchesWithInitialSignature_Ok() throws Exception {
        Mockito.when(mockedVerificationContext.getExtendedCalendarHashChain(Mockito.any(Date.class))).thenReturn(TestUtil.loadSignature("ok-sig-2014-04-30.1-extended.ksig").getCalendarHashChain());
        RuleResult result = rule.verify(mockedVerificationContext);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
    }

    @Test
    public void testVerifyExtendedCalendarChainInputHashDoesNotMatchWithInitialSignature_Ok() throws Exception {
        Mockito.when(mockedVerificationContext.getExtendedCalendarHashChain(Mockito.any(Date.class))).thenReturn(TestUtil.loadSignature("ok-sig-2014-06-2-extended.ksig").getCalendarHashChain());
        RuleResult result = rule.verify(mockedVerificationContext);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        Assert.assertEquals(result.getErrorCode(), VerificationErrorCode.CAL_02);
    }

}