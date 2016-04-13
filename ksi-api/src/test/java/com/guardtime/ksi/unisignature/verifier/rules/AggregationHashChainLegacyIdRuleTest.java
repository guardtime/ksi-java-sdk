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

package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.unisignature.AggregationChainLink;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import org.mockito.Mockito;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static java.util.Arrays.asList;
import static org.testng.Assert.assertEquals;

public class AggregationHashChainLegacyIdRuleTest extends AbstractRuleTest {

    private Rule rule = new AggregationHashChainLegacyIdRule();
    private VerificationContext mockedVerificationContext;
    private AggregationHashChain mockedAggregationHashChain;
    private AggregationChainLink mockedLink;

    @BeforeMethod
    public void setUp() throws Exception {
        KSISignature sig = TestUtil.loadSignature("ok-sig-2014-04-30.1-extended.ksig");
        this.mockedVerificationContext = Mockito.mock(VerificationContext.class);
        this.mockedAggregationHashChain = Mockito.mock(AggregationHashChain.class);
        this.mockedLink = Mockito.mock(AggregationChainLink.class);
        Mockito.when(mockedVerificationContext.getSignature()).thenReturn(sig);
        Mockito.when(mockedAggregationHashChain.getChainLinks()).thenReturn(asList(mockedLink));
        Mockito.when(mockedVerificationContext.getAggregationHashChains()).thenReturn(new AggregationHashChain[]{mockedAggregationHashChain});
    }

    @Test
    public void testVerifyLegacyIdWithInvalidLength() throws Exception {
        Mockito.when(mockedLink.getLegacyId()).thenReturn(new byte[0]);
        RuleResult result = rule.verify(mockedVerificationContext);
        assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        assertEquals(result.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testVerifyLegacyIdWithInvalidPrefix() throws Exception {
        Mockito.when(mockedLink.getLegacyId()).thenReturn(new byte[29]);
        RuleResult result = rule.verify(mockedVerificationContext);
        assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        assertEquals(result.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testVerifyLegacyIdWithInvalidOctetStringLength() throws Exception {
        Mockito.when(mockedLink.getLegacyId()).thenReturn(new byte[]{0x03, 0x0, 0x26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        RuleResult result = rule.verify(mockedVerificationContext);
        assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        assertEquals(result.getErrorCode(), VerificationErrorCode.INT_11);
    }

    @Test
    public void testVerifyLegacyIdWithInvalidOctetStringPadding() throws Exception {
        Mockito.when(mockedLink.getLegacyId()).thenReturn(new byte[]{0x03, 0x0, 0x4, 'T', 'E', 'S', 'T', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
        RuleResult result = rule.verify(mockedVerificationContext);
        assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
        assertEquals(result.getErrorCode(), VerificationErrorCode.INT_11);
    }
    
}
