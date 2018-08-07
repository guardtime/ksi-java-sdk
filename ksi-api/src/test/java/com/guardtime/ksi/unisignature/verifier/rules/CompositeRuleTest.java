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

import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class CompositeRuleTest {

    private Rule mockedRule1;
    private Rule mockedRule2;
    private RuleResult mockResult1;
    private RuleResult mockResult2;


    @BeforeMethod
    public void setUp() throws Exception {
        this.mockResult1 = Mockito.mock(RuleResult.class);
        this.mockResult2 = Mockito.mock(RuleResult.class);
        this.mockedRule1 = Mockito.mock(Rule.class);
        this.mockedRule2 = Mockito.mock(Rule.class);

        Mockito.when(mockResult1.getResultCode()).thenReturn(VerificationResultCode.OK);
        Mockito.when(mockResult2.getResultCode()).thenReturn(VerificationResultCode.OK);
        Mockito.when(mockedRule1.verify(Mockito.any(VerificationContext.class))).thenReturn(mockResult1);
        Mockito.when(mockedRule2.verify(Mockito.any(VerificationContext.class))).thenReturn(mockResult2);
    }

    @Test
    public void testCompositeRuleReturnsOkWhenAllTestsReturnOk() throws Exception {
        CompositeRule rule = new CompositeRule(false, mockedRule1, mockedRule2);
        RuleResult result = rule.verify(null);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
    }

    @Test
    public void testCompositeRuleReturnsFailWhenAtLeastOnRuleFails() throws Exception {
        Mockito.when(mockResult2.getResultCode()).thenReturn(VerificationResultCode.FAIL);
        CompositeRule rule = new CompositeRule(false, mockedRule1, mockedRule2);
        RuleResult result = rule.verify(null);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.FAIL);
    }

    @Test
    public void testCompositeRuleReturnsNaWhenAtLeastOnRuleReturnsNA() throws Exception {
        Mockito.when(mockResult2.getResultCode()).thenReturn(VerificationResultCode.NA);
        CompositeRule rule = new CompositeRule(false, mockedRule1, mockedRule2);
        RuleResult result = rule.verify(null);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.NA);
    }

    @Test
    public void testCompositeRuleReturnsOkWhenAtLeastOnRuleReturnsOk() throws Exception {
        Mockito.when(mockResult1.getResultCode()).thenReturn(VerificationResultCode.OK);
        CompositeRule rule = new CompositeRule(true, mockedRule1, mockedRule2);
        RuleResult result = rule.verify(null);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
    }

    @Test
    public void testCompositeRuleReturnsNaWhenAllRulesReturnNa() throws Exception {
        Mockito.when(mockResult1.getResultCode()).thenReturn(VerificationResultCode.NA);
        Mockito.when(mockResult2.getResultCode()).thenReturn(VerificationResultCode.NA);
        CompositeRule rule = new CompositeRule(true, mockedRule1, mockedRule2);
        RuleResult result = rule.verify(null);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.NA);
    }

    @Test
    public void testNestedCompositeRule() throws Exception {
        Mockito.when(mockResult1.getResultCode()).thenReturn(VerificationResultCode.NA);
        Mockito.when(mockResult2.getResultCode()).thenReturn(VerificationResultCode.OK);
        CompositeRule rule = new CompositeRule(true,
                new CompositeRule(false,
                        mockedRule2,
                        new CompositeRule(true,
                                new CompositeRule(false,
                                        mockedRule2,
                                        mockedRule1
                                ),

                                new CompositeRule(false,
                                        mockedRule2,
                                        mockedRule2
                                )),
                        mockedRule2)
        );
        RuleResult result = rule.verify(null);
        Assert.assertEquals(result.getResultCode(), VerificationResultCode.OK);
    }

}