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

package com.guardtime.ksi.unisignature.verifier;

import com.guardtime.ksi.TestUtil;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.unisignature.verifier.rules.Rule;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class SignatureVerifierTest {

    private SignatureVerifier verifier;
    private Policy mockedPolicy;
    private Policy fallbackPolicy;
    private VerificationContext context;

    @BeforeMethod
    public void setUp() throws Exception {
        this.mockedPolicy = Mockito.mock(Policy.class);
        this.fallbackPolicy = Mockito.mock(Policy.class);
        this.verifier = new KSISignatureVerifier();
        this.context = Mockito.mock(VerificationContext.class);
        Mockito.when(context.getSignature()).thenReturn(TestUtil.loadSignature("ok-sig-2014-06-2.ksig"));
    }

    @Test
    public void testVerifySignatureWithoutAnyRules_Ok() throws Exception {
        Mockito.when(mockedPolicy.getRules()).thenReturn(new LinkedList<Rule>());
        VerificationResult result = verifier.verify(context, mockedPolicy);
        Assert.assertNotNull(result);
        Assert.assertEquals(result.isOk(), false);
        Assert.assertEquals(result.getPolicyVerificationResults().size(), 1);
        Assert.assertEquals(result.getPolicyVerificationResults().get(0).getPolicyStatus(), VerificationResultCode.NA);
    }

    @Test
    public void testWhenVerifyingInvalidSignatureThenResultIsInvalid_Ok() throws Exception {
        Rule mockedRule = Mockito.mock(Rule.class);
        RuleResult mockedResult = Mockito.mock(RuleResult.class);
        Mockito.when(mockedResult.getResultCode()).thenReturn(VerificationResultCode.FAIL);
        Mockito.when(mockedRule.verify(Mockito.any(KSIVerificationContext.class))).thenReturn(mockedResult);
        Mockito.when(mockedPolicy.getRules()).thenReturn(toList(mockedRule));
        VerificationResult result = verifier.verify(context, mockedPolicy);
        Assert.assertNotNull(result);
        Assert.assertEquals(result.isOk(), false);
        Assert.assertEquals(result.getPolicyVerificationResults().size(), 1);
        Assert.assertEquals(result.getPolicyVerificationResults().get(0).getPolicyStatus(), VerificationResultCode.FAIL);
    }

    @Test
    public void testWhenVerifyingSignatureWithoutEnoughDataThenResultIsNa_Ok() throws Exception {
        Rule mockedRule = Mockito.mock(Rule.class);
        RuleResult mockedResult = Mockito.mock(RuleResult.class);
        Mockito.when(mockedResult.getResultCode()).thenReturn(VerificationResultCode.OK);
        Mockito.when(mockedRule.verify(Mockito.any(KSIVerificationContext.class))).thenReturn(mockedResult);

        RuleResult mockedResult2 = Mockito.mock(RuleResult.class);
        Mockito.when(mockedResult2.getResultCode()).thenReturn(VerificationResultCode.NA);
        Rule mockedRule2 = Mockito.mock(Rule.class);
        Mockito.when(mockedRule2.verify(Mockito.any(KSIVerificationContext.class))).thenReturn(mockedResult2);

        Mockito.when(mockedPolicy.getRules()).thenReturn(toList(mockedRule, mockedRule2));
        VerificationResult result = verifier.verify(context, mockedPolicy);
        Assert.assertNotNull(result);
        Assert.assertEquals(result.isOk(), false);
        Assert.assertEquals(result.getPolicyVerificationResults().get(0).getPolicyStatus(), VerificationResultCode.NA);
        Assert.assertEquals(result.getPolicyVerificationResults().get(0).getRuleResults().get(mockedRule).getResultCode(), VerificationResultCode.OK);
        Assert.assertEquals(result.getPolicyVerificationResults().get(0).getRuleResults().get(mockedRule2).getResultCode(), VerificationResultCode.NA);
    }

    @Test
    public void testFallbackPolicy() throws Exception {
        Rule mockedRule = Mockito.mock(Rule.class);
        RuleResult mockedResult = Mockito.mock(RuleResult.class);
        Mockito.when(mockedResult.getErrorCode()).thenReturn(VerificationErrorCode.GEN_1);
        Mockito.when(mockedResult.getResultCode()).thenReturn(VerificationResultCode.NA);
        Mockito.when(mockedRule.verify(Mockito.any(KSIVerificationContext.class))).thenReturn(mockedResult);

        RuleResult mockedResult2 = Mockito.mock(RuleResult.class);
        Mockito.when(mockedResult2.getResultCode()).thenReturn(VerificationResultCode.OK);
        Rule mockedRule2 = Mockito.mock(Rule.class);
        Mockito.when(mockedRule2.verify(Mockito.any(KSIVerificationContext.class))).thenReturn(mockedResult2);

        Mockito.when(mockedPolicy.getRules()).thenReturn(toList(mockedRule));
        Mockito.when(fallbackPolicy.getRules()).thenReturn(toList(mockedRule2));

        Mockito.when(mockedPolicy.getFallbackPolicy()).thenReturn(fallbackPolicy);
        VerificationResult result = verifier.verify(context, mockedPolicy);
        Assert.assertTrue(result.isOk());
        Assert.assertNull(result.getErrorCode());
    }

    List<Rule> toList(Rule... rules) {
        return Arrays.asList(rules);
    }


}