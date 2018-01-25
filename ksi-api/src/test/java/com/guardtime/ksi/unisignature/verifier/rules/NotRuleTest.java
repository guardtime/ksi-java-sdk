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

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;
import com.guardtime.ksi.util.Util;

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

public class NotRuleTest extends AbstractRuleTest {

    private VerificationContext context = Mockito.mock(VerificationContext.class);
    Rule ruleOk = new TestRule(VerificationResultCode.OK, null);
    Rule ruleNa = new TestRule(VerificationResultCode.NA, VerificationErrorCode.GEN_02);
    Rule ruleFail = new TestRule(VerificationResultCode.FAIL, VerificationErrorCode.GEN_01);

    @Test
    public void testNotOkResult_NA() throws KSIException {
        RuleResult ruleResult = new NotRule(ruleOk).verify(context);
        verifyResults(ruleResult, VerificationResultCode.NA, VerificationErrorCode.GEN_02, "Not TestRule");
    }

    @Test
    public void testNotNaResult_OK() throws KSIException {
        RuleResult ruleResult = new NotRule(ruleNa).verify(context);
        verifyResults(ruleResult, VerificationResultCode.OK, null, "Not TestRule");
    }

    @Test
    public void testNotFailResult_FAIL() throws KSIException {
        RuleResult ruleResult = new NotRule(ruleFail).verify(context);
        verifyResults(ruleResult, VerificationResultCode.FAIL, VerificationErrorCode.GEN_01, "Not TestRule");
    }

    @Test
    public void testCompositeRuleNotOkResult_NA() throws KSIException {
        Rule rule = new NotRule(new CompositeRule(true, ruleOk, ruleFail, ruleNa));
        RuleResult ruleResult = rule.verify(context);
        verifyResults(ruleResult, VerificationResultCode.NA, VerificationErrorCode.GEN_02, "Not TestRule,");
    }

    @Test
    public void testCompositeRuleNotNAResult_OK() throws KSIException {
        Rule rule = new NotRule(new CompositeRule(false, ruleNa, ruleFail, ruleOk));
        RuleResult ruleResult = rule.verify(context);
        verifyResults(ruleResult, VerificationResultCode.OK, null, "Not TestRule,");
    }

    @Test
    public void testCompositeRuleNotFailResult_Fail() throws KSIException {
        Rule rule = new NotRule(new CompositeRule(false, ruleFail, ruleOk, ruleNa));
        RuleResult ruleResult = rule.verify(context);;
        verifyResults(ruleResult, VerificationResultCode.FAIL, VerificationErrorCode.GEN_01, "Not TestRule,");
    }

    private void verifyResults(RuleResult result, VerificationResultCode resultCode, VerificationErrorCode errorCode, String ruleNameStartsWith) {
        Assert.assertEquals(result.getResultCode(),resultCode);
        Assert.assertEquals(result.getErrorCode(), errorCode);
        Assert.assertTrue(result.getRuleName().startsWith(ruleNameStartsWith));
    }

    private class TestRule extends BaseRule {
        private VerificationResultCode resultCode;
        private VerificationErrorCode errorCode;
        public TestRule(VerificationResultCode resultCode, VerificationErrorCode errorCode) {
            Util.notNull(resultCode, "VerificationResultCode");
            this.resultCode = resultCode;
            this.errorCode = errorCode;
        }

        @Override
        VerificationResultCode verifySignature(VerificationContext context) throws KSIException {
            return resultCode;
        }

        @Override
        VerificationErrorCode getErrorCode() {
            return errorCode;
        }
    }
}
