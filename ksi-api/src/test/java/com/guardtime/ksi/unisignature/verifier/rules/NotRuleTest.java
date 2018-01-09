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
