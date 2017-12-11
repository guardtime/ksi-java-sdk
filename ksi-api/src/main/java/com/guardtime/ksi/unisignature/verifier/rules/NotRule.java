package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;

import java.util.Collections;

/**
 * Inverts rule results where:
 *      !OK = NA
 *      !NA = OK
 *      !FAIL = FAIL
 */
public class NotRule implements Rule {

    private Rule rule;

    public NotRule(Rule rule){
        this.rule = rule;
    }

    @Override
    public RuleResult verify(VerificationContext context) throws KSIException {
        return new NotRuleResult(rule, rule.verify(context));
    }

    private class NotRuleResult implements RuleResult {

        private VerificationResultCode resultCode;
        private VerificationErrorCode errorCode = null;
        private String ruleName;

        public NotRuleResult(Rule rule, RuleResult ruleResult) {
            this.ruleName = ruleResult.getRuleName();
            if (ruleResult.getResultCode().equals(VerificationResultCode.OK)) {
                resultCode = VerificationResultCode.NA;
                errorCode = VerificationErrorCode.GEN_02;
            } else if (ruleResult.getResultCode().equals(VerificationResultCode.NA)) {
                resultCode = VerificationResultCode.OK;
            } else {
                resultCode = VerificationResultCode.FAIL;
                errorCode = ruleResult.getErrorCode();
            }
        }

        public VerificationResultCode getResultCode() {
            return resultCode;
        }

        public VerificationErrorCode getErrorCode() {
            return errorCode;
        }

        public String getRuleName() {
            return "Not " + ruleName;
        }

        @Override
        public String toString() {
            return getRuleName() + "=" + getResultCode() + "(" + getErrorCode() + ")";
        }
    }

}
