/*
 * Copyright 2013-2017 Guardtime, Inc.
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
