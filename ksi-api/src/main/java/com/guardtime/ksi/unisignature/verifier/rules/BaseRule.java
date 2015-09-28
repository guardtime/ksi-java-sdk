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

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.VerificationErrorCode;
import com.guardtime.ksi.unisignature.verifier.VerificationResultCode;

/**
 * Abstract class for all rules
 */
public abstract class BaseRule implements Rule {

    public final RuleResult verify(VerificationContext context) throws KSIException {

        VerificationResultCode result = verifySignature(context);
        if (VerificationResultCode.OK.equals(result)) {
            return new SimpleRuleResult(result, this.getClass().getSimpleName());
        }
        return new SimpleRuleResult(result, getErrorCode(), this.getClass().getSimpleName());
    }

    abstract VerificationResultCode verifySignature(VerificationContext context) throws KSIException;

    abstract VerificationErrorCode getErrorCode();

    /**
     * Base rule result.
     */
    private class SimpleRuleResult implements RuleResult {

        private final VerificationResultCode result;
        private VerificationErrorCode errorCode;
        private final String ruleName;

        public SimpleRuleResult(VerificationResultCode result, VerificationErrorCode errorCode, String ruleName) {
            this.result = result;
            this.errorCode = errorCode;
            this.ruleName = ruleName;
        }

        public SimpleRuleResult(VerificationResultCode result, String ruleName) {
            this.result = result;
            this.ruleName = ruleName;
        }

        public VerificationResultCode getResultCode() {
            return result;
        }

        public VerificationErrorCode getErrorCode() {
            return errorCode;
        }

        public String getRuleName() {
            return ruleName;
        }

        @Override
        public String toString() {
            return ruleName + "=" + result + "(" + errorCode + ")";
        }
    }

}
