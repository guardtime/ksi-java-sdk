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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * This class represents a rule composed of a set of rules.
 */
public class CompositeRule implements Rule {

    private static final Logger LOGGER = LoggerFactory.getLogger(CompositeRule.class);

    private final boolean skipOnFirstAppliedRule;
    private final Rule[] rules;

    /**
     * Constructor to createSignature a rule that contains multiple other rules.
     *
     * @param skipOnFirstAppliedRule
     *         when this parameter is set to true then the rule engine skips all the next rules when a rule is found
     *         that returns status {@link VerificationResultCode#OK}
     * @param rules
     *         rules to execute by this composite rule
     */
    public CompositeRule(boolean skipOnFirstAppliedRule, Rule... rules) {
        this.skipOnFirstAppliedRule = skipOnFirstAppliedRule;
        this.rules = rules;
    }

    public final CompositeRuleResult verify(VerificationContext context) throws KSIException {
        CompositeRuleResult result = new CompositeRuleResult(skipOnFirstAppliedRule);
        for (Rule rule : rules) {
            result.addRuleResult(rule, rule.verify(context));
            if (VerificationResultCode.OK.equals(result.getResultCode()) && skipOnFirstAppliedRule) {
                return result;
            }
            if (!skipOnFirstAppliedRule && (VerificationResultCode.FAIL.equals(result.getResultCode()) || VerificationResultCode.NA.equals(result.getResultCode()))) {
                return result;
            }
        }
        return result;
    }

    /**
     * Composite rule result
     */
    private class CompositeRuleResult implements RuleResult {

        private Map<Rule, RuleResult> results = new LinkedHashMap<>();
        private RuleResult lastFailedResult;
        private RuleResult lastNaResult;
        private boolean skipOnFirstAppliedRule;

        public CompositeRuleResult(boolean skipOnFirstAppliedRule) {
            this.skipOnFirstAppliedRule = skipOnFirstAppliedRule;
        }

        public void addRuleResult(Rule rule, RuleResult result) {
            LOGGER.debug("Added result {} to composite rule result", result);
            if (VerificationResultCode.FAIL.equals(result.getResultCode())) {
                lastFailedResult = result;
            }
            if (VerificationResultCode.NA.equals(result.getResultCode())) {
                lastNaResult = result;
            }
            results.put(rule, result);
        }


        public VerificationResultCode getResultCode() {
            if (skipOnFirstAppliedRule) {
                Collection<RuleResult> statuses = results.values();
                for (RuleResult status : statuses) {
                    if (VerificationResultCode.OK.equals(status.getResultCode())) {
                        return status.getResultCode();
                    }
                }
            }
            if (lastFailedResult != null) {
                return lastFailedResult.getResultCode();
            }
            if (lastNaResult != null) {
                return lastNaResult.getResultCode();
            }

            return VerificationResultCode.OK;
        }


        public VerificationErrorCode getErrorCode() {
            if (skipOnFirstAppliedRule) {
                Collection<RuleResult> statuses = results.values();
                for (RuleResult status : statuses) {
                    if (VerificationResultCode.OK.equals(status.getResultCode())) {
                        return null;
                    }
                }
            }
            if (lastFailedResult != null) {
                return lastFailedResult.getErrorCode();
            }
            if (lastNaResult != null) {
                return lastNaResult.getErrorCode();
            }

            return null;
        }

        public String getRuleName() {
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < rules.length; i++) {
                Rule rule = rules[i];
                if (rule instanceof CompositeRule)
                    builder.append(rule.getClass().getSimpleName());
                if (rule instanceof BaseRule)
                    builder.append(((BaseRule) rule).getClass().getSimpleName());
                if (i < rules.length) {
                    builder.append(",");
                }
            }
            return builder.toString();
        }

        @Override
        public String toString() {
            return getRuleName() + "=" + getResultCode() + "(" + getErrorCode() + ")";
        }


    }

}
