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

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.unisignature.verifier.rules.Rule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Keyless signature verifier implementation.
 */
public final class KSISignatureVerifier implements SignatureVerifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(KSISignatureVerifier.class);

    public KSIVerificationResult verify(VerificationContext context, Policy policy) throws KSIException {
        LOGGER.info("Starting to verify signature {} using policy {}", context.getSignature(), policy.getName());
        KSIVerificationResult finalResult = new KSIVerificationResult();
        Policy runPolicy = policy;
        while (runPolicy != null) {
            PolicyVerificationResult result = verifySignature(context, runPolicy);
            finalResult.addPolicyResult(result);
            if (!VerificationResultCode.OK.equals(result.getPolicyStatus())) {
                LOGGER.info("Using fallback policy {}", runPolicy.getFallbackPolicy());
                runPolicy = runPolicy.getFallbackPolicy();
            } else {
                runPolicy = null;
            }
        }
        return finalResult;
    }

    private KSIPolicyVerificationResult verifySignature(VerificationContext context, Policy policy) throws KSIException {
        KSIPolicyVerificationResult policyVerificationResult = new KSIPolicyVerificationResult(policy);
        List<Rule> rules = policy.getRules();
        for (Rule rule : rules) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Starting to execute rule {}", rule);
            }
            RuleResult result = rule.verify(context);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Rule '{}' result is {}", rule, result);
            }
            policyVerificationResult.addRuleResult(rule, result);
            policyVerificationResult.setPolicyStatus(result.getResultCode());
            if (!VerificationResultCode.OK.equals(result.getResultCode())) {
                break;
            }
        }
        return policyVerificationResult;
    }

    private class KSIPolicyVerificationResult implements PolicyVerificationResult {

        private final Policy policy;
        private VerificationResultCode policyStatus = VerificationResultCode.NA;
        private Map<Rule, RuleResult> ruleResults = new LinkedHashMap<Rule, RuleResult>();
        private VerificationErrorCode errorCode;

        public KSIPolicyVerificationResult(Policy policy) {
            this.policy = policy;
        }

        public void addRuleResult(Rule rule, RuleResult result) {
            ruleResults.put(rule, result);
            if (!VerificationResultCode.OK.equals(result.getResultCode())) {
                this.errorCode = result.getErrorCode();
            }
        }

        public VerificationResultCode getPolicyStatus() {
            return policyStatus;
        }

        public void setPolicyStatus(VerificationResultCode policyStatus) {
            this.policyStatus = policyStatus;
        }

        public Policy getPolicy() {
            return policy;
        }

        public VerificationErrorCode getErrorCode() {
            return errorCode;
        }

        public Map<Rule, RuleResult> getRuleResults() {
            return ruleResults;
        }

        @Override
        public String toString() {
            return "policy='" + policy.getName() +
                    "', policyStatus=" + policyStatus + ", errorCode=" + errorCode +
                    ", ruleResults=[" + ruleResults.values() + "]";
        }
    }


    private class KSIVerificationResult implements VerificationResult {

        private List<PolicyVerificationResult> policyResults = new LinkedList<PolicyVerificationResult>();
        private VerificationErrorCode errorCode;

        public void addPolicyResult(PolicyVerificationResult result) {
            policyResults.add(result);
            if (!VerificationResultCode.OK.equals(result.getPolicyStatus())) {
                this.errorCode = result.getErrorCode();
            } else {
                this.errorCode = null;
            }
        }

        public VerificationErrorCode getErrorCode() {
            return errorCode;
        }

        public boolean isOk() {
            for (PolicyVerificationResult policyResult : policyResults) {
                if (VerificationResultCode.OK.equals(policyResult.getPolicyStatus())) {
                    return true;
                }
            }
            return false;
        }

        public List<PolicyVerificationResult> getPolicyVerificationResults() {
            return policyResults;
        }

        @Override
        public String toString() {
            return "Result=" + getPolicyVerificationResults() + ", errorCode=" + errorCode + ", policyResult=[" + policyResults + "]";
        }
    }

}
