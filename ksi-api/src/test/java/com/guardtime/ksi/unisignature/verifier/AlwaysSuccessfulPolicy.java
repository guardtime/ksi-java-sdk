package com.guardtime.ksi.unisignature.verifier;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.unisignature.verifier.rules.Rule;

import java.util.List;

import static java.util.Arrays.asList;

/**
 * A policy used in tests. Always returns {@link VerificationResultCode#OK}
 */
public class AlwaysSuccessfulPolicy implements Policy {
    public List<Rule> getRules() {
        Rule r = new Rule() {

            public RuleResult verify(VerificationContext context) throws KSIException {
                return new RuleResult() {
                    public VerificationResultCode getResultCode() {
                        return VerificationResultCode.OK;
                    }

                    public VerificationErrorCode getErrorCode() {
                        return null;
                    }

                    public String getRuleName() {
                        return "Ok rule";
                    }
                };
            }
        };
        return asList(r);
    }

    public String getName() {
        return "AlwaysSuccessful";
    }

    public String getType() {
        return getName();
    }

    public void setFallbackPolicy(Policy policy) {

    }

    public Policy getFallbackPolicy() {
        return null;
    }
}
