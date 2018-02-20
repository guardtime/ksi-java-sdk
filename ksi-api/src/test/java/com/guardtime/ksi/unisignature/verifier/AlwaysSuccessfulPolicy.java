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

package com.guardtime.ksi.unisignature.verifier;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.unisignature.verifier.rules.Rule;

import java.util.List;

import static java.util.Collections.singletonList;

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
        return singletonList(r);
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
