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

import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.unisignature.verifier.rules.Rule;

import java.util.Map;

/**
 * This interface represents a single {@link Policy} result.
 */
public interface PolicyVerificationResult {

    /**
     * Returns a map of rule and rule results.
     */
    Map<Rule, RuleResult> getRuleResults();

    /**
     * Returns the verification process status.
     */
    VerificationResultCode getPolicyStatus();

    /**
     * Returns the policy used to get this result
     */
    Policy getPolicy();

    /**
     * Returns error code when verification failed.
     */
    VerificationErrorCode getErrorCode();
}
