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

package com.guardtime.ksi.unisignature.verifier.policies;

import com.guardtime.ksi.unisignature.verifier.rules.Rule;

import java.util.List;

/**
 * Policy contains the set of rules to be used to verify KSI signature. Different type of policies can be used to verify
 * KSI signature.
 *
 * @see InternalVerificationPolicy
 * @see KeyBasedVerificationPolicy
 * @see CalendarBasedVerificationPolicy
 * @see PublicationsFileBasedVerificationPolicy
 * @see UserProvidedPublicationBasedVerificationPolicy
 */
public interface Policy {

    /**
     * Used to get the rules of the policy. The rules are used to verify KSI signature.
     *
     * @return list of rules to be used to verify keyless signature
     */
    List<Rule> getRules();

    /**
     * Human readable name of the policy
     *
     * @return the name of the policy
     */
    String getName();

    /**
     * This method returns the type of the policy.
     */
    String getType();

    /**
     * Adds fallback policy to be used when signature does not verify with given policy.
     *
     * @param policy
     *         fallback policy to be used when signature does not verify with given policy.
     */
    void setFallbackPolicy(Policy policy);

    /**
     * Used to get the fallback policy set by {@link Policy#setFallbackPolicy(Policy)}.
     *
     * @return instance of {@link Policy} if fallback policy is set.
     */
    Policy getFallbackPolicy();

}
