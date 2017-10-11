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

package com.guardtime.ksi.unisignature.verifier.policies;

import com.guardtime.ksi.Extender;
import com.guardtime.ksi.PublicationsHandler;
import com.guardtime.ksi.publication.PublicationData;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.unisignature.verifier.rules.Rule;
import com.guardtime.ksi.util.Util;

import java.util.List;

public class ContextAwarePolicyAdapter implements ContextAwarePolicy {

    private Policy policy;
    private PolicyContext context;

    private ContextAwarePolicyAdapter(Policy policy, PolicyContext context) {
        Util.notNull(policy, "Policy");
        Util.notNull(context, "PolicyContext");
        this.policy = policy;
        this.context = context;
    }

    /**
     * Method creating context aware policy using {@link InternalVerificationPolicy} for verification.
     *
     * @return Internal verification policy with suitable context.
     */
    public static ContextAwarePolicy createInternalPolicy() {
        return new ContextAwarePolicyAdapter(new InternalVerificationPolicy(), new PolicyContext());
    }

    /**
     * Method creating context aware policy using {@link KeyBasedVerificationPolicy} for verification.
     *
     * @param handler
     *      Publications handler.
     * @return Key based verification policy with suitable context.
     */
    public static ContextAwarePolicy createKeyPolicy(PublicationsHandler handler) {
        Util.notNull(handler, "Publications handler");
        return new ContextAwarePolicyAdapter(new KeyBasedVerificationPolicy(), new PolicyContext(handler, null));
    }

    /**
     * Method creating context aware policy using {@link PublicationsFileBasedVerificationPolicy} for verification.
     *
     * @param handler
     *      Publications handler.
     * @return Publications file based verification policy with suitable context.
     */
    public static ContextAwarePolicy createPublicationsFilePolicy(PublicationsHandler handler) {
        return createPublicationsFilePolicy(handler, null);
    }

    /**
     * Method creating context aware policy using {@link PublicationsFileBasedVerificationPolicy} for verification. If
     * extender is provided, then extending is allowed while verifying signature.
     *
     * @param handler
     *      Publications handler.
     * @param extender
     *      Extender.
     * @return Publications file based verification policy with suitable context.
     */
    public static ContextAwarePolicy createPublicationsFilePolicy(PublicationsHandler handler, Extender extender) {
        Util.notNull(handler, "Publications handler");
        PolicyContext context = new PolicyContext(handler, extender != null ? extender.getExtendingService() : null);
        return new ContextAwarePolicyAdapter(new PublicationsFileBasedVerificationPolicy(), context);
    }

    /**
     * Method creating context aware policy using {@link CalendarBasedVerificationPolicy} for verification. Since
     * extender is provided, then extending is allowed when verifying signature.
     *
     * @param extender
     *      Extender.
     * @return Calendar based verification policy with suitable context.
     */
    public static ContextAwarePolicy createCalendarPolicy(Extender extender) {
        Util.notNull(extender, "Extender");
        return new ContextAwarePolicyAdapter(new CalendarBasedVerificationPolicy(),
                new PolicyContext(extender.getExtendingService()));
    }

    /**
     * Method creating context aware policy using {@link UserProvidedPublicationBasedVerificationPolicy} for verification. Only
     * user provided publication data is used for verification.
     *
     * @param publicationData
     *      User provided publication data.
     * @return User provided publication based verification policy with suitable context.
     */
    public static ContextAwarePolicy createUserProvidedPublicationPolicy(PublicationData publicationData) {
        return createUserProvidedPublicationPolicy(publicationData, null, false);
    }

    /**
     * Method creating context aware policy using {@link UserProvidedPublicationBasedVerificationPolicy} for verification.
     * If "extendingAllowed" flag is set to true, extender is mandatory.
     *
     * @param publicationData
     *      User provided publication data.
     * @param extender
     *      Extender.
     * @param extendingAllowed
     *      Publication-Based verification flag, if extending is allowed or not.
     * @return User provided publication based verification policy with suitable context.
     */
    public static ContextAwarePolicy createUserProvidedPublicationPolicy(PublicationData publicationData, Extender extender,
            boolean extendingAllowed) {
        Util.notNull(publicationData, "Publication data");
        if (extendingAllowed) {
            Util.notNull(extender, "Extender");
        }
        return new ContextAwarePolicyAdapter(new UserProvidedPublicationBasedVerificationPolicy(),
                new PolicyContext(publicationData, extender != null ? extender.getExtendingService() : null, extendingAllowed));
    }

    /**
     * Creates general verification policy.
     * <br>
     * Verification steps:
     * <li>Verification with user publication (if provided), signature is extended only if extending is permitted.
     * <li>Verification with publications file, signature is extended only if extending is permitted.
     * <li>Key-based verification is done if publications file based verification ends with NA status.
     * <br>
     * If "extendingAllowed" flag is set to true, extender is mandatory.
     *
     * @param publicationData
     *      User provided publication data.
     * @param handler
     *      Publications handler.
     * @param extender
     *      Extender.
     * @param extendingAllowed
     *      Publication-Based verification flag, if extending is allowed or not.
     * @return Context aware verification policy based on user input.
     */
    public static ContextAwarePolicy createGeneralPolicy(PublicationData publicationData, PublicationsHandler handler,
            Extender extender, boolean extendingAllowed) {
        if (publicationData != null) {
            return createUserProvidedPublicationPolicy(publicationData, extender, extendingAllowed);
        } else {
            if (extendingAllowed) {
                Util.notNull(extender, "Extender");
            }
            return createGeneralPolicy(handler, extender);
        }
    }

    /**
     * Creates general verification policy.
     * <br>
     * Verification steps:
     * <li>Verification with publications file, signature is extended only if extender is provided.
     * <li>Key-based verification is done if publications file based verification ends with NA status.
     *
     * @param handler
     *      Publications handler.
     * @param extender
     *      Extender.
     * @return Context aware verification policy based on user input.
     */
    public static ContextAwarePolicy createGeneralPolicy(PublicationsHandler handler, Extender extender) {
        Util.notNull(handler, "Publications handler");
        PolicyContext context = new PolicyContext(handler, extender != null ? extender.getExtendingService() : null);
        PublicationsFileBasedVerificationPolicy publicationsPolicy = new PublicationsFileBasedVerificationPolicy();
        publicationsPolicy.setFallbackPolicy(new KeyBasedVerificationPolicy());
        return new ContextAwarePolicyAdapter(publicationsPolicy, context);
    }

    /**
     * Method creating context aware policy using user provided policy with needed components.
     *
     * @param policy
     *      Policy.
     * @param handler
     *      Publications handler.
     * @param extendingService
     *      Extending service.
     * @return Policy with suitable context.
     */
    public static ContextAwarePolicy createPolicy(Policy policy, PublicationsHandler handler, KSIExtendingService extendingService) {
        if(policy instanceof UserProvidedPublicationBasedVerificationPolicy){
            throw new IllegalArgumentException("Unsupported verification policy.");
        }
        Util.notNull(handler, "Publications handler");
        Util.notNull(extendingService, "Extending service");
        return new ContextAwarePolicyAdapter(policy, new PolicyContext(handler, extendingService));
    }

    public PolicyContext getPolicyContext() {
        return context;
    }

    public List<Rule> getRules() {
        return policy.getRules();
    }

    public String getName() {
        return policy.getName();
    }

    public String getType() {
        return policy.getType();
    }

    public Policy getFallbackPolicy() {
        return policy.getFallbackPolicy();
    }

    public void setFallbackPolicy(Policy policy) {
        policy.setFallbackPolicy(policy);
    }

}
