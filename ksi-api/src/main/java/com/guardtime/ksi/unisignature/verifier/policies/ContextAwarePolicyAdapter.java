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
import com.guardtime.ksi.unisignature.KSISignatureComponentFactory;
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

    // InternalVerificationPolicy
    public static ContextAwarePolicy createInternalPolicy() {
        return new ContextAwarePolicyAdapter(new InternalVerificationPolicy(), new PolicyContext());
    }

    // KeyBasedVerificationPolicy
    public static ContextAwarePolicy createKeyPolicy(PublicationsHandler handler) {
        Util.notNull(handler, "Publications handler");
        return new ContextAwarePolicyAdapter(new KeyBasedVerificationPolicy(), new PolicyContext(handler, null));
    }

    // PublicationsFileBasedVerificationPolicy
    public static ContextAwarePolicy createPublicationsFilePolicy(PublicationsHandler handler) {
        return createPublicationsFilePolicy(handler, null);
    }

    // PublicationsFileBasedVerificationPolicy
    public static ContextAwarePolicy createPublicationsFilePolicy(PublicationsHandler handler, Extender extender) {
        Util.notNull(handler, "Publications handler");
        PolicyContext context = new PolicyContext(handler, extender);
        return new ContextAwarePolicyAdapter(new PublicationsFileBasedVerificationPolicy(), context);
    }

    // CalendarBasedVerificationPolicy
    public static ContextAwarePolicy createCalendarPolicy(KSISignatureComponentFactory signatureComponentFactory,
            Extender extender) {
        Util.notNull(signatureComponentFactory, "Signature factory");
        Util.notNull(extender, "Extender");
        return new ContextAwarePolicyAdapter(new CalendarBasedVerificationPolicy(),
                new PolicyContext(signatureComponentFactory, extender));
    }

    // UserProvidedPublicationBasedVerificationPolicy
    public static ContextAwarePolicy createUserPolicy(PublicationData publicationData, KSISignatureComponentFactory signatureComponentFactory, Extender extender) {
        Util.notNull(publicationData, "Publication data");
        Util.notNull(signatureComponentFactory, "Signature factory");
        Util.notNull(extender, "Extender");
        return new ContextAwarePolicyAdapter(new UserProvidedPublicationBasedVerificationPolicy(),
                new PolicyContext(publicationData, signatureComponentFactory, extender));
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
