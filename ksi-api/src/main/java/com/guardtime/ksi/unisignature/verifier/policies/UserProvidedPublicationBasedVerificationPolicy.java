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

import com.guardtime.ksi.unisignature.verifier.rules.CalendarAuthenticationRecordAggregationHashRule;
import com.guardtime.ksi.unisignature.verifier.rules.CalendarHashChainAlgorithmDeprecatedRule;
import com.guardtime.ksi.unisignature.verifier.rules.CompositeRule;
import com.guardtime.ksi.unisignature.verifier.rules.ExtendingPermittedVerificationRule;
import com.guardtime.ksi.unisignature.verifier.rules.NotRule;
import com.guardtime.ksi.unisignature.verifier.rules.Rule;
import com.guardtime.ksi.unisignature.verifier.rules.SignaturePublicationRecordExistenceRule;
import com.guardtime.ksi.unisignature.verifier.rules.UserProvidedPublicationCalendarHashChainAlgorithmDeprecatedRule;
import com.guardtime.ksi.unisignature.verifier.rules.UserProvidedPublicationCreationTimeVerificationRule;
import com.guardtime.ksi.unisignature.verifier.rules.UserProvidedPublicationExistenceRule;
import com.guardtime.ksi.unisignature.verifier.rules.UserProvidedPublicationExtendedSignatureInputHashRule;
import com.guardtime.ksi.unisignature.verifier.rules.UserProvidedPublicationHashEqualsToSignaturePublicationHashRule;
import com.guardtime.ksi.unisignature.verifier.rules.UserProvidedPublicationHashMatchesExtendedResponseRule;
import com.guardtime.ksi.unisignature.verifier.rules.UserProvidedPublicationTimeEqualsToSignaturePublicationTimeRule;
import com.guardtime.ksi.unisignature.verifier.rules.UserProvidedPublicationTimeMatchesExtendedResponseRule;

/**
 * KSI Signature verification policy. Can be used to verify signatures using userd provided publication.
 */
public class UserProvidedPublicationBasedVerificationPolicy extends InternalVerificationPolicy {

    private static final String TYPE_USER_PROVIDED_PUBLICATION_BASED_POLICY = "USER_PROVIDED_PUBLICATION_POLICY";

    public UserProvidedPublicationBasedVerificationPolicy() {

        Rule useExtendingRule = new CompositeRule(false,
                new UserProvidedPublicationCreationTimeVerificationRule(),
                new ExtendingPermittedVerificationRule(),
                new UserProvidedPublicationCalendarHashChainAlgorithmDeprecatedRule(),
                new UserProvidedPublicationHashMatchesExtendedResponseRule(),
                new UserProvidedPublicationTimeMatchesExtendedResponseRule(),
                new UserProvidedPublicationExtendedSignatureInputHashRule());

        Rule publicationsEqual = new CompositeRule(false,
                new UserProvidedPublicationExistenceRule(),
                new SignaturePublicationRecordExistenceRule(),
                new UserProvidedPublicationTimeEqualsToSignaturePublicationTimeRule(),
                new UserProvidedPublicationHashEqualsToSignaturePublicationHashRule(),
                new CalendarHashChainAlgorithmDeprecatedRule());

        Rule publicationTimesNotEqualDoExtending = new CompositeRule(false,
                new UserProvidedPublicationExistenceRule(),
                new SignaturePublicationRecordExistenceRule(),
                new NotRule(new UserProvidedPublicationTimeEqualsToSignaturePublicationTimeRule()),
                useExtendingRule);

        Rule signatureDoesNotContainPublicationDoExtending = new CompositeRule(false,
                new UserProvidedPublicationExistenceRule(),
                new NotRule(new SignaturePublicationRecordExistenceRule()),
                useExtendingRule);


        addRule(new CompositeRule(true,
                publicationsEqual,
                publicationTimesNotEqualDoExtending,
                signatureDoesNotContainPublicationDoExtending));

    }

    public String getName() {
        return "User provided publication based verification policy";
    }

    public String getType() {
        return TYPE_USER_PROVIDED_PUBLICATION_BASED_POLICY;
    }

}
