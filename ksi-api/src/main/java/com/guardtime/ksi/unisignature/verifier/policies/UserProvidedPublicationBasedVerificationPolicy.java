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

import com.guardtime.ksi.unisignature.verifier.rules.*;

/**
 * This policy can be used to verify keyless signatures using used provided publication.
 */
public class UserProvidedPublicationBasedVerificationPolicy extends InternalVerificationPolicy {

    private static final String TYPE_USER_PROVIDED_PUBLICATION_BASED_POLICY = "USER_PROVIDED_PUBLICATION_POLICY";

    public UserProvidedPublicationBasedVerificationPolicy() {
        addRule(new UserProvidedPublicationExistenceRule());

        Rule verifyUserPublicationRule = new CompositeRule(false,
                new SignaturePublicationRecordExistenceRule(),
                new UserProvidedPublicationTimeEqualsToSignaturePublicationTimeRule(),
                new UserProvidedPublicationHashEqualsToSignaturePublicationHashRule()
        );


        Rule publicationTimeRule = new CompositeRule(true,
                new SignatureDoesNotContainPublicationRule(),
                new UserProvidedPublicationTimeNotEqualToSignaturePublicationTimeRule()
        );


        Rule verifyUsingExtenderRule = new CompositeRule(false,
                publicationTimeRule,
                new UserProvidedPublicationCreationTimeVerificationRule(),
                new ExtendingPermittedVerificationRule(),
                new UserProvidedPublicationHashMatchesExtendedResponseRule(),
                new UserProvidedPublicationTimeMatchesExtendedResponseRule(),
                new UserProvidedPublicationExtendedSignatureInputHashRule()
        );


        addRule(new CompositeRule(true, verifyUserPublicationRule, verifyUsingExtenderRule));
    }

    public String getName() {
        return "User provided publication based verification policy";
    }

    public String getType() {
        return TYPE_USER_PROVIDED_PUBLICATION_BASED_POLICY;
    }

}
