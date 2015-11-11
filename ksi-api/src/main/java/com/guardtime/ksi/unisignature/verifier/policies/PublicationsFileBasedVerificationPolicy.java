/*
 * Copyright 2013-2015 Guardtime, Inc.
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
 * This rule can be used to verify signatures using publications file.
 */
public class PublicationsFileBasedVerificationPolicy extends InternalVerificationPolicy {

    public PublicationsFileBasedVerificationPolicy() {

        Rule signaturePublicationPresentInPubFileRule = new CompositeRule(false,
                new SignaturePublicationRecordExistenceRule(),
                new PublicationsFileContainsSignaturePublicationRule());

        Rule useExtendingRule = new CompositeRule(false,
                new SignatureDoesNotContainPublicationRule(),
                new PublicationsFileContainsPublicationRule(),
                new ExtendingPermittedVerificationRule(),
                new PublicationsFilePublicationHashMatchesExtenderResponseRule(),
                new PublicationsFilePublicationTimeMatchesExtenderResponseRule(),
                new PublicationsFileExtendedSignatureInputHashRule()
        );

        addRule(new CompositeRule(true,
                signaturePublicationPresentInPubFileRule,
                useExtendingRule));
    }

    public String getName() {
        return "Publications file based verification policy";
    }

}
