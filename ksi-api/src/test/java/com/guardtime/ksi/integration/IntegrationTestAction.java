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

package com.guardtime.ksi.integration;

import com.guardtime.ksi.unisignature.verifier.policies.CalendarBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.InternalVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.KeyBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;
import com.guardtime.ksi.unisignature.verifier.policies.PublicationsFileBasedVerificationPolicy;
import com.guardtime.ksi.unisignature.verifier.policies.UserProvidedPublicationBasedVerificationPolicy;

public enum IntegrationTestAction {
    PARSING("parsing", new InternalVerificationPolicy()),
    NOT_IMPLEMENTED("not-implemented", new InternalVerificationPolicy()),
    INTERNAL("internal", new InternalVerificationPolicy()),
    KEY("key", new KeyBasedVerificationPolicy()),
    CALENDAR("calendar", new CalendarBasedVerificationPolicy()),
    USER_PUBLICATION("userPublication", new UserProvidedPublicationBasedVerificationPolicy()),
    PUBLICATIONS_FILE("publicationsFile", new PublicationsFileBasedVerificationPolicy());

    IntegrationTestAction(String name, Policy policy) {
        this.name = name;
        this.policy = policy;
    }

    private final String name;

    private final Policy policy;

    public String getName() {
        return this.name;
    }

    public Policy getPolicy() {
        return this.policy;
    }


    static String nameNormalize(String name) {
        return name.toUpperCase();
    }

    public static IntegrationTestAction getByName(String name) {
        for (IntegrationTestAction action : values()) {
            if (action.getName().equals(name)) {
                return action;
            }
        }
        //TODO: Default to not_implemented for skipping instead?
        throw new IllegalArgumentException("Invalid action '" + name + "'.");
    }

    public String toString() {
        return "Action: " + this.getName() + "\nPolicy: " + this.getPolicy().toString();
    }
}
