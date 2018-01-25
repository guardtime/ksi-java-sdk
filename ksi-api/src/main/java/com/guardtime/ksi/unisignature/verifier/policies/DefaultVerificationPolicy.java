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

/**
 * Used to verify extended and not extended signatures with publications file, verification procedure:
 * <ul>
 * <li>If the signature is already extended, performs publication-based verification and reports the result.</li>
 * <li>If the signature is not extended but is old enough to extend, tries to extend it.</li>
 * <ul>
 * <li>If extending fails for technical reasons, throws technical error.</li>
 * <li>If extending fails for cryptographical reasons (extender response inconsistent with signature), reports the
 * result.</li>
 * <li>If extending succeeds, performs publication-based verification and reports the result.</li>
 * </ul>
 * <li>If publication-based verification results in NA, performs key-based verification and reports the result.</li>
 * </ul>
 *
 * Note: Older signature verification may fail if extender is not provided because publications file does not
 * contain old keys for key-based verification.
 */
public class DefaultVerificationPolicy extends PublicationsFileBasedVerificationPolicy {

    private static final String TYPE_DEFAULT_POLICY = "DEFAULT_POLICY";

    public DefaultVerificationPolicy() {
        setFallbackPolicy(new KeyBasedVerificationPolicy());
    }

    public String getName() {
        return "Default verification policy";
    }

    public String getType() {
        return TYPE_DEFAULT_POLICY;
    }

    @Override
    public final void setFallbackPolicy(Policy policy) {
        if (getFallbackPolicy() != null) {
            getFallbackPolicy().setFallbackPolicy(policy);
        } else {
            super.setFallbackPolicy(policy);
        }
    }
}
