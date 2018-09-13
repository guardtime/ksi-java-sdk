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

package com.guardtime.ksi.unisignature.verifier.policies;

import com.guardtime.ksi.unisignature.verifier.rules.CalendarAuthenticationRecordExistenceRule;
import com.guardtime.ksi.unisignature.verifier.rules.CalendarAuthenticationRecordSignatureVerificationRule;
import com.guardtime.ksi.unisignature.verifier.rules.CalendarHashChainAlgorithmDeprecatedRule;
import com.guardtime.ksi.unisignature.verifier.rules.CalendarHashChainExistenceRule;
import com.guardtime.ksi.unisignature.verifier.rules.CertificateExistenceRule;
import com.guardtime.ksi.unisignature.verifier.rules.CertificateValidityRule;

/**
 * KSI Signature verification policy. Can be used if the KSI signature contains a calendar hash chain and a calendar
 * authentication record. <p/><p>NB! Key-based verification should be used for short-term verification before a
 * publication becomes available.</p>
 */
public class KeyBasedVerificationPolicy extends InternalVerificationPolicy {

    private static final String TYPE_KEY_BASED_POLICY = "KEY_BASED_POLICY";

    public KeyBasedVerificationPolicy() {
        addRule(new CalendarHashChainExistenceRule());
        addRule(new CalendarHashChainAlgorithmDeprecatedRule());
        addRule(new CalendarAuthenticationRecordExistenceRule());
        addRule(new CertificateExistenceRule());
        addRule(new CertificateValidityRule());
        addRule(new CalendarAuthenticationRecordSignatureVerificationRule());
    }

    public String getName() {
        return "Key-based verification policy";
    }

    public String getType() {
        return TYPE_KEY_BASED_POLICY;
    }

}
