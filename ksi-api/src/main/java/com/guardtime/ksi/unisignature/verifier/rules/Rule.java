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

package com.guardtime.ksi.unisignature.verifier.rules;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.verifier.RuleResult;
import com.guardtime.ksi.unisignature.verifier.SignatureVerifier;
import com.guardtime.ksi.unisignature.verifier.VerificationContext;
import com.guardtime.ksi.unisignature.verifier.policies.Policy;

/**
 * Rule contains one logical step of signature verification policy. Rules are reusable and can be used by multiple
 * different policies. Rules are registered in the {@link Policy} and will be executed by {@link SignatureVerifier}
 *
 * @see Policy
 * @see SignatureVerifier
 */
public interface Rule {

    /**
     * Method for verifying the signature.
     *
     * @param context
     *         context to be used for this rule for verification.
     * @return rule result
     * @throws KSIException
     *         if exception occures.
     */
    RuleResult verify(VerificationContext context) throws KSIException;

}
