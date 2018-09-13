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

package com.guardtime.ksi.unisignature.verifier;

import java.util.List;

/**
 * This interface represents a KSI signature verification result.
 */
public interface VerificationResult {

    /**
     * Returns true if signature verification is successful.
     *
     * @return true if signature is valid.
     */
    boolean isOk();

    /**
     * Return null if signature is valid. If signature is invalid then instance of {@link VerificationErrorCode} is
     * returned.
     *
     * @return returns an instance of {@link VerificationErrorCode} when signature is invalid. returns null otherwise.
     */
    VerificationErrorCode getErrorCode();

    /**
     * Returns list of {@link PolicyVerificationResult} objects.
     *
     * @return ist of {@link PolicyVerificationResult} objects
     */
    List<PolicyVerificationResult> getPolicyVerificationResults();

}
