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

package com.guardtime.ksi.unisignature.verifier;

/**
 * This enum contains the statuses of KSI signature verification. Any verification process may finish with three
 * possible outcomes: <ul> <li><b>Verification succeeded</b>, which means there's a way to prove the correctness of the
 * signature</li> <li><b>Verification not possible</b>, which means there is not enough data to prove or disprove the
 * correctness of the signature</li> <li><b>Verification failed</b>, which means the signature is definitely invalid or
 * the document does not match with the signature</li> </ul>
 */
public enum VerificationResultCode {

    /**
     * Verification succeeded, which means there's a way to prove the correctness of the signature
     */
    OK,

    /**
     * Verification failed, which means the signature is definitely invalid or the document does not match with the
     * signature
     */
    FAIL,

    /**
     * Verification not possible, which means there is not enough data to prove or disprove the correctness of the
     * signature
     */
    NA

}
