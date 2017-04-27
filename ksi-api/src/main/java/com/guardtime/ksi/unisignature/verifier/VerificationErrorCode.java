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

package com.guardtime.ksi.unisignature.verifier;

/**
 * This enum contains all the error codes that may be returned by keyless signature verification process.
 */
public enum VerificationErrorCode {

    GEN_1("GEN-1", "Wrong document"),
    GEN_2("GEN-2", "Verification inconclusive"),
    INT_01("INT-01", "Inconsistent aggregation hash chains"),
    INT_02("INT-02", "Inconsistent aggregation hash chain aggregation times"),
    INT_03("INT-03", "Calendar hash chain input hash mismatch"),
    INT_04("INT-04", "Calendar hash chain aggregation time mismatch"),
    INT_05("INT-05", "Calendar hash chain shape inconsistent with aggregation time"),
    INT_06("INT-06", "Calendar hash chain time inconsistent with calendar authentication record time"),
    INT_07("INT-07", "Calendar hash chain time inconsistent with publication time"),
    INT_08("INT-08", "Calendar hash chain root hash is inconsistent with calendar authentication record input hash"),
    INT_09("INT-09", "Calendar hash chain root hash is inconsistent with published hash value"),
    INT_10("INT-10", "Aggregation hash chain chain index mismatch"),
    INT_11("INT-11", "The metadata record in the aggregation hash chain may not be trusted"),
    INT_12("INT-12", "Inconsistent chain indexes"),
    PUB_01("PUB-01", "Extender response calendar root hash mismatch"),
    PUB_02("PUB-02", "Extender response inconsistent"),
    PUB_03("PUB-03", "Extender response input hash mismatch"),
    PUB_04("PUB-04", "Publication record hash and user provided publication hash mismatch"),
    PUB_05("PUB-05", "Publication record hash and publications file publication hash mismatch"),
    KEY_01("KEY-01", "Certificate not found"),
    KEY_02("KEY-02", "PKI signature not verified with certificate"),
    CAL_01("CAL-01", "Calendar root hash mismatch between signature and calendar database chain"),
    CAL_02("CAL-02", "Aggregation hash chain root hash and calendar database hash chain input hash mismatch"),
    CAL_03("CAL-03", "Aggregation time mismatch"),
    CAL_04("CAL-04", "Calendar hash chain right links are inconsistent");

    private final String code;
    private final String message;

    VerificationErrorCode(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
