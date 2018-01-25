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

package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;

public class InvalidSignatureContentException extends KSIException {

    private KSISignature signature;
    private VerificationResult verificationResult;

    public InvalidSignatureContentException(InMemoryKsiSignature signature, VerificationResult verificationResult) {
        super("Signature (inputHash:" + signature.getInputHash() + ", extended=" + signature.isExtended() + ") is invalid: " + verificationResult.getErrorCode() + "('" + verificationResult.getErrorCode().getMessage() + "')");
        this.signature = signature;
        this.verificationResult = verificationResult;
    }

    public KSISignature getSignature() {
        return signature;
    }

    public VerificationResult getVerificationResult() {
        return verificationResult;
    }
}
