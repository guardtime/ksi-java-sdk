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

package com.guardtime.ksi.service;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.KSISignature;

/**
 * The future of the signature extension process.
 *
 * @see Future
 */
public class SignatureExtensionRequestFuture implements Future<KSISignature> {

    private ExtensionRequestFuture future;
    private PublicationRecord publicationRecord;
    private KSISignature signature;
    private KSISignature extendedSignature;

    public SignatureExtensionRequestFuture(ExtensionRequestFuture future, PublicationRecord publicationRecord, KSISignature signature) {
        this.future = future;
        this.publicationRecord = publicationRecord;
        this.signature = signature;
    }

    public KSISignature getResult() throws KSIException {
        if (extendedSignature == null) {
            CalendarHashChain result = future.getResult();
            extendedSignature = signature.extend(result, publicationRecord);
        }
        return extendedSignature;
    }

    public boolean isFinished() {
        return future.isFinished();
    }
}
