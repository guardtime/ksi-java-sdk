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
import com.guardtime.ksi.unisignature.*;
import com.guardtime.ksi.unisignature.inmemory.InMemoryKsiSignatureComponentFactory;

import static java.util.Arrays.asList;

/**
 * The future of the signature extension process.
 *
 * @see Future
 */
public class SignatureExtensionRequestFuture implements Future<KSISignature> {

    private static final KSISignatureComponentFactory COMPONENT_FACTORY = new InMemoryKsiSignatureComponentFactory();
    private ExtensionRequestFuture future;
    private PublicationRecord publicationRecord;
    private KSISignature signature;
    private KSISignature extendedSignature;
    private KSISignatureFactory signatureFactory;

    public SignatureExtensionRequestFuture(ExtensionRequestFuture future, PublicationRecord publicationRecord, KSISignature signature, KSISignatureFactory signatureFactory) {
        this.future = future;
        this.publicationRecord = publicationRecord;
        this.signature = signature;
        this.signatureFactory = signatureFactory;
    }

    public KSISignature getResult() throws KSIException {
        if (extendedSignature == null) {
            CalendarHashChain result = future.getResult();
            SignaturePublicationRecord signaturePublicationRecord = COMPONENT_FACTORY.createPublicationRecord(publicationRecord.getPublicationData(), publicationRecord.getPublicationReferences(), publicationRecord.getPublicationRepositoryURIs());
            extendedSignature = signatureFactory.createSignature(asList(signature.getAggregationHashChains()), result, null, signaturePublicationRecord, signature.getRfc3161Record());
        }
        return extendedSignature;
    }

    public boolean isFinished() {
        return future.isFinished();
    }
}
