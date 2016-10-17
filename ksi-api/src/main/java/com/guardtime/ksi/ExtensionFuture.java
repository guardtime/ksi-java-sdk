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

package com.guardtime.ksi;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.*;

import static java.util.Arrays.asList;

/**
 * The future of the signature extension process.
 *
 * @see Future
 */
final class ExtensionFuture implements Future<KSISignature> {

    private final Future<TLVElement> future;
    private final PublicationRecord publicationRecord;
    private final KSISignature signature;
    private final KSIRequestContext context;
    private final KSISignatureFactory signatureFactory;
    private final KSISignatureComponentFactory signatureComponentFactory;
    private final PduFactory pduFactory;

    private KSISignature extendedSignature;

    public ExtensionFuture(Future<TLVElement> future, PublicationRecord publicationRecord, KSISignature signature, KSIRequestContext context, KSISignatureComponentFactory signatureComponentFactory, PduFactory pduFactory, KSISignatureFactory signatureFactory) {
        this.future = future;
        this.publicationRecord = publicationRecord;
        this.signature = signature;
        this.context = context;
        this.signatureComponentFactory = signatureComponentFactory;
        this.pduFactory = pduFactory;
        this.signatureFactory = signatureFactory;
    }

    public KSISignature getResult() throws KSIException {
        if (extendedSignature == null) {
            try {
                TLVElement tlvElement = future.getResult();
                ExtensionResponse extensionResponse = pduFactory.readExtensionResponse(context, tlvElement);
                CalendarHashChain calendarHashChain = signatureComponentFactory.createCalendarHashChain(extensionResponse.getPayload());
                SignaturePublicationRecord publication = signatureComponentFactory.createPublicationRecord(publicationRecord.getPublicationData(), publicationRecord.getPublicationReferences(), publicationRecord.getPublicationRepositoryURIs());
                extendedSignature = signatureFactory.createSignature(asList(signature.getAggregationHashChains()), calendarHashChain, null, publication, signature.getRfc3161Record());

            } catch (com.guardtime.ksi.tlv.TLVParserException e) {
                throw new KSIProtocolException("Can't parse response message", e);
            }
        }
        return extendedSignature;
    }

    public boolean isFinished() {
        return future.isFinished();
    }
}
