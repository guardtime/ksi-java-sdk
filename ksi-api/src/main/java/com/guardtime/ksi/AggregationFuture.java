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
import com.guardtime.ksi.hashing.HashException;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.legazy.LegacyKsiPduFactory;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureFactory;

import java.util.List;

/**
 * Aggregation service request response future.
 *
 * @see Future
 */
final class AggregationFuture implements Future<KSISignature> {

    private final Future<TLVElement> requestFuture;
    private final KSIRequestContext requestContext;
    private final KSISignatureFactory signatureFactory;
    private final PduFactory pduFactory;

    private KSISignature response;

    public AggregationFuture(Future<TLVElement> requestFuture, KSIRequestContext requestContext, KSISignatureFactory signatureFactory, PduFactory pduFactory) {
        this.requestFuture = requestFuture;
        this.requestContext = requestContext;
        this.signatureFactory = signatureFactory;
        this.pduFactory = pduFactory;
    }

    public final KSISignature getResult() throws KSIException {
        try {
            if (response == null) {
                TLVElement response = requestFuture.getResult();
                AggregationResponse aggregationResponse = pduFactory.readAggregationResponse(requestContext, response);
                this.response = signatureFactory.createSignature(convert(aggregationResponse.getPayload()));
            }
            return response;
        } catch (com.guardtime.ksi.tlv.TLVParserException e) {
            throw new KSIProtocolException("Can't parse response message", e);
        } catch (HashException e) {
            throw new KSIProtocolException("Hashing exception occurred when turning signature creation", e);
        }
    }

    public final boolean isFinished() {
        return this.requestFuture.isFinished();
    }

    private TLVElement convert(TLVElement response) throws TLVParserException {
        //TODO use signature factory?
        TLVElement element = new TLVElement(false, false, 0x0800);
        List<TLVElement> children = response.getChildElements();
        for (TLVElement child : children) {
            if (child.getType() > 0x800 && child.getType() < 0x900) {
                element.addChildElement(child);
            }
        }
        return element;
    }
}
