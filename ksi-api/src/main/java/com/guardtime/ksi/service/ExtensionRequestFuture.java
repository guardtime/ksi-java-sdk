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
import com.guardtime.ksi.service.extension.ExtensionResponse;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.CalendarHashChain;
import com.guardtime.ksi.unisignature.KSISignatureComponentFactory;

/**
 * Extension service request response future.
 *
 * @see Future
 */
public class ExtensionRequestFuture implements Future<CalendarHashChain> {

    private final KSISignatureComponentFactory signatureComponentFactory;
    private final Future<TLVElement> future;
    private final KSIRequestContext context;
    private CalendarHashChain response;

    public ExtensionRequestFuture(Future<TLVElement> future, KSIRequestContext requestContext,
            KSISignatureComponentFactory signatureComponentFactory) {
        this.future = future;
        this.context = requestContext;
        this.signatureComponentFactory = signatureComponentFactory;
    }

    public CalendarHashChain getResult() throws KSIException {
        if (response == null) {
            try {
                TLVElement tlvElement = future.getResult();
                ExtensionResponse extensionResponse = new ExtensionResponse(tlvElement, context);
                response = signatureComponentFactory.createCalendarHashChain(extensionResponse.getCalendarHashChainTlvElement());
            } catch (com.guardtime.ksi.tlv.TLVParserException e) {
                throw new KSIProtocolException("Can't parse response message", e);
            }
        }
        return response;
    }

    public boolean isFinished() {
        return future.isFinished();
    }

}
