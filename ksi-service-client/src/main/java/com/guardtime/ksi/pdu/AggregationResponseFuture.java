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
package com.guardtime.ksi.pdu;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;

/**
 * Future of the aggregation process.
 *
 * @see Future
 */
public final class AggregationResponseFuture implements Future<AggregationResponse> {

    private Future<TLVElement> requestFuture;
    private KSIRequestContext requestContext;
    private PduFactory pduFactory;
    private ServiceCredentials credentials;

    private AggregationResponse response;

    public AggregationResponseFuture(Future<TLVElement> requestFuture, KSIRequestContext requestContext, ServiceCredentials credentials, PduFactory pduFactory) {
        this.requestFuture = requestFuture;
        this.requestContext = requestContext;
        this.credentials = credentials;
        this.pduFactory = pduFactory;
    }

    public AggregationResponse getResult() throws KSIException {
        try {
            if (response == null) {
                TLVElement responseTlv = requestFuture.getResult();
                response = pduFactory.readAggregationResponse(requestContext, credentials, responseTlv);
            }
            return response;
        } catch (com.guardtime.ksi.tlv.TLVParserException e) {
            throw new KSIProtocolException("Can't parse response message", e);
        }
    }

    public boolean isFinished() {
        return requestFuture.isFinished();
    }
}
