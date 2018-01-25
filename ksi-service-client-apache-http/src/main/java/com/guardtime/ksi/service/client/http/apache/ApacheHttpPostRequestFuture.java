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
package com.guardtime.ksi.service.client.http.apache;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.http.HttpPostRequestFuture;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;
import org.apache.http.HttpResponse;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

/**
 * Apache HTTP client specific response future class.
 */
public class ApacheHttpPostRequestFuture extends HttpPostRequestFuture {

    private Future<HttpResponse> future;

    public ApacheHttpPostRequestFuture(Future<HttpResponse> future) {
        this.future = future;
    }

    public boolean isFinished() {
        return future.isDone();
    }

    public TLVElement getResult() throws KSIException {
        InputStream input = null;
        try {
            HttpResponse response = future.get();
            int statusCode = response.getStatusLine().getStatusCode();
            String responseMessage = response.getStatusLine().getReasonPhrase();
            input = response.getEntity().getContent();
            return parse(statusCode, responseMessage, input);
        } catch (InterruptedException | IOException | ExecutionException e) {
            throw new KSIClientException("Getting KSI response failed", e);
        } finally {
            Util.closeQuietly(input);
        }
    }

}
