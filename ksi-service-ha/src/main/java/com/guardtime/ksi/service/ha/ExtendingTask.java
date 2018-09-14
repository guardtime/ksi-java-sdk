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
package com.guardtime.ksi.service.ha;

import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.service.client.KSIClientException;

import java.util.Date;
import java.util.concurrent.Callable;

/**
 * Creates an extension request.
 */
class ExtendingTask implements Callable<ExtensionResponse> {

    private final KSIExtendingService service;
    private Date aggregationTime;
    private Date publicationTime;

    /**
     * @param service
     *          {@link KSIExtendingService} used for the extension request.
     * @param aggregationTime
     *          aggregation time of the signature to be extended.
     * @param publicationTime
     *          publication time until which the signature is to be extended.
     */
    public ExtendingTask(KSIExtendingService service, Date aggregationTime, Date publicationTime) {
        this.service = service;
        this.aggregationTime = aggregationTime;
        this.publicationTime = publicationTime;
    }

    public ExtensionResponse call() throws KSIClientException {
        try {
            return service.extend(aggregationTime, publicationTime).getResult();
        } catch (Exception e) {
            throw new KSIClientException("Extending via client '" + service + "' failed", e);
        }
    }
}
