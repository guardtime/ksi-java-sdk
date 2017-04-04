/*
 * Copyright 2013-2017 Guardtime, Inc.
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
package com.guardtime.ksi.service.ha;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import com.guardtime.ksi.service.ha.settings.SingleFunctionHAClientSettings;
import com.guardtime.ksi.service.ha.tasks.ExtendingTask;
import com.guardtime.ksi.service.ha.tasks.ServiceCallingTask;
import com.guardtime.ksi.tlv.TLVElement;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * KSI Extender Client which combines other clients for high availability and load balancing purposes.
 */
public class ExtenderHAClient extends AbstractHAClient<KSIExtenderClient, ExtensionResponse> implements KSIExtenderClient {

    public ExtenderHAClient(List<KSIExtenderClient> subclients) throws KSIException {
        this(subclients, null);
    }

    public ExtenderHAClient(List<KSIExtenderClient> subclients, SingleFunctionHAClientSettings settings) throws KSIException {
        super(subclients, settings);
    }

    public Future<TLVElement> extend(InputStream request) throws KSIClientException {
        throw new KSIClientException("ExtenderHAClient.extend(inputStream) is not supported. Use " +
                "ExtenderHAClient.extend(ksiRequestContext, aggregationTime, publicationTime) instead");
    }

    public Future<ExtensionResponse> extend(KSIRequestContext requestContext, Date aggregationTime, Date publicationTime) throws KSIException {
        final Long requestId = requestContext.getRequestId();
        Collection<KSIExtenderClient> clients = preprareClients();
        final Collection<ServiceCallingTask<ExtensionResponse>> tasks = new ArrayList<ServiceCallingTask<ExtensionResponse>>();
        for (KSIExtenderClient client : clients) {
            tasks.add(new ExtendingTask(client, requestContext, aggregationTime, publicationTime));
        }
        return callServices(tasks, requestId);
    }
}
