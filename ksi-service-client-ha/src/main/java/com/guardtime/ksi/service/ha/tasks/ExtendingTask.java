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
package com.guardtime.ksi.service.ha.tasks;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.client.KSIExtenderClient;
import java.util.Date;

public class ExtendingTask extends ServiceCallingTask<ExtensionResponse> {

    private final KSIExtenderClient client;
    private Date aggregationTime;
    private Date publicationTime;

    public ExtendingTask(KSIExtenderClient client, KSIRequestContext requestContext, Date aggregationTime, Date publicationTime) {
        super(createClientKey(client), requestContext);
        this.client = client;
        this.aggregationTime = aggregationTime;
        this.publicationTime = publicationTime;
    }


    public ExtensionResponse completeTask() throws KSIException {
        return client.extend(requestContext, aggregationTime, publicationTime).getResult();
    }
}
