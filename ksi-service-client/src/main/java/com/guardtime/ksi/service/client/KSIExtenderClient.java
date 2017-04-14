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
package com.guardtime.ksi.service.client;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.ExtensionResponseFuture;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.Future;

import java.io.Closeable;
import java.util.Date;

/**
 * KSI client for extender service
 */
public interface KSIExtenderClient extends Closeable {

    /**
     * Used to extend existing signatures.
     *
     * @param requestContext  - instance of {@link KSIRequestContext}.
     * @param aggregationTime - aggregation time of the existing signature.
     * @param publicationTime - publication time to which the existing signature is to be extended.
     * @return instance of {@link ExtensionResponseFuture} containing calendar chains needed to extend the signature.
     */
    Future<ExtensionResponse> extend(KSIRequestContext requestContext, Date aggregationTime, Date publicationTime) throws
            KSIException;

    /**
     * @param requestContext - instance of {@link KSIRequestContext}.
     * @return {@link ExtenderConfiguration} one should rely on when using this client
     */
    ExtenderConfiguration getExtenderConfiguration(KSIRequestContext requestContext) throws KSIException;

}
