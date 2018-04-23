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
import com.guardtime.ksi.service.client.ServiceCredentials;
import com.guardtime.ksi.tlv.TLVElement;

import java.util.Date;

public interface ExtenderPduFactory {

    /**
     * Creates a new extension request.
     */
    ExtensionRequest createExtensionRequest(KSIRequestContext context, ServiceCredentials credentials, Date aggregationTime, Date publicationTime) throws KSIException;

    /**
     * Reads an extension response.
     */
    ExtensionResponse readExtensionResponse(KSIRequestContext context, ServiceCredentials credentials, TLVElement input) throws KSIException;

    /**
     * Creates an extension configuration request.
     */
    ExtensionRequest createExtensionConfigurationRequest(KSIRequestContext requestContext, ServiceCredentials credentials) throws KSIException;

    /**
     * Reads an extension configuration response.
     */
    ExtenderConfiguration readExtenderConfigurationResponse(ServiceCredentials credentials, TLVElement input) throws KSIException;

}
