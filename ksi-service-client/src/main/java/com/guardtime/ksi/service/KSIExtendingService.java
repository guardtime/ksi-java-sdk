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
package com.guardtime.ksi.service;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.ExtensionResponseFuture;

import java.io.Closeable;
import java.util.Date;
import java.util.List;

/**
 * Provides KSI services to communicate with the extender(s).
 */
public interface KSIExtendingService extends Closeable {

    /**
     * Extends existing signatures.
     *
     * @param aggregationTime aggregation time of the existing signature.
     * @param publicationTime publication time to which the existing signature is to be extended.
     *
     * @return Instance of {@link ExtensionResponseFuture} containing calendar chains needed to extend the signature.
     * @throws KSIException in case any error occurs.
     */
    Future<ExtensionResponse> extend(Date aggregationTime, Date publicationTime) throws KSIException;

    /**
     * Gets the subclients in case of the implementation that combines multiple clients. If the implementation
     * is a client that directly connects to a single gateway, an empty list will be returned.
     *
     * @return List of subclients.
     */
    List<KSIExtendingService> getSubExtendingServices();

    /**
     * Registers a new {@link ConfigurationListener}&lt;{@link ExtenderConfiguration}&gt; for the client. Each time client's configuration
     * is updated, this listener is called.
     *
     * @param listener an instance of {@link ConfigurationListener}&lt;{@link ExtenderConfiguration}&gt;.
     */
    void registerExtenderConfigurationListener(ConfigurationListener<ExtenderConfiguration> listener);

    /**
     * Makes the client ask for configuration update. On completion of the update registered {@link ConfigurationListener}s
     * are called.
     *
     * @return Future of the {@link ExtenderConfiguration}.
     */
    Future<ExtenderConfiguration> getExtendingConfiguration();

}
