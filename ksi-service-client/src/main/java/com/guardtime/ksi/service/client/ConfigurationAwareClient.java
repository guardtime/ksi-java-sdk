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

import com.guardtime.ksi.pdu.PduVersion;

import java.io.Closeable;

/**
 * ConfigurationAwareClient is a client which connects to a service with same configuration every time
 */
public interface ConfigurationAwareClient extends Closeable {
    /**
     * Returns the service credentials used by this service
     */
    ServiceCredentials getServiceCredentials();

    /**
     * Returns the PDU format version of the client
     */
    PduVersion getPduVersion();
}
