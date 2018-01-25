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

package com.guardtime.ksi.publication.adapter;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.publication.PublicationsFile;
import com.guardtime.ksi.service.client.KSIPublicationsFileClient;

/**
 * Adapter interface for publication file clients
 */
public interface PublicationsFileClientAdapter {

    /**
     * Returns the instance of the {@link PublicationsFile}.
     */
    PublicationsFile getPublicationsFile() throws KSIException;

    /**
     * Returns the publication file client used by adapter
     */
    KSIPublicationsFileClient getPublicationsFileClient();

}
