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

package com.guardtime.ksi.publication;

import com.guardtime.ksi.exceptions.KSIException;

import java.io.InputStream;

/**
 * Interface for creating publications files.
 */
public interface PublicationsFileFactory {

    /**
     * Reads the publications file from given input stream.
     *
     * @param input
     *         input stream to read. not null
     * @return the instance of the {@link PublicationsFile}
     * @throws KSIException
     *         when reading input stream fails.
     */
    PublicationsFile create(InputStream input) throws KSIException;

}
