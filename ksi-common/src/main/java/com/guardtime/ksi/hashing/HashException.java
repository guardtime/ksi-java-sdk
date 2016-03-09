/*
 * Copyright 2013-2015 Guardtime, Inc.
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

package com.guardtime.ksi.hashing;

import com.guardtime.ksi.exceptions.KSIException;

/**
 * This exception is common exception for exception thrown by {@link DataHasher}, {@link DataHash} or {@link
 * HashAlgorithm} classes.
 *
 * @see HashAlgorithmNotImplementedException
 * @see InvalidHashFormatException
 */
public class HashException extends KSIException {

    private static final long serialVersionUID = 1;

    HashException(String message) {
        super(message);
    }

    HashException(String message, Throwable cause) {
        super(message, cause);
    }
}
