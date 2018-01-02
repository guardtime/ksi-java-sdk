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

package com.guardtime.ksi.exceptions;

/**
 * KSI Java SDK has an hierarchic exception model on which all the exceptions are ultimately based on this exception.
 * This enables developer to go from rough to fine grained exception filtering by pointing at different levels in the
 * hierarchy.
 */
public class KSIException extends Exception {

    private static final long serialVersionUID = 1;

    public KSIException(String message) {
        super(message);
    }

    public KSIException(String message, Throwable cause) {
        super(message, cause);
    }

}
