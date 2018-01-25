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

/**
 * KSI protocol related request response future.
 * <br><br>
 * Future is a design pattern for asynchronous request. A Future represents the result of an asynchronous operation.
 * It is possible to check if the computation is complete, and to retrieve the result of the operation. The result can
 * be retrieved using the method {@link #getResult()} once the computation has completed.
 * {@link #getResult()} is blocking, until the result is ready.
 * <br><br>
 * Note: while recent Java versions also provide the Future pattern this API has it's own implementation to provide backwards
 * compatibility with older Java versions.
 *
 * @param <T>
 *         future return type
 */
public interface Future<T> {

    /**
     * Retrieves the result of the request. If request is not finished this call will block until result is available.
     *
     * @return Result of the request.
     * @throws KSIException
     *         when KSI service returns an error or does not work as expected.
     */
    T getResult() throws KSIException;

    /**
     * Returns true if result is available. Does not necessarily mean that the computation is complete.
     *
     * @return True, if call is finished.
     */
    boolean isFinished();
}
