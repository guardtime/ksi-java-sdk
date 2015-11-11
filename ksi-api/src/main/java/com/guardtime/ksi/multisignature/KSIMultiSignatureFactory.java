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

package com.guardtime.ksi.multisignature;

import com.guardtime.ksi.exceptions.KSIException;

/**
 * Interface for creating multi signature containers. Implementation of this class can be used to get instance of {@link
 * KSIMultiSignature}.
 *
 * @param <C>
 *         configuration parameter implementation class
 * @param <S>
 *         multi signature implementation class
 */
public interface KSIMultiSignatureFactory<C extends MultiSignatureConfigurationParameters, S extends KSIMultiSignature> {

    /**
     * Returns the instance of {@link KSIMultiSignature}. The real implementation og {@link KSIMultiSignature} depends
     * on which implementation of {@link KSIMultiSignatureFactory} is used.
     *
     * @throws KSIException
     *         when error occurs
     */
    S create(C params) throws KSIException;

}
