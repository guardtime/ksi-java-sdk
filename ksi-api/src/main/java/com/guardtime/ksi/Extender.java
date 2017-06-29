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

package com.guardtime.ksi;


import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.publication.PublicationRecord;
import com.guardtime.ksi.service.ConfigurationListener;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSIExtendingService;
import com.guardtime.ksi.unisignature.KSISignature;

import java.io.Closeable;

/**
 * An instance of this class can be obtained using {@link ExtenderBuilder} class.
 */
public interface Extender extends Closeable {

    /**
     * Extends signature to the "closest" publication in publication file.
     *
     * @param signature signature to be extended. not null.
     * @return KSISignature extended keyless signature
     * @throws KSIException when error occurs (e.g when communication with KSI service fails)
     */
    KSISignature extend(KSISignature signature) throws KSIException;

    /**
     * Extends the signature to specified publication record. The publication time of the publication record must be
     * after signature aggregation time. When signature is extended then the old calendar hash chain and publication
     * record is removed.
     *
     * @param signature         signature to be extended. not null.
     * @param publicationRecord publication record to extend. not null.
     * @return extended keyless signature with extended calendar hash chain and publication record
     * @throws KSIException when error occurs (e.g when communication with KSI service fails)
     */
    KSISignature extend(KSISignature signature, PublicationRecord publicationRecord) throws KSIException;

    /**
     * This method is used to extend signature asynchronously to closest publication. Use method {@link
     * Future#getResult()} to get the extended keyless signature.
     *
     * @param signature instance of {@link KSISignature} to extend. not null.
     * @return instance of {@link Future} future
     * @throws KSIException when error occurs (e.g when communication with KSI service fails)
     */
    Future<KSISignature> asyncExtend(KSISignature signature) throws KSIException;

    /**
     * This method is used to extend signature asynchronously to the given publication. Use method {@link
     * Future#getResult()} to get the extended keyless signature.
     *
     * @param signature         instance of {@link KSISignature} to extend. not null.
     * @param publicationRecord instance of {@link PublicationRecord} to extend the signature.
     * @return instance of {@link Future} future
     * @throws KSIException when error occurs (e.g when communication with KSI service fails)
     */
    Future<KSISignature> asyncExtend(KSISignature signature, PublicationRecord publicationRecord) throws KSIException;

    /**
     * This method is used to get the extender service that the SDK was initialized with. One could use the extender service to get
     * access to its configuration for example.
     */
    KSIExtendingService getExtendingService();

    /**
     * GetExtenderConfiguration method is used to ask extender configuration from KSI gateway/aggregator. Only supported
     * if {@link com.guardtime.ksi.pdu.PduVersion#V2} is used.
     *
     * @deprecated Deprecated since 4.10. Use {@link KSIExtendingService#getExtendingConfiguration()}
     *      in pair with {@link KSIExtendingService#registerExtenderConfigurationListener(ConfigurationListener)} instead.
     *      One can acquire instance of {@link KSIExtendingService} which a {@link KSI} instance uses by calling
     *      {@link KSI#getExtendingService()}.
     *
     * @throws UnsupportedOperationException If KSI is initialized with a service not a client.
     */
    @Deprecated
    ExtenderConfiguration getExtenderConfiguration() throws KSIException;
}

