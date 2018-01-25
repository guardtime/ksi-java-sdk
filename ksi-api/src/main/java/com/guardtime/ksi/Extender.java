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
 * Extending a KSI signature. An instance of this class can be obtained using {@link ExtenderBuilder} class.
 */
public interface Extender extends Closeable {

    /**
     * Extends the signature to the closest publication in publications file.
     *
     * @param signature {@link KSISignature} to be extended, not null.
     * @return Extended KSI signature ({@link KSISignature}).
     * @throws KSIException when error occurs (e.g. when communication with KSI service fails).
     */
    KSISignature extend(KSISignature signature) throws KSIException;

    /**
     * Extends the signature to specified publication record. The publication time of the publication record must be
     * after signature aggregation time. When signature is extended, the old calendar hash chain and publication
     * record is removed.
     *
     * @param signature         {@link KSISignature} to be extended, not null.
     * @param publicationRecord publication record ({@link PublicationRecord}) to extend to, not null.
     * @return Extended KSI signature with extended calendar hash chain and publication record.
     * @throws KSIException when error occurs (e.g. when communication with KSI service fails).
     */
    KSISignature extend(KSISignature signature, PublicationRecord publicationRecord) throws KSIException;

    /**
     * Extends the signature asynchronously to the closest publication in publications file. Use method {@link
     * Future#getResult()} to get the extended KSI signature.
     *
     * @param signature {@link KSISignature} to be extended, not null.
     * @return Instance of {@link Future}.
     * @throws KSIException when error occurs (e.g. when communication with KSI service fails).
     */
    Future<KSISignature> asyncExtend(KSISignature signature) throws KSIException;

    /**
     * Extends the signature asynchronously to the specified publication record. Use method {@link
     * Future#getResult()} to get the extended KSI signature.
     *
     * @param signature         {@link KSISignature} to be extended, not null.
     * @param publicationRecord publication record ({@link PublicationRecord}) to extend the signature to.
     * @return Instance of {@link Future}.
     * @throws KSIException when error occurs (e.g. when communication with KSI service fails).
     */
    Future<KSISignature> asyncExtend(KSISignature signature, PublicationRecord publicationRecord) throws KSIException;

    /**
     * Gets the extender service that the SDK was initialized with. E.g. to get access to extender's configuration.
     */
    KSIExtendingService getExtendingService();

    /**
     * Asks the extender configuration from KSI gateway/aggregator. Only supported
     * if {@link com.guardtime.ksi.pdu.PduVersion#V2} is used.
     *
     * @deprecated Deprecated since 4.10. Use {@link KSIExtendingService#getExtendingConfiguration()}
     *      in pair with {@link KSIExtendingService#registerExtenderConfigurationListener(ConfigurationListener)} instead.
     *      To acquire the {@link KSIExtendingService} which a {@link KSI} instance uses, call
     *      {@link KSI#getExtendingService()}.
     *
     * @throws UnsupportedOperationException if KSI is initialized with a service not a client.
     */
    @Deprecated
    ExtenderConfiguration getExtenderConfiguration() throws KSIException;
}
