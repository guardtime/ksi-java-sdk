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
package com.guardtime.ksi.service.ha;

/**
 * Settings for the HAClient. Can be used to set the balance between load-balancing and high availability.
 */
public class HAClientSettings {

    private final Integer signingClientsForRequest;
    private final Integer extendingClientsForRequest;

    /**
     * @param signingClientsForRequest
     *          To how many subclients any single signing request is sent in parallel.  If null then it can assumed that all the requests is sent to all the subclients.
     * @param extendingClientsForRequest
     *          To how many subclients any single extending request is sent in parallel. If null then it can assumed that all the requests is sent to all the subclients.
     */
    public HAClientSettings(Integer signingClientsForRequest, Integer extendingClientsForRequest) {
        this.signingClientsForRequest = signingClientsForRequest;
        this.extendingClientsForRequest = extendingClientsForRequest;
    }

    /**
     * @return Number of subclients that any single signing request is sent in parallel. If null then it can assumed that all the requests is sent to all the subclients.
     */
    public Integer getSigningClientsForRequest() {
        return signingClientsForRequest;
    }

    /**
     * @return Number of subclients that any single extending request is sent in parallel. If null then it can assumed that all the requests is sent to all the subclients.
     */
    public Integer getExtendingClientsForRequest() {
        return extendingClientsForRequest;
    }

    @Override
    public String toString() {
        return "HAClientSettings{" +
                "signingClientsForRequest=" + signingClientsForRequest +
                ", extendingClientsForRequest=" + extendingClientsForRequest +
                '}';
    }
}
