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
package com.guardtime.ksi.service.ha.tasks;

import com.guardtime.ksi.pdu.AggregatorConfiguration;
import com.guardtime.ksi.pdu.SubclientConfiguration;
import com.guardtime.ksi.service.client.KSISigningClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.Callable;

/**
 * Task for asking aggregators configuration.
 */
public class AggregatorConfigurationTask implements Callable<SubclientConfiguration<AggregatorConfiguration>> {

    private static final Logger logger = LoggerFactory.getLogger(AggregatorConfiguration.class);

    private final KSISigningClient client;
    /**
     * @param client
     *          {@link KSISigningClient} which's configuration is to be asked.
     */
    public AggregatorConfigurationTask(KSISigningClient client) {
        this.client = client;
    }

    public SubclientConfiguration<AggregatorConfiguration> call() throws Exception {
        try {
            return new SubclientConfiguration<AggregatorConfiguration>(client.toString(), client.getAggregatorConfiguration());
        } catch (Exception e) {
            logger.warn("Asking configuration from subclient '" + client + "' failed", e);
            return new SubclientConfiguration<AggregatorConfiguration>(client.toString(), e);
        }
    }

}
