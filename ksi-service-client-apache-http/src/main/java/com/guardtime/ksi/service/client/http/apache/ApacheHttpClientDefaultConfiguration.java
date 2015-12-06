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
package com.guardtime.ksi.service.client.http.apache;

/**
 * Basic implementation of {@link ApacheHttpClientConfiguration} that uses predefined values for the configuration.
 */
public class ApacheHttpClientDefaultConfiguration implements ApacheHttpClientConfiguration {
    private int maxThreadCount;
    private int maxTotalConnectionCount;
    private int maxRouteConnectionCount;

    public ApacheHttpClientDefaultConfiguration() {
        this.maxThreadCount = 10;
        this.maxTotalConnectionCount = 1000;
        this.maxRouteConnectionCount = 1000;
    }

    public int getMaxThreadCount() {
        return this.maxThreadCount;
    }

    public int getMaxTotalConnectionCount() {
        return this.maxTotalConnectionCount;
    }

    public int getMaxRouteConnectionCount() {
        return this.maxRouteConnectionCount;
    }
}
