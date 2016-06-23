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
package com.guardtime.ksi.service.client.http.apache;

/**
 * Basic implementation of {@link ApacheHttpClientConfiguration} that uses predefined values for the configuration.
 */
public class ApacheHttpClientSimpleConfiguration implements ApacheHttpClientConfiguration {
    private static final int MAX_THREAD_COUNT = 10;
    private static final int MAX_TOTAL_CONNECTION_COUNT = 1000;
    private static final int MAX_ROUTE_CONNECTION_COUNT = 1000;

    private int maxThreadCount;
    private int maxTotalConnectionCount;
    private int maxRouteConnectionCount;

    public ApacheHttpClientSimpleConfiguration() {
        this(MAX_THREAD_COUNT, MAX_TOTAL_CONNECTION_COUNT, MAX_ROUTE_CONNECTION_COUNT);
    }

    public ApacheHttpClientSimpleConfiguration(int maxThreadCount, int maxTotalConnectionCount, int maxRouteConnectionCount) {
        this.maxThreadCount = maxThreadCount;
        this.maxTotalConnectionCount = maxTotalConnectionCount;
        this.maxRouteConnectionCount = maxRouteConnectionCount;
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
