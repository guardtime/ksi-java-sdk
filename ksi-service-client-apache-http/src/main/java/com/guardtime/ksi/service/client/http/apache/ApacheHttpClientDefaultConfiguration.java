package com.guardtime.ksi.service.client.http.apache;

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
