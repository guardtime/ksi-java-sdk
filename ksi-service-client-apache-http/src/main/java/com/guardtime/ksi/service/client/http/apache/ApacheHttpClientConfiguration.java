package com.guardtime.ksi.service.client.http.apache;

public interface ApacheHttpClientConfiguration {

    int getMaxThreadCount();
    int getMaxTotalConnectionCount();
    int getMaxRouteConnectionCount();
}
