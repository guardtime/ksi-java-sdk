package com.guardtime.ksi.service;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.ExtenderConfiguration;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.ExtensionResponseFuture;
import com.guardtime.ksi.service.client.ConfigurationListener;

import java.io.Closeable;
import java.util.Date;
import java.util.List;

/**
 * Provides KSI services to communicate with extender(s).
 */
public interface KSIExtendingService extends Closeable {

    /**
     * Used to extend existing signatures.
     *
     * @param aggregationTime - aggregation time of the existing signature.
     * @param publicationTime - publication time to which the existing signature is to be extended.
     * @return instance of {@link ExtensionResponseFuture} containing calendar chains needed to extend the signature.
     */
    Future<ExtensionResponse> extend(Date aggregationTime, Date publicationTime) throws KSIException;

    /**
     * If the implementation combines multiple clients then this method can be used to get those subservices. If the implementation
     * is a client that directly connects to a single gateway then it will return an empty list.
     */
    List<KSIExtendingService> getSubExtendingServices();

    /**
     * Registers a new {@link ConfigurationListener <ExtenderConfiguration>} for the client. Each time client's configuration is
     * update is handled, this listener is called.
     */
    void registerExtenderConfigurationListener(ConfigurationListener<ExtenderConfiguration> listener);

    /**
     * Makes the client ask for configuration update. On completion of the update config registered {@link ConfigurationListener}s
     * are called
     */
    void sendExtenderConfigurationRequest();

}
