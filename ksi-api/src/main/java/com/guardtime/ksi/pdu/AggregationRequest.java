package com.guardtime.ksi.pdu;

/**
 *
 */
public interface AggregationRequest {

    byte[] toByteArray();

    KSIRequestContext getRequestContext();
}
