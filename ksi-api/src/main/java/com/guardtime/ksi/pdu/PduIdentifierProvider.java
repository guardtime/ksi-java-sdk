package com.guardtime.ksi.pdu;

/**
 * Interface to generate different identifiers for PDU requests
 */
public interface PduIdentifierProvider {

    long getInstanceId();

    long nextRequestId();

    long nextMessageId();

}
