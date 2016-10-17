package com.guardtime.ksi.pdu;

/**
 * Interface to generate different identifiers for PDU requests
 */
public interface PduIdentifierProvider {

    // TODO javadoc
    long getInstanceId();

    // TODO javadoc
    long nextRequestId();

    // TODO javadoc
    long nextMessageId();

}
