package com.guardtime.ksi.pdu;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.tlv.TLVElement;

import java.util.Date;

/**
 * An abstract factory interface to support multiple ways to create KSI Protocol Data Unit (PDU) messages.
 */
public interface PduFactory {

    //TODO javadoc
    AggregationRequest createAggregationRequest(KSIRequestContext context, DataHash imprint, Long level) throws KSIException;

    //TODO javadoc
    AggregationResponse readAggregationResponse(KSIRequestContext context, TLVElement input) throws KSIException;

    //TODO javadoc
    ExtensionRequest createExtensionRequest(KSIRequestContext context, Date aggregationTime, Date publicationTime) throws KSIException;

    //TODO javadoc
    ExtensionResponse readExtensionResponse(KSIRequestContext context, TLVElement input) throws KSIException;

}
