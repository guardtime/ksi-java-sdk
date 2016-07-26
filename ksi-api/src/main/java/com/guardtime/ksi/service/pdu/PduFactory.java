package com.guardtime.ksi.service.pdu;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.service.KSIRequestContext;
import com.guardtime.ksi.tlv.TLVInputStream;

/**
 * An abstract factory interface to support multiple ways to create KSI Protocol Data Unit (PDU) messages.
 */
public interface PduFactory {

    AggregationRequest createAggregationRequest(KSIRequestContext context, DataHash imprint, Long level) throws KSIException;

    AggregationRequest readAggregationResponse(TLVInputStream input) throws KSIException;

}
