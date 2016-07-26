package com.guardtime.ksi.service.pdu.legazy;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.service.KSIMessageHeader;
import com.guardtime.ksi.service.KSIRequestContext;
import com.guardtime.ksi.service.pdu.AggregationRequest;
import com.guardtime.ksi.service.pdu.AggregationResponse;
import com.guardtime.ksi.service.pdu.PduFactory;
import com.guardtime.ksi.tlv.TLVElement;

/**
 * Legacy implementation of {@link PduFactory}.
 */
public class LegacyKsiPduFactory implements PduFactory {

    public AggregationRequest createAggregationRequest(KSIRequestContext context, DataHash imprint, Long level) throws KSIException {
        if (context == null) {
            throw new NullPointerException("KsiRequestContext can not be null");
        }
        if (imprint == null) {
            throw new NullPointerException("DataHash can not be null");
        }
        Long requestLevel = 0L;
        if (level != null) {
            if (level < 0) {
                throw new IllegalArgumentException("Level can not be negative");
            }
            requestLevel = level;
        }

        KSIMessageHeader header = new KSIMessageHeader(context.getLoginId(), context.getInstanceId(), context.getMessageId());
        LegacyAggregationRequestPayload request = new LegacyAggregationRequestPayload(imprint, context.getRequestId(), requestLevel);
        return new LegacyAggregationRequest(header, request, context.getLoginKey());
    }

    public AggregationResponse readAggregationResponse(KSIRequestContext context, TLVElement input) throws KSIException {
        if (context == null) {
            throw new NullPointerException("KsiRequestContext can not be null");
        }
        if (input == null) {
            throw new NullPointerException("Input TLV element can not be null");
        }
        return new LegacyAggregationResponse(input, context);
    }

}
