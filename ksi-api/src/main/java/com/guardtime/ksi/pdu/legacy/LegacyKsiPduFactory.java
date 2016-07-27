package com.guardtime.ksi.pdu.legacy;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.PduMessageHeader;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.*;
import com.guardtime.ksi.tlv.TLVElement;

import java.util.Date;

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

        PduMessageHeader header = new PduMessageHeader(context.getLoginId(), context.getInstanceId(), context.getMessageId());
        LegacyAggregationRequestPayload request = new LegacyAggregationRequestPayload(imprint, context.getRequestId(), requestLevel);
        return new LegacyAggregationRequest(header, request, context);
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

    public ExtensionRequest createExtensionRequest(KSIRequestContext context, Date aggregationTime, Date publicationTime) throws KSIException {
        if (context == null) {
            throw new NullPointerException("KsiRequestContext can not be null");
        }
        if (aggregationTime == null) {
            throw new NullPointerException("AggregationTime can not be null");
        }
        PduMessageHeader header = new PduMessageHeader(context.getLoginId(), context.getInstanceId(), context.getMessageId());
        LegacyExtensionRequestPayload extensionRequest = new LegacyExtensionRequestPayload(aggregationTime, publicationTime, context.getRequestId());
        return new LegacyExtensionRequest(header, extensionRequest, context.getLoginKey());
    }

    public ExtensionResponse readExtensionResponse(KSIRequestContext context, TLVElement input) throws KSIException {
        if (context == null) {
            throw new NullPointerException("KsiRequestContext can not be null");
        }
        if (input == null) {
            throw new NullPointerException("Input TLV element can not be null");
        }
        return new LegacyExtensionResponse(input, context);
    }

}
