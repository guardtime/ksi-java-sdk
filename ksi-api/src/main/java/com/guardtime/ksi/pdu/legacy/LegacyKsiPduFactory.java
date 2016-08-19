package com.guardtime.ksi.pdu.legacy;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.ExtensionRequest;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.PduMessageHeader;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;

import java.util.Date;

/**
 * Legacy implementation of {@link PduFactory}.
 */
public class LegacyKsiPduFactory implements PduFactory {

    public AggregationRequest createAggregationRequest(KSIRequestContext context, DataHash imprint, Long level) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(imprint, "DataHash");
        PduMessageHeader header = new PduMessageHeader(context.getLoginId(), context.getInstanceId(), context.getMessageId());
        LegacyAggregationRequestPayload request = new LegacyAggregationRequestPayload(imprint, context.getRequestId(), level);
        return new LegacyAggregationRequest(header, request, context);
    }

    public AggregationResponse readAggregationResponse(KSIRequestContext context, TLVElement input) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(input, "Input TLV");
        return new LegacyAggregationResponse(input, context).getResponsePayload();
    }

    public ExtensionRequest createExtensionRequest(KSIRequestContext context, Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(aggregationTime, "AggregationTime");
        PduMessageHeader header = new PduMessageHeader(context.getLoginId(), context.getInstanceId(), context.getMessageId());
        LegacyExtensionRequestPayload extensionRequest = new LegacyExtensionRequestPayload(aggregationTime, publicationTime, context.getRequestId());
        return new LegacyExtensionRequest(header, extensionRequest, context.getLoginKey());
    }

    public ExtensionResponse readExtensionResponse(KSIRequestContext context, TLVElement input) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(input, "Input TLV");
        return new LegacyExtensionResponse(input, context).getResponsePayload();
    }

}
