package com.guardtime.ksi.pdu.v1;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.ExtensionRequest;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.pdu.PduMessageHeader;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.GlobalTlvTypes;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.util.Util;

import java.util.Date;

/**
 * Legacy implementation of {@link PduFactory}.
 */
public class PduV1Factory implements PduFactory {

    public AggregationRequest createAggregationRequest(KSIRequestContext context, DataHash imprint, Long level) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(imprint, "DataHash");
        PduMessageHeader header = new PduMessageHeader(context.getLoginId(), context.getInstanceId(), context.getMessageId());
        AggregationRequestPayloadV1 request = new AggregationRequestPayloadV1(imprint, context.getRequestId(), level);
        return new AggregationRequestV1(header, request, context);
    }

    public AggregationResponse readAggregationResponse(KSIRequestContext context, TLVElement input) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(input, "Input TLV");
        if (input.getType() == GlobalTlvTypes.ELEMENT_TYPE_AGGREGATION_RESPONSE_PDU_V2) {
            throw new KSIProtocolException("Received PDU v2 response to PDU v1 request. Configure the SDK to use PDU v2 format for the given Aggregator");
        }
        return new AggregationResponseV1(input, context).getResponsePayload();
    }

    public ExtensionRequest createExtensionRequest(KSIRequestContext context, Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(aggregationTime, "AggregationTime");
        PduMessageHeader header = new PduMessageHeader(context.getLoginId(), context.getInstanceId(), context.getMessageId());
        ExtensionRequestPayloadV1 extensionRequest = new ExtensionRequestPayloadV1(aggregationTime, publicationTime, context.getRequestId());
        return new ExtensionRequestV1(header, extensionRequest, context.getLoginKey());
    }

    public ExtensionResponse readExtensionResponse(KSIRequestContext context, TLVElement input) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(input, "Input TLV");
        if (input.getType() == GlobalTlvTypes.ELEMENT_TYPE_EXTENSION_RESPONSE_PDU_V2) {
            throw new KSIProtocolException("Received PDU v2 response to PDU v1 request. Configure the SDK to use PDU v2 format for the given Extender");
        }
        return new ExtensionResponseV1(input, context).getResponsePayload();
    }

}
