package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.ExtensionRequest;
import com.guardtime.ksi.pdu.ExtensionResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduFactory;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.util.Util;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class PduV2Factory implements PduFactory {

    public AggregationRequest createAggregationRequest(KSIRequestContext context, DataHash imprint, Long level) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(context, "DataHash");
        AggregationRequestPayloadV2 payload = new AggregationRequestPayloadV2(imprint, context.getRequestId(), level);
        List<? extends TLVStructure> payloads = Arrays.asList(payload);
        return new AggregationRequestPduV2(payloads, HashAlgorithm.SHA2_256, context);
    }

    public AggregationResponse readAggregationResponse(KSIRequestContext context, TLVElement input) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(context, "Input TLV");
        AggregationResponsePduV2 aggregationResponsePdu = new AggregationResponsePduV2(input, context);

        return new AggregationResponsePayloadV2(aggregationResponsePdu.getPayload(AggregationResponsePayloadV2.ELEMENT_TYPE, context.getRequestId()));
    }

    public ExtensionRequest createExtensionRequest(KSIRequestContext context, Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(context, "Aggregation time");
        if (publicationTime != null && aggregationTime.after(publicationTime)) {
            throw new KSIProtocolException("There is no suitable publication yet");
        }
        ExtensionRequestPayloadV2 payload = new ExtensionRequestPayloadV2(aggregationTime, publicationTime, context.getRequestId());
        return new ExtensionRequestPduV2(Arrays.asList(payload), HashAlgorithm.SHA2_256, context);
    }

    public ExtensionResponse readExtensionResponse(KSIRequestContext context, TLVElement input) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(context, "Input TLV");
        ExtensionResponsePduV2 responsePdu = new ExtensionResponsePduV2(input, context);
        return new ExtensionResponsePayloadV2(responsePdu.getPayload(ExtensionResponsePayloadV2.ELEMENT_TYPE, context.getRequestId()));
    }

}
