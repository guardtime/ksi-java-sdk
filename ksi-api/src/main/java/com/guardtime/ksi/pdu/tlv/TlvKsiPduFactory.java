package com.guardtime.ksi.pdu.tlv;

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

public class TlvKsiPduFactory implements PduFactory {

    public AggregationRequest createAggregationRequest(KSIRequestContext context, DataHash imprint, Long level) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(context, "DataHash");
        AggregationRequestPayload payload = new AggregationRequestPayload(imprint, context.getRequestId(), level);
        List<? extends TLVStructure> payloads = Arrays.asList(payload);
        return new AggregationRequestPdu(payloads, HashAlgorithm.SHA2_256, context);
    }

    public AggregationResponse readAggregationResponse(KSIRequestContext context, TLVElement input) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(context, "Input TLV");
        AggregationResponsePdu aggregationResponsePdu = new AggregationResponsePdu(input, context);

        return new AggregationResponsePayload(aggregationResponsePdu.getPayload(AggregationResponsePayload.ELEMENT_TYPE, context.getRequestId()));
    }

    public ExtensionRequest createExtensionRequest(KSIRequestContext context, Date aggregationTime, Date publicationTime) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(context, "Aggregation time");
        if (publicationTime != null && aggregationTime.after(publicationTime)) {
            throw new KSIProtocolException("There is no suitable publication yet");
        }
        ExtensionRequestPayload payload = new ExtensionRequestPayload(aggregationTime, publicationTime, context.getRequestId());
        return new ExtensionRequestPdu(Arrays.asList(payload), HashAlgorithm.SHA2_256, context);
    }

    public ExtensionResponse readExtensionResponse(KSIRequestContext context, TLVElement input) throws KSIException {
        Util.notNull(context, "KsiRequestContext");
        Util.notNull(context, "Input TLV");
        ExtensionResponsePdu responsePdu = new ExtensionResponsePdu(input, context);
        return new ExtensionResponsePayload(responsePdu.getPayload(ExtensionResponsePayload.ELEMENT_TYPE, context.getRequestId()));
    }

}
