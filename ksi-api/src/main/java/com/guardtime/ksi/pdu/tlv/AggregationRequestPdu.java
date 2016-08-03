package com.guardtime.ksi.pdu.tlv;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.List;

class AggregationRequestPdu extends Pdu implements AggregationRequest {

    private final KSIRequestContext context;

    public AggregationRequestPdu(List<? extends TLVStructure> payloads, HashAlgorithm macAlgorithm, KSIRequestContext context) throws KSIException {
        super(new PduHeader(context), payloads, macAlgorithm, context.getLoginKey());
        this.context = context;
    }

    //TODO element types
    @Override
    public int[] getSupportedPayloadTypes() {
        return new int[] {AggregationRequestPayload.ELEMENT_TYPE};
    }

    @Override
    public int getErrorPayloadType() {
        return 0x0203;
    }

    //TODO move to constant
    @Override
    public int getElementType() {
        return PDU_TYPE_AGGREGATION;
    }

    public byte[] toByteArray() {
        try {
            return getRootElement().getEncoded();
        } catch (TLVParserException e) {
            throw new IllegalArgumentException("Invalid aggregation request state");
        }
    }

    public KSIRequestContext getRequestContext() {
        return context;
    }

}
