package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.AggregationRequest;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.List;

class AggregationRequestPduV2 extends PduV2 implements AggregationRequest {

    private static final int PDU_TYPE_AGGREGATION_REQUEST = 0x0220;

    private final KSIRequestContext context;

    public AggregationRequestPduV2(List<? extends TLVStructure> payloads, HashAlgorithm macAlgorithm, KSIRequestContext context) throws KSIException {
        super(new PduV2Header(context), payloads, macAlgorithm, context.getLoginKey());
        this.context = context;
    }

    @Override
    public int[] getSupportedPayloadTypes() {
        return new int[] {AggregationRequestPayloadV2.ELEMENT_TYPE};
    }

    @Override
    public int getErrorPayloadType() {
        return 0x0203;
    }

    @Override
    public int getElementType() {
        return PDU_TYPE_AGGREGATION_REQUEST;
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
