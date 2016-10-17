package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.pdu.ExtensionRequest;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;

import java.util.List;

class ExtensionRequestPduV2 extends Pdu implements ExtensionRequest {

    public ExtensionRequestPduV2(List<? extends TLVStructure> payloads, HashAlgorithm macAlgorithm, KSIRequestContext context) throws KSIException {
        super(new PduHeader(context), payloads, macAlgorithm, context.getLoginKey());
    }

    @Override
    public int[] getSupportedPayloadTypes() {
        return new int[]{0x02, 0x03};
    }

    @Override
    public int getErrorPayloadType() {
        return 0x03;
    }

    @Override
    public int getElementType() {
        return 0x0320;
    }

    public byte[] toByteArray() {
        try {
            return getRootElement().getEncoded();
        } catch (TLVParserException e) {
            throw new IllegalArgumentException("Invalid aggregation request state");
        }
    }
}
