package com.guardtime.ksi.pdu.tlv;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.tlv.TLVElement;

class AggregationResponsePdu extends Pdu {

    public AggregationResponsePdu(TLVElement rootElement, KSIRequestContext context) throws KSIException {
        super(rootElement, context.getLoginKey());
    }

    @Override
    public int[] getSupportedPayloadTypes() {
        return new int[]{0x0202, 0x0203};
    }

    @Override
    public int getErrorPayloadType() {
        return 0x0203;
    }

    @Override
    public int getElementType() {
        return 0x02FF;
    }

}
