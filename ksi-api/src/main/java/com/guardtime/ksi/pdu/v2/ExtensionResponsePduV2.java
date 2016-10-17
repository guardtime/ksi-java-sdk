package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.tlv.TLVElement;

class ExtensionResponsePduV2 extends PduV2 {

    public ExtensionResponsePduV2(TLVElement rootElement, KSIRequestContext context) throws KSIException {
        super(rootElement, context.getLoginKey());
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
        return 0x0321;
    }

}
