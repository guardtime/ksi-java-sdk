package com.guardtime.ksi.pdu.tlv;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.tlv.TLVElement;

class ExtensionResponsePdu extends Pdu {

    public ExtensionResponsePdu(TLVElement rootElement, KSIRequestContext context) throws KSIException {
        super(rootElement, context.getLoginKey());
    }

    @Override
    public int[] getSupportedPayloadTypes() {
        return new int[]{0x0302, 0x0303};
    }

    @Override
    public int getErrorPayloadType() {
        return 0x0303;
    }

    @Override
    public int getElementType() {
        return 0x03FF;
    }

}
