package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.pdu.PduMessageHeader;
import com.guardtime.ksi.tlv.TLVElement;

class PduHeader extends PduMessageHeader {

    public static final int ELEMENT_TYPE = 0x01;

    public PduHeader(KSIRequestContext context) throws KSIException {
        super(context.getLoginId(), context.getInstanceId(), context.getMessageId());
    }

    public PduHeader(TLVElement rootElement) throws KSIException {
        super(rootElement);
    }

}
