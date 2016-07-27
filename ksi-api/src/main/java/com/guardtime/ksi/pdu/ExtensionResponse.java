package com.guardtime.ksi.pdu;

import com.guardtime.ksi.tlv.TLVElement;

public interface ExtensionResponse {

    TLVElement getPayload();

}
