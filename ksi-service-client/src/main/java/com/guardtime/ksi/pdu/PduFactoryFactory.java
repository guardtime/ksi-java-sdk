package com.guardtime.ksi.pdu;

import com.guardtime.ksi.pdu.v1.PduV1Factory;
import com.guardtime.ksi.pdu.v2.PduV2Factory;

public final class PduFactoryFactory {
    public static PduFactory createPduFactory(PduVersion pduVersion) {
        switch (pduVersion) {
            case V1:
                return new PduV1Factory();
            case V2:
                return new PduV2Factory();
            default:
                throw new IllegalArgumentException("Invalid PDU version. Allowed values are V1 and V2");
        }
    }
}
