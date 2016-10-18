package com.guardtime.ksi.tlv;

public final class GlobalTlvTypes {

    private GlobalTlvTypes(){
    }

    // signature tlv types
    public static final int ELEMENT_TYPE_SIGNATURE = 0x0800;
    public static final int ELEMENT_TYPE_AGGREGATION_HASH_CHAIN = 0x0801;
    public static final int ELEMENT_TYPE_CALENDAR_HASH_CHAIN = 0x0802;
    public static final int ELEMENT_TYPE_SIGNATURE_PUBLICATION_RECORD = 0x0803;
    public static final int ELEMENT_TYPE_AGGREGATION_AUTHENTICATION_RECORD = 0x0804;
    public static final int ELEMENT_TYPE_CALENDAR_AUTHENTICATION_RECORD = 0x0805;
    public static final int ELEMENT_TYPE_RFC_3161_RECORD = 0x0806;

    // PDU types
    public static final int ELEMENT_TYPE_AGGREGATION_PDU_V1 = 0x0200;
    public static final int ELEMENT_TYPE_EXTENSION_PDU_V1 = 0x0300;
    public static final int ELEMENT_TYPE_AGGREGATION_REQUEST_PDU_V2 = 0x0220;
    public static final int ELEMENT_TYPE_AGGREGATION_RESPONSE_PDU_V2 = 0x0221;
    public static final int ELEMENT_TYPE_EXTENSION_REQUEST_PDU_V2 = 0x0320;
    public static final int ELEMENT_TYPE_EXTENSION_RESPONSE_PDU_V2 = 0x0321;

}
