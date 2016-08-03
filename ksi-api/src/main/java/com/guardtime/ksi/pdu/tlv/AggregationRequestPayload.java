package com.guardtime.ksi.pdu.tlv;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;

class AggregationRequestPayload extends TLVStructure{

    public static final int ELEMENT_TYPE = 0x0201;

    private static final int ELEMENT_TYPE_REQUEST_ID = 0x01;
    private static final int ELEMENT_TYPE_REQUEST_HASH = 0x02;
    private static final int ELEMENT_TYPE_LEVEL = 0x03;

    private long level = 0L;
    private Long requestId;
    private DataHash requestHash;

    public AggregationRequestPayload(DataHash dataHash, Long requestId, long level) throws KSIException {
        this.requestId = requestId;
        this.level = level;
        this.requestHash = dataHash;
        this.rootElement = new TLVElement(false, false, ELEMENT_TYPE);

        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_REQUEST_ID, requestId));
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_REQUEST_HASH, dataHash));
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_LEVEL, level));
    }

    public long getLevel() {
        return level;
    }

    public Long getRequestId() {
        return requestId;
    }

    public DataHash getRequestHash() {
        return requestHash;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

    @Override
    public String toString() {
        return "AggregationRequestPayload{" +
                "level=" + level +
                ", requestId=" + requestId +
                ", requestHash=" + requestHash +
                '}';
    }

}
