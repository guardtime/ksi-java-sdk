package com.guardtime.ksi.pdu.v2;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.pdu.KSIRequestContext;
import com.guardtime.ksi.service.KSIProtocolException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.unisignature.AggregationAuthenticationRecord;
import com.guardtime.ksi.unisignature.AggregationHashChain;
import com.guardtime.ksi.unisignature.CalendarAuthenticationRecord;
import com.guardtime.ksi.unisignature.CalendarHashChain;

import java.util.List;

class AggregationResponsePayloadV2 extends TLVStructure implements AggregationResponse {

    static final int ELEMENT_TYPE = 0x02;

    private static final int ELEMENT_TYPE_REQUEST_ID = 0x01;
    private static final int ELEMENT_TYPE_ERROR = 0x04;
    private static final int ELEMENT_TYPE_ERROR_MESSAGE = 0x05;

    private Long requestId;
    private Long error;
    private String errorMessage;

    public AggregationResponsePayloadV2(TLVElement element, KSIRequestContext context) throws KSIException {
        super(element);
        List<TLVElement> children = element.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_REQUEST_ID:
                    this.requestId = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_ERROR:
                    this.error = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_ERROR_MESSAGE:
                    this.errorMessage = readOnce(child).getDecodedString();
                    continue;
                case AggregationHashChain.ELEMENT_TYPE:
                case AggregationAuthenticationRecord.ELEMENT_TYPE:
                case CalendarHashChain.ELEMENT_TYPE:
                case CalendarAuthenticationRecord.ELEMENT_TYPE:
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (error != 0) {
            throw new KSIProtocolException("Invalid aggregation response. Error code: 0x" + Long.toHexString(error) + ", message: '"+errorMessage+"'");
        }
        if (requestId == null) {
            throw new KSIProtocolException("Invalid KSI response. Aggregation response payload does not contain request id.");
        }
        if (!requestId.equals(context.getRequestId())) {
            throw new KSIProtocolException("Aggregation response request ID do not match. Sent '" + context.getRequestId() + "'" + " received '" + requestId + "'");
        }
    }

    /**
     * @return error number
     */
    public Long getStatus() {
        return error;
    }

    /**
     * returns an error message
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Returns the request identifier
     */
    public final Long getRequestId() {
        return requestId;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE;
    }

    public TLVElement getPayload() {
        return this.getRootElement();
    }
}
