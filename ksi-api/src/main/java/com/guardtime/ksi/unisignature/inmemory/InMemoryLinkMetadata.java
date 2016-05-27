package com.guardtime.ksi.unisignature.inmemory;

import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.tlv.TLVParserException;
import com.guardtime.ksi.tlv.TLVStructure;
import com.guardtime.ksi.util.Util;

import java.util.Arrays;
import java.util.List;

public class InMemoryLinkMetadata extends TLVStructure implements com.guardtime.ksi.unisignature.LinkMetadata {

    public static final int ELEMENT_TYPE_METADATA = 0x04;

    public static final int ELEMENT_TYPE_CLIENT_ID = 0x01;
    public static final int ELEMENT_TYPE_MACHINE_ID = 0x02;
    public static final int ELEMENT_TYPE_SEQUENCE_NUMBER = 0x03;
    public static final int ELEMENT_TYPE_REQUEST_TIME = 0x04;
    public static final int ELEMENT_TYPE_PADDING = 0x1E;

    private String clientId;
    private String machineId;
    private Long sequenceNumber;
    private Long requestTime;

    public InMemoryLinkMetadata(String clientId) throws KSIException {
        this(clientId, null, null, null);
    }

    public InMemoryLinkMetadata(com.guardtime.ksi.unisignature.LinkMetadata metadata) throws KSIException {
        this(metadata.getClientId(), metadata.getMachineId(), metadata.getSequenceNumber(), metadata.getRequestTime());
    }

    public InMemoryLinkMetadata(String clientId, String machineId, Long sequenceNumber, Long requestTime) throws KSIException {
        Util.notNull(clientId, "Client Identifier");
        this.clientId = clientId;
        this.machineId = machineId;
        this.sequenceNumber = sequenceNumber;
        this.requestTime = requestTime;
        this.rootElement = new TLVElement(false, false, getElementType());
        addMetadataChildElements();
    }

    public InMemoryLinkMetadata(TLVElement tlvElement) throws KSIException {
        super(tlvElement);
        List<TLVElement> children = tlvElement.getChildElements();
        for (TLVElement child : children) {
            switch (child.getType()) {
                case ELEMENT_TYPE_CLIENT_ID:
                    clientId = readOnce(child).getDecodedString();
                    continue;
                case ELEMENT_TYPE_MACHINE_ID:
                    machineId = readOnce(child).getDecodedString();
                    continue;
                case ELEMENT_TYPE_SEQUENCE_NUMBER:
                    sequenceNumber = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_REQUEST_TIME:
                    requestTime = readOnce(child).getDecodedLong();
                    continue;
                case ELEMENT_TYPE_PADDING:
                    continue;
                default:
                    verifyCriticalFlag(child);
            }
        }
        if (clientId == null) {
            throw new InvalidAggregationHashChainException("AggregationChainLink metadata does not contain clientId element");
        }

    }

    public String getClientId() {
        return clientId;
    }

    public String getMachineId() {
        return machineId;
    }

    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    public Long getRequestTime() {
        return requestTime;
    }

    @Override
    public int getElementType() {
        return ELEMENT_TYPE_METADATA;
    }

    private void addMetadataChildElements() throws TLVParserException {
        this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_CLIENT_ID, clientId));
        if (machineId != null) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_MACHINE_ID, machineId));
        }
        if (sequenceNumber != null) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_SEQUENCE_NUMBER, sequenceNumber));
        }
        if (requestTime != null) {
            this.rootElement.addChildElement(TLVElement.create(ELEMENT_TYPE_REQUEST_TIME, requestTime));
        }
        this.rootElement.addFirstChildElement(createPaddingTlvElement());
    }

    private TLVElement createPaddingTlvElement() throws TLVParserException {
        TLVElement element = new TLVElement(true, true, ELEMENT_TYPE_PADDING);
        int padding = 1;
        if(this.rootElement.getContentLength() % 2 == 0) {
            padding = 2;
        }
        byte[] bytes = new byte[padding];
        Arrays.fill(bytes, (byte) 0x01);
        element.setContent(bytes);
        return element;
    }
}
